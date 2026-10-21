"""
Zero-dependency GitHub REST client.

Uses only urllib from the standard library. Handles the things that actually
matter for scanning a whole org reliably and *idempotently*:

  * Bearer-token auth + versioned Accept header.
  * Link-header pagination (bounded by config page caps).
  * Primary rate-limit budgeting: pause until reset when the remaining budget
    drops below a floor (never longer than max_sleep_seconds).
  * Secondary/abuse rate-limit handling: honour Retry-After with bounded retries.
  * ETag conditional requests with an on-disk cache. Re-running the scan sends
    `If-None-Match`; unchanged resources return 304 (which does NOT consume the
    primary rate limit) and we reuse the cached body. This is what makes repeated
    runs cheap and their output stable -> idempotent.

Read-only by construction: the client only ever issues GET.
"""

from __future__ import annotations

import gzip
import hashlib
import http.client
import json
import os
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .config import ApiConfig


class GitHubError(Exception):
    def __init__(self, status: int, message: str, url: str):
        super().__init__(f"HTTP {status} for {url}: {message}")
        self.status = status
        self.url = url
        self.message = message


class NotAuthorized(GitHubError):
    """403/404 on a resource that needs elevated (admin/security) access.

    On a public org the scanner treats this as a signal to fall back to
    public-limited mode rather than crashing."""


class GitHubClient:
    def __init__(
        self,
        token: Optional[str] = None,
        cfg: Optional[ApiConfig] = None,
        cache_dir: Optional[str] = None,
        verbose: bool = False,
    ):
        self.cfg = cfg or ApiConfig()
        self.token = token
        self.cache_dir = cache_dir
        self.verbose = verbose
        self.api_calls = 0            # network round-trips actually made
        self.conditional_hits = 0     # 304s served from cache
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)

    # ------------------------------------------------------------------ #
    # low-level cache helpers
    # ------------------------------------------------------------------ #
    def _cache_path(self, url: str) -> Optional[str]:
        if not self.cache_dir:
            return None
        h = hashlib.sha256(url.encode()).hexdigest()[:20]
        return os.path.join(self.cache_dir, f"{h}.json")

    def _load_cache(self, url: str) -> Optional[dict]:
        path = self._cache_path(url)
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except (OSError, json.JSONDecodeError):
                return None
        return None

    def _store_cache(self, url: str, etag: Optional[str], body: Any) -> None:
        path = self._cache_path(url)
        if path and etag:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"url": url, "etag": etag, "body": body}, fh)
            os.replace(tmp, path)  # atomic -> safe if a run is interrupted

    # ------------------------------------------------------------------ #
    # request
    # ------------------------------------------------------------------ #
    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {
            "Accept": self.cfg.accept,
            "X-GitHub-Api-Version": self.cfg.api_version,
            "User-Agent": self.cfg.user_agent,
            "Accept-Encoding": "gzip",
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if extra:
            h.update(extra)
        return h

    def _respect_rate_limit(self, headers) -> None:
        remaining = headers.get("X-RateLimit-Remaining")
        reset = headers.get("X-RateLimit-Reset")
        if remaining is None or reset is None:
            return
        try:
            remaining_i = int(remaining)
            reset_i = int(reset)
        except ValueError:
            return
        if remaining_i <= self.cfg.rate_limit_floor:
            sleep_for = max(0, reset_i - int(time.time())) + 1
            sleep_for = min(sleep_for, self.cfg.max_sleep_seconds)
            if self.verbose:
                print(f"  [rate-limit] {remaining_i} left; sleeping {sleep_for}s until reset")
            time.sleep(sleep_for)

    def _read_body(self, resp) -> bytes:
        data = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip":
            data = gzip.decompress(data)
        return data

    def _request(self, url: str, _retries: int = 3) -> Tuple[int, Any, Dict[str, str]]:
        """GET a single URL. Returns (status, parsed_json_or_None, headers).

        Uses a cached ETag for a conditional request; on 304 returns the cached
        body with status 304."""
        cached = self._load_cache(url)
        extra = {"If-None-Match": cached["etag"]} if cached and cached.get("etag") else None
        req = urllib.request.Request(url, headers=self._headers(extra), method="GET")

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                self.api_calls += 1
                status = resp.getcode()
                hdrs = {k: v for k, v in resp.headers.items()}
                body = json.loads(self._read_body(resp).decode("utf-8"))
                etag = resp.headers.get("ETag")
                self._store_cache(url, etag, body)
                self._respect_rate_limit(resp.headers)
                return status, body, hdrs
        except urllib.error.HTTPError as e:
            hdrs = {k: v for k, v in (e.headers or {}).items()}
            self.api_calls += 1
            if e.code == 304 and cached is not None:
                self.conditional_hits += 1
                return 304, cached["body"], hdrs
            # secondary / abuse rate limit -> honour Retry-After and retry
            if e.code in (403, 429):
                retry_after = e.headers.get("Retry-After") if e.headers else None
                remaining = e.headers.get("X-RateLimit-Remaining") if e.headers else None
                if _retries > 0 and (retry_after or remaining == "0"):
                    wait = int(retry_after) if retry_after and retry_after.isdigit() else 60
                    wait = min(wait, self.cfg.max_sleep_seconds)
                    if self.verbose:
                        print(f"  [secondary-limit] waiting {wait}s then retrying")
                    time.sleep(wait)
                    return self._request(url, _retries - 1)
                raise NotAuthorized(e.code, "forbidden / rate-limited", url)
            # 5xx server errors -> bounded retry with exponential backoff
            if e.code in (500, 502, 503, 504):
                if _retries > 0:
                    wait = 3 * (4 - _retries)
                    if self.verbose:
                        print(f"  [server-error-{e.code}] {e.reason}; retrying in {wait}s...")
                    time.sleep(wait)
                    return self._request(url, _retries - 1)
            if e.code == 404:
                raise NotAuthorized(e.code, "not found or not authorised", url)
            raise GitHubError(e.code, e.reason or "http error", url)
        except (urllib.error.URLError, http.client.HTTPException, ConnectionResetError, TimeoutError, socket.error) as e:
            if _retries > 0:
                if self.verbose:
                    print(f"  [network-retry] {e}; retrying in 2s...")
                time.sleep(2)
                return self._request(url, _retries - 1)
            reason = getattr(e, "reason", str(e))
            raise GitHubError(0, f"network error: {reason}", url)

    # ------------------------------------------------------------------ #
    # public helpers
    # ------------------------------------------------------------------ #
    def get(self, path_or_url: str, params: Optional[Dict[str, Any]] = None) -> Any:
        url = self._abs(path_or_url, params)
        _, body, _ = self._request(url)
        return body

    def get_optional(self, path_or_url: str, params: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        """Like get(), but returns None on 403/404 instead of raising -- used
        for endpoints that may be gated (advisories, collaborators) on orgs we
        don't administer."""
        try:
            return self.get(path_or_url, params)
        except NotAuthorized:
            return None

    def paginate(self, path_or_url: str, params: Optional[Dict[str, Any]] = None,
                 max_pages: Optional[int] = None) -> Iterator[Any]:
        """Yield items across pages, following the Link rel=next header."""
        url = self._abs(path_or_url, params)
        pages = 0
        while url:
            status, body, hdrs = self._request(url)
            if isinstance(body, list):
                for item in body:
                    yield item
            elif body is not None:
                yield body
            pages += 1
            if max_pages and pages >= max_pages:
                break
            url = self._next_link(hdrs.get("Link"))

    def paginate_optional(self, path_or_url: str, params: Optional[Dict[str, Any]] = None,
                          max_pages: Optional[int] = None) -> Tuple[List[Any], bool]:
        """Paginate but tolerate a gated endpoint. Returns (items, authorized)."""
        try:
            return list(self.paginate(path_or_url, params, max_pages)), True
        except NotAuthorized:
            return [], False

    # ------------------------------------------------------------------ #
    # utils
    # ------------------------------------------------------------------ #
    def _abs(self, path_or_url: str, params: Optional[Dict[str, Any]]) -> str:
        if path_or_url.startswith("http"):
            base = path_or_url
        else:
            base = self.cfg.api_root + "/" + path_or_url.lstrip("/")
        if params:
            from urllib.parse import urlencode
            sep = "&" if "?" in base else "?"
            base = base + sep + urlencode(params)
        return base

    @staticmethod
    def _next_link(link_header: Optional[str]) -> Optional[str]:
        if not link_header:
            return None
        for part in link_header.split(","):
            segs = part.split(";")
            if len(segs) < 2:
                continue
            url = segs[0].strip().lstrip("<").rstrip(">")
            rel = segs[1].strip()
            if rel == 'rel="next"':
                return url
        return None
