"""
Mock GitHub API for offline testing and for generating a fully-populated sample
run without network access.

Design choice: the mock emulates GitHub's *raw REST response shapes* and is
driven by a compact, human-readable org spec (ORG_FIXTURE). Because it speaks
the same endpoint/JSON contract as the real API, the identical scanner code path
runs against both -- there is no "if mock" branching inside the engine. Every
value here is synthetic; the dashboard labels it as such.

The fixture is intentionally built to exercise the edge cases the brief calls
out: archived / forked / empty / brand-new / single-contributor repos, bots,
outside collaborators, an admin/reviewer with low commit volume (must NOT be
flagged), and stale high-privilege access (must be flagged).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .client import NotAuthorized

REFERENCE_NOW = "2025-08-20T12:00:00Z"


# --------------------------------------------------------------------------- #
# The synthetic org
# --------------------------------------------------------------------------- #
ORG_FIXTURE: Dict[str, Any] = {
    "org": "acme-sandbox",
    "now": REFERENCE_NOW,
    "owners": ["renuka-owner", "sam-founder"],
    "bots": ["ci-bot", "dependabot[bot]"],
    "repos": [
        {
            "name": "payments-api",
            "archived": False, "fork": False, "size_kb": 8200,
            "created_days_ago": 1100, "pushed_days_ago": 2, "default_branch": "main",
            "collaborators": {
                "renuka-owner": "admin", "sam-founder": "admin",
                "aisha-dev": "write", "diego-dev": "write", "lena-sec": "maintain",
                "old-contractor": "write", "ci-bot": "write", "vendor-x": "write",
            },
            "outside": ["vendor-x"],
            "activity": {
                # active core devs
                "aisha-dev":     {"commits": 120, "prs": 30, "merged": 28, "reviews": 12, "last": 2},
                "diego-dev":     {"commits": 78,  "prs": 20, "merged": 18, "reviews": 44, "last": 4},
                # reviewer + maintainer, deliberately LOW commits, high reviews, recent
                "lena-sec":      {"commits": 4,   "prs": 2,  "merged": 2,  "reviews": 51, "last": 6},
                # owner with low activity -> must stay (protected)
                "renuka-owner":  {"commits": 3,   "prs": 1,  "merged": 1,  "reviews": 5,  "last": 35},
                # stale high-privilege access -> should be flagged (high priority)
                "old-contractor":{"commits": 0,   "prs": 0,  "merged": 0,  "reviews": 0,  "last": 420},
                # bot with lots of commits -> excluded from suggestions
                "ci-bot":        {"commits": 300, "prs": 0,  "merged": 0,  "reviews": 0,  "last": 1},
                # outside collaborator, stale -> flagged, extra scrutiny
                "vendor-x":      {"commits": 2,   "prs": 1,  "merged": 0,  "reviews": 0,  "last": 260},
            },
            "advisories": [
                {"severity": "critical", "package": "pip:django", "state": "open", "age_days": 240,
                 "summary": "SQL injection via crafted query in Django ORM"},
                {"severity": "high", "package": "npm:lodash", "state": "open", "age_days": 130,
                 "summary": "Prototype pollution in lodash merge"},
                {"severity": "high", "package": "pip:cryptography", "state": "open", "age_days": 40,
                 "summary": "NULL pointer deref in OpenSSL-backed cipher"},
                {"severity": "medium", "package": "pip:requests", "state": "fixed", "age_days": 18,
                 "summary": "Leak of Proxy-Authorization header on redirect"},
                {"severity": "low", "package": "npm:tmp", "state": "dismissed", "age_days": 300,
                 "summary": "Arbitrary temp file write (dev-only dependency)"},
            ],
        },
        {
            "name": "web-dashboard",
            "archived": False, "fork": False, "size_kb": 15300,
            "created_days_ago": 800, "pushed_days_ago": 9, "default_branch": "main",
            "collaborators": {
                "renuka-owner": "admin", "aisha-dev": "write",
                "diego-dev": "maintain", "marco-fe": "write", "priya-pm": "read",
                "ex-intern": "write",
            },
            "outside": [],
            "activity": {
                "marco-fe":     {"commits": 95, "prs": 24, "merged": 22, "reviews": 18, "last": 3},
                "diego-dev":    {"commits": 30, "prs": 8,  "merged": 7,  "reviews": 20, "last": 9},
                "aisha-dev":    {"commits": 12, "prs": 4,  "merged": 3,  "reviews": 9,  "last": 22},
                # read-only PM, low activity but only read access -> low priority even if flagged
                "priya-pm":     {"commits": 0,  "prs": 0,  "merged": 0,  "reviews": 2,  "last": 60},
                # ex-intern, write access, gone -> flagged
                "ex-intern":    {"commits": 40, "prs": 10, "merged": 8,  "reviews": 1,  "last": 300},
                "renuka-owner": {"commits": 0,  "prs": 0,  "merged": 0,  "reviews": 0,  "last": 200},
            },
            "advisories": [
                {"severity": "high", "package": "npm:next", "state": "open", "age_days": 75,
                 "summary": "SSRF in image optimisation endpoint"},
                {"severity": "medium", "package": "npm:postcss", "state": "open", "age_days": 22,
                 "summary": "ReDoS in PostCSS parser"},
            ],
        },
        {
            "name": "data-pipeline",
            "archived": False, "fork": False, "size_kb": 5400,
            "created_days_ago": 500, "pushed_days_ago": 20, "default_branch": "main",
            # single active human contributor -> bus-factor flag, no removal suggestion
            "collaborators": {
                "renuka-owner": "admin", "hikaru-data": "maintain", "ci-bot": "write",
                "old-analyst": "read",
            },
            "outside": [],
            "activity": {
                "hikaru-data":  {"commits": 210, "prs": 40, "merged": 39, "reviews": 4, "last": 20},
                "ci-bot":       {"commits": 60,  "prs": 0,  "merged": 0,  "reviews": 0, "last": 3},
                "renuka-owner": {"commits": 0,   "prs": 0,  "merged": 0,  "reviews": 0, "last": 480},
                # read-only account, dormant -> flagged but LOW priority (limited blast radius)
                "old-analyst":  {"commits": 0,   "prs": 0,  "merged": 0,  "reviews": 0, "last": 500},
            },
            "advisories": [
                {"severity": "critical", "package": "pip:numpy", "state": "open", "age_days": 190,
                 "summary": "Buffer overflow in array-from-buffer path"},
            ],
        },
        {
            "name": "legacy-billing",
            "archived": True, "fork": False, "size_kb": 3100,
            "created_days_ago": 1600, "pushed_days_ago": 500, "default_branch": "master",
            "collaborators": {
                "renuka-owner": "admin", "old-contractor": "admin", "aisha-dev": "write",
            },
            "outside": [],
            "activity": {
                "old-contractor":{"commits": 0, "prs": 0, "merged": 0, "reviews": 0, "last": 520},
                "aisha-dev":     {"commits": 0, "prs": 0, "merged": 0, "reviews": 0, "last": 510},
                "renuka-owner":  {"commits": 0, "prs": 0, "merged": 0, "reviews": 0, "last": 500},
            },
            "advisories": [
                {"severity": "high", "package": "pip:flask", "state": "open", "age_days": 460,
                 "summary": "Open redirect in error handler"},
            ],
        },
        {
            "name": "infra-scripts-fork",
            "archived": False, "fork": True, "size_kb": 900,
            "created_days_ago": 120, "pushed_days_ago": 60, "default_branch": "main",
            "collaborators": {
                "renuka-owner": "admin", "diego-dev": "write", "vendor-x": "write",
            },
            "outside": ["vendor-x"],
            "activity": {
                "diego-dev": {"commits": 8, "prs": 2, "merged": 1, "reviews": 0, "last": 60},
                "vendor-x":  {"commits": 3, "prs": 1, "merged": 0, "reviews": 0, "last": 70},
                "renuka-owner": {"commits": 0, "prs": 0, "merged": 0, "reviews": 0, "last": 110},
            },
            "advisories": [],
        },
        {
            "name": "new-mobile-app",
            "archived": False, "fork": False, "size_kb": 400,
            "created_days_ago": 12, "pushed_days_ago": 1, "default_branch": "main",
            # brand-new repo -> recommendations suppressed
            "collaborators": {
                "renuka-owner": "admin", "marco-fe": "write", "aisha-dev": "write",
            },
            "outside": [],
            "activity": {
                "marco-fe":  {"commits": 20, "prs": 5, "merged": 3, "reviews": 1, "last": 1},
                "aisha-dev": {"commits": 2,  "prs": 1, "merged": 0, "reviews": 0, "last": 5},
                "renuka-owner": {"commits": 1, "prs": 0, "merged": 0, "reviews": 0, "last": 8},
            },
            "advisories": [],
        },
        {
            "name": "archived-empty-repo",
            "archived": False, "fork": False, "size_kb": 0,
            "created_days_ago": 40, "pushed_days_ago": None, "default_branch": "main",
            # empty repo -> skipped for analysis
            "collaborators": {"renuka-owner": "admin"},
            "outside": [],
            "activity": {},
            "advisories": [],
        },
    ],
}


def _iso(now: datetime, days_ago: Optional[int]) -> Optional[str]:
    if days_ago is None:
        return None
    return (now - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


class MockGitHubClient:
    """Drop-in stand-in for GitHubClient that serves ORG_FIXTURE-shaped data.

    `authorized=True` simulates scanning an org where you have admin/security
    access (real collaborators + Dependabot alerts are returned).
    `authorized=False` simulates a public org: collaborators and Dependabot
    endpoints raise NotAuthorized, forcing the scanner's public-limited fallback.
    """

    def __init__(self, fixture: Dict[str, Any] = ORG_FIXTURE, authorized: bool = True):
        self.fx = fixture
        self.authorized = authorized
        self.now = datetime.fromisoformat(fixture["now"].replace("Z", "+00:00"))
        self.api_calls = 0
        self.conditional_hits = 0
        self._built: Dict[str, Any] = {}
        self._build()

    # ---- build raw commit/PR/review objects from the compact activity spec --
    def _build(self) -> None:
        for repo in self.fx["repos"]:
            commits: List[dict] = []
            pulls: List[dict] = []
            reviews_by_pr: Dict[int, List[dict]] = {}
            pr_no = 0
            for login, act in repo.get("activity", {}).items():
                date = _iso(self.now, act["last"])
                for _ in range(act.get("commits", 0)):
                    commits.append({
                        "sha": f"{login}-{len(commits)}",
                        "author": {"login": login, "type": self._acct_type(login)},
                        "commit": {"author": {"date": date}},
                    })
                for i in range(act.get("prs", 0)):
                    pr_no += 1
                    merged = i < act.get("merged", 0)
                    pulls.append({
                        "number": pr_no,
                        "user": {"login": login, "type": self._acct_type(login)},
                        "created_at": date,
                        "merged_at": date if merged else None,
                        "state": "closed" if merged else "open",
                    })
            # attach reviews across existing PRs (round-robin)
            pr_numbers = [p["number"] for p in pulls] or [None]
            ri = 0
            for login, act in repo.get("activity", {}).items():
                date = _iso(self.now, act["last"])
                for _ in range(act.get("reviews", 0)):
                    target = pr_numbers[ri % len(pr_numbers)]
                    ri += 1
                    if target is None:
                        continue
                    reviews_by_pr.setdefault(target, []).append(
                        {"user": {"login": login, "type": self._acct_type(login)},
                         "submitted_at": date, "state": "APPROVED"})
            self._built[repo["name"]] = {
                "commits": commits, "pulls": pulls, "reviews_by_pr": reviews_by_pr,
            }

    def _acct_type(self, login: str) -> str:
        return "Bot" if (login in self.fx.get("bots", []) or login.endswith("[bot]")) else "User"

    def _repo(self, name: str) -> Optional[dict]:
        for r in self.fx["repos"]:
            if r["name"] == name:
                return r
        return None

    def _repo_json(self, r: dict) -> dict:
        return {
            "name": r["name"],
            "full_name": f'{self.fx["org"]}/{r["name"]}',
            "private": False,
            "archived": r["archived"],
            "fork": r["fork"],
            "disabled": False,
            "default_branch": r["default_branch"],
            "size": r["size_kb"],
            "pushed_at": _iso(self.now, r["pushed_days_ago"]),
            "created_at": _iso(self.now, r["created_days_ago"]),
        }

    # ------------------------------------------------------------------ #
    # routing
    # ------------------------------------------------------------------ #
    def _route(self, path: str, params: Optional[Dict[str, Any]]) -> Any:
        self.api_calls += 1
        p = path.strip("/")
        parts = p.split("/")
        org = self.fx["org"]

        if parts == ["orgs", org]:
            return {"login": org, "type": "Organization"}

        if parts == ["orgs", org, "members"]:
            # Listing owners requires org membership. Scanning a PUBLIC org you
            # do not belong to -> this is gated, so the scanner cannot confirm
            # the owner set and must warn (owner-exclusion not guaranteed).
            if not self.authorized:
                raise NotAuthorized(403, "must be an org member to list members", path)
            if params and params.get("role") == "admin":
                return [{"login": o, "type": "User"} for o in self.fx["owners"]]
            members = set(self.fx["owners"])
            for r in self.fx["repos"]:
                members.update(r.get("collaborators", {}).keys())
            return [{"login": m, "type": self._acct_type(m)} for m in sorted(members)]

        if parts == ["orgs", org, "repos"]:
            return [self._repo_json(r) for r in self.fx["repos"]]

        if len(parts) >= 4 and parts[0] == "repos":
            repo_name = parts[2]
            tail = parts[3:]
            r = self._repo(repo_name)
            if r is None:
                raise NotAuthorized(404, "no such repo", path)
            built = self._built[repo_name]

            if tail == ["collaborators"]:
                if not self.authorized:
                    raise NotAuthorized(403, "collaborators need push access", path)
                affiliation = (params or {}).get("affiliation", "all")
                outside = set(r.get("outside", []))
                out = []
                for login, perm in r.get("collaborators", {}).items():
                    if affiliation == "outside" and login not in outside:
                        continue
                    if affiliation == "direct" and login in outside:
                        # mock models no teams, so "direct" = everyone who is
                        # not an outside collaborator.
                        continue
                    out.append({
                        "login": login,
                        "type": self._acct_type(login),
                        "role_name": perm,
                        "permissions": self._perm_bools(perm),
                    })
                return out

            if tail == ["contributors"]:
                # public fallback population = anyone with commits
                seen = {}
                for c in built["commits"]:
                    lg = c["author"]["login"]
                    seen[lg] = seen.get(lg, 0) + 1
                return [{"login": lg, "type": self._acct_type(lg), "contributions": n}
                        for lg, n in sorted(seen.items(), key=lambda kv: -kv[1])]

            if tail == ["commits"]:
                return self._filter_since(built["commits"], params, "commit_date")

            if tail == ["pulls"]:
                return list(built["pulls"])

            if len(tail) == 3 and tail[0] == "pulls" and tail[2] == "reviews":
                return built["reviews_by_pr"].get(int(tail[1]), [])

            if tail == ["dependabot", "alerts"]:
                if not self.authorized:
                    raise NotAuthorized(403, "dependabot alerts need security access", path)
                return self._advisory_json(r)

        raise NotAuthorized(404, f"unrouted mock path: {path}", path)

    def _perm_bools(self, role: str) -> dict:
        order = {"read": 0, "triage": 1, "write": 2, "maintain": 3, "admin": 4}
        lvl = order.get(role, 0)
        return {
            "pull": lvl >= 0, "triage": lvl >= 1, "push": lvl >= 2,
            "maintain": lvl >= 3, "admin": lvl >= 4,
        }

    def _filter_since(self, commits: List[dict], params, _kind: str) -> List[dict]:
        if not params or "since" not in params:
            return commits
        since = datetime.fromisoformat(params["since"].replace("Z", "+00:00"))
        out = []
        for c in commits:
            d = c["commit"]["author"]["date"]
            if d and datetime.fromisoformat(d.replace("Z", "+00:00")) >= since:
                out.append(c)
        return out

    def _advisory_json(self, r: dict) -> List[dict]:
        out = []
        for i, a in enumerate(r.get("advisories", [])):
            eco, _, name = a["package"].partition(":")
            out.append({
                "number": i + 1,
                "state": a["state"],
                "created_at": _iso(self.now, a["age_days"]),
                "security_advisory": {
                    "ghsa_id": f"GHSA-mock-{r['name']}-{i+1}",
                    "severity": a["severity"],
                    "summary": a["summary"],
                },
                "security_vulnerability": {
                    "severity": a["severity"],
                    "package": {"ecosystem": eco, "name": name},
                },
                "dependency": {"package": {"ecosystem": eco, "name": name}},
            })
        return out

    # ------------------------------------------------------------------ #
    # public interface (mirrors GitHubClient)
    # ------------------------------------------------------------------ #
    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return self._route(path, params)

    def get_optional(self, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        try:
            return self._route(path, params)
        except NotAuthorized:
            return None

    def paginate(self, path: str, params: Optional[Dict[str, Any]] = None,
                 max_pages: Optional[int] = None) -> Iterator[Any]:
        res = self._route(path, params)
        if isinstance(res, list):
            yield from res
        elif res is not None:
            yield res

    def paginate_optional(self, path: str, params: Optional[Dict[str, Any]] = None,
                          max_pages: Optional[int] = None) -> Tuple[List[Any], bool]:
        try:
            return list(self.paginate(path, params, max_pages)), True
        except NotAuthorized:
            return [], False
