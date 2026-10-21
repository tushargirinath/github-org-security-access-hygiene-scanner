"""
Command-line entrypoint:  python -m github_hygiene [options]

Runs one org scan and writes the full deliverable set to an output directory:
  * dashboard.html      -- the 2-minute security-lead view (self-contained)
  * report.json         -- complete machine-readable results
  * access_review.csv   -- one row per access-removal suggestion (+ evidence)
  * members.csv         -- every member/repo contribution row
  * advisories.csv      -- every advisory row
  * run_manifest.json   -- run metadata + content hashes (for idempotency checks)

Two ways to run:
  --mock            use the built-in synthetic org (no network, fully offline)
  --org NAME        scan a real org via the GitHub REST API (needs --token/env)

Design intent: the mock path lets anyone reproduce an identical sample run with
no credentials, while the real path is the one the security team points at their
own org. The same engine serves both.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

from .client import GitHubClient
from .config import ApiConfig, ScoringConfig
from .mock import MockGitHubClient
from .scanner import Scanner
from . import report as report_mod
from . import dashboard as dashboard_mod
from . import llm as llm_mod

TOOL_VERSION = "1.0.0"


def _parse_now(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m github_hygiene",
        description="GitHub org security-advisory + access-hygiene scanner (read-only).",
    )
    src = p.add_argument_group("data source")
    src.add_argument("--mock", action="store_true",
                     help="Use the built-in synthetic org (offline, no token).")
    src.add_argument("--public", action="store_true",
                     help="With --mock, simulate a PUBLIC org (collaborators + "
                          "advisories gated) to exercise public-limited fallback.")
    src.add_argument("--org", help="GitHub org login to scan (real API).")
    src.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"),
                     help="GitHub token (or set GITHUB_TOKEN). Read-only scopes only.")

    tune = p.add_argument_group("scan tuning")
    tune.add_argument("--lookback-days", type=int, default=None,
                      help="Activity window in days (default 180).")
    tune.add_argument("--now", type=_parse_now, default=None,
                      help="Override 'now' (ISO-8601) for reproducible runs. "
                           "Defaults to the fixture date under --mock.")
    tune.add_argument("--cache-dir", default=None,
                      help="ETag cache dir for cheap, idempotent re-runs (real API).")
    tune.add_argument("--verbose", action="store_true")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output-dir", default="sample_output",
                     help="Directory to write outputs into (created if missing).")

    ai = p.add_argument_group("optional AI summary (off by default)")
    ai.add_argument("--ai-summary", action="store_true",
                    help="Add a plain-English risk summary to the dashboard. "
                         "Requires ANTHROPIC_API_KEY (or --ai-key). Fails soft.")
    ai.add_argument("--ai-key", default=os.environ.get("ANTHROPIC_API_KEY"),
                    help="Anthropic API key (or set ANTHROPIC_API_KEY).")
    ai.add_argument("--ai-model", default=llm_mod.DEFAULT_MODEL,
                    help=f"Anthropic model (default {llm_mod.DEFAULT_MODEL}).")
    return p


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run(args) -> int:
    if not args.mock and not args.org:
        print("error: provide --org NAME (real scan) or --mock (offline demo).",
              file=sys.stderr)
        return 2

    scfg = ScoringConfig()
    if args.lookback_days is not None:
        scfg.lookback_days = args.lookback_days
    acfg = ApiConfig()

    # ---- build the client + choose the reference clock --------------------
    if args.mock:
        client = MockGitHubClient(authorized=not args.public)
        org = client.fx["org"]
        now = args.now or client.now  # fixture date -> deterministic sample
        print(f"[mode] MOCK org '{org}' "
              f"({'public-limited' if args.public else 'authorized'} simulation)")
    else:
        if not args.token:
            print("warning: no token provided; only public data will be visible, "
                  "and the scan will run in public-limited mode.", file=sys.stderr)
        client = GitHubClient(token=args.token, cfg=acfg,
                              cache_dir=args.cache_dir, verbose=args.verbose)
        org = args.org
        now = args.now or datetime.now(timezone.utc)
        print(f"[mode] LIVE scan of org '{org}'")

    # ---- run ---------------------------------------------------------------
    scanner = Scanner(client, org, scoring_cfg=scfg, api_cfg=acfg, now=now)
    try:
        result = scanner.scan()
    except Exception as exc:  # noqa: BLE001  (top-level CLI guard)
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return 1

    # ---- write outputs -----------------------------------------------------
    outdir = args.output_dir
    os.makedirs(outdir, exist_ok=True)
    paths = {
        "report.json": os.path.join(outdir, "report.json"),
        "access_review.csv": os.path.join(outdir, "access_review.csv"),
        "members.csv": os.path.join(outdir, "members.csv"),
        "advisories.csv": os.path.join(outdir, "advisories.csv"),
        "dashboard.html": os.path.join(outdir, "dashboard.html"),
    }
    summary = report_mod.compute_summary(result)

    # ---- optional AI risk summary (off unless flag + key) -----------------
    ai_summary = None
    if args.ai_summary:
        sample = [
            {"login": r.login, "repo": r.repo, "permission": r.permission,
             "priority": r.priority}
            for rr in result.repo_reports for r in rr.recommendations
        ]
        sample.sort(key=lambda s: {"high": 0, "medium": 1, "low": 2}[s["priority"]])
        ai_summary = llm_mod.summarise(summary, api_key=args.ai_key,
                                       model=args.ai_model, sample_suggestions=sample)
        if ai_summary:
            with open(os.path.join(outdir, "ai_summary.md"), "w", encoding="utf-8") as fh:
                fh.write(f"# AI risk summary — {result.org}\n\n{ai_summary}\n")
            print("[ai]   risk summary generated")
        else:
            print("[ai]   summary skipped (no key or API unavailable) — "
                  "dashboard renders without it")

    report_mod.write_json(paths["report.json"], result)
    report_mod.write_access_csv(paths["access_review.csv"], result)
    report_mod.write_members_csv(paths["members.csv"], result)
    report_mod.write_advisories_csv(paths["advisories.csv"], result)
    with open(paths["dashboard.html"], "w", encoding="utf-8") as fh:
        fh.write(dashboard_mod.render(result, ai_summary=ai_summary))

    # ---- manifest: metadata + content hashes ------------------------------
    # report.json is excluded from its own hash set; everything else is hashed
    # so a re-run can be proven byte-identical (idempotency evidence).
    hashes = {name: _sha256_file(path) for name, path in paths.items()
              if name != "dashboard.html"}  # html embeds a timestamp; hash data files
    manifest = {
        "tool_version": TOOL_VERSION,
        "org": result.org,
        "mode": result.mode,
        "generated_at": result.generated_at,
        "reference_now": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lookback_days": scfg.lookback_days,
        "api_calls": result.api_calls,
        "owners": result.owners,
        "totals": summary["totals"],
        "advisories_open": summary["advisories"]["total_open"],
        "access_suggestions": summary["access"],
        "warnings": result.warnings,
        "data_file_sha256": hashes,
    }
    with open(os.path.join(outdir, "run_manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)

    # ---- console summary ---------------------------------------------------
    a = summary["advisories"]; acc = summary["access"]
    print(f"[done] mode={result.mode}  repos={summary['totals']['repos']}  "
          f"api_calls={result.api_calls}")
    print(f"       advisories open: {a['total_open']} "
          f"(critical {a['open_by_severity']['critical']}, "
          f"high {a['open_by_severity']['high']})")
    print(f"       access suggestions: {acc['total_suggestions']} "
          f"(high {acc['by_priority']['high']}, "
          f"medium {acc['by_priority']['medium']}, low {acc['by_priority']['low']})")
    for w in result.warnings:
        print(f"       ! {w}")
    print(f"[out]  {os.path.abspath(outdir)}")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
