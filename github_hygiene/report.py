"""Serialisation + org-wide roll-ups.

Produces the machine-readable outputs (report.json, CSVs) and the summary
statistics the dashboard renders. Kept separate from rendering so the same
numbers feed the JSON, the CSVs, and the HTML -- guaranteeing they agree.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from typing import Dict, List

from .config import SEVERITY_ORDER, SEVERITY_WEIGHT
from .models import ScanResult


def compute_summary(result: ScanResult) -> dict:
    sev_open = {s: 0 for s in SEVERITY_ORDER}
    sev_all = {s: 0 for s in SEVERITY_ORDER}
    state_counts: Dict[str, int] = {}
    oldest = {"age_days": -1, "repo": None, "package": None, "severity": None}
    any_mock = False
    repo_rows: List[dict] = []

    analysed = skipped_empty = archived = forks = new_repos = 0
    unique_members = set()
    rec_priority = {"high": 0, "medium": 0, "low": 0}
    total_recs = 0

    for rr in result.repo_reports:
        if "empty" in rr.flags:
            skipped_empty += 1
        else:
            analysed += 1
        if "archived" in rr.flags:
            archived += 1
        if "fork" in rr.flags:
            forks += 1
        if "new_repo" in rr.flags:
            new_repos += 1

        open_weight = 0.0
        open_count = 0
        for a in rr.advisories:
            any_mock = any_mock or a.is_mock
            if a.severity in sev_all:
                sev_all[a.severity] += 1
            state_counts[a.state] = state_counts.get(a.state, 0) + 1
            if a.state == "open":
                if a.severity in sev_open:
                    sev_open[a.severity] += 1
                open_weight += SEVERITY_WEIGHT.get(a.severity, 1.0)
                open_count += 1
                if a.age_days > oldest["age_days"]:
                    oldest = {"age_days": a.age_days, "repo": rr.repo.name,
                              "package": a.package, "severity": a.severity}

        for mc in rr.contributions:
            unique_members.add(mc.login)

        for rec in rr.recommendations:
            total_recs += 1
            rec_priority[rec.priority] += 1

        repo_rows.append({
            "repo": rr.repo.name,
            "open_advisories": open_count,
            "advisory_risk_weight": round(open_weight, 1),
            "recommendations": len(rr.recommendations),
            "flags": rr.flags,
        })

    most_affected = sorted(
        [r for r in repo_rows if r["open_advisories"] > 0],
        key=lambda r: (-r["advisory_risk_weight"], -r["open_advisories"]))[:5]

    return {
        "org": result.org,
        "generated_at": result.generated_at,
        "mode": result.mode,
        "totals": {
            "repos": len(result.repo_reports),
            "analysed": analysed,
            "skipped_empty": skipped_empty,
            "archived": archived,
            "forks": forks,
            "new_repos": new_repos,
            "unique_members_with_access": len(unique_members),
        },
        "advisories": {
            "open_by_severity": sev_open,
            "all_by_severity": sev_all,
            "by_state": state_counts,
            "total_open": sum(sev_open.values()),
            "oldest_unresolved": oldest if oldest["age_days"] >= 0 else None,
            "contains_mock": any_mock,
        },
        "access": {
            "total_suggestions": total_recs,
            "by_priority": rec_priority,
        },
        "most_affected_repos": most_affected,
    }


def to_dict(result: ScanResult) -> dict:
    return {
        "summary": compute_summary(result),
        "owners": result.owners,
        "warnings": result.warnings,
        "api_calls": result.api_calls,
        "repos": [
            {
                "repo": asdict(rr.repo),
                "flags": rr.flags,
                "notes": rr.notes,
                "advisories": [asdict(a) for a in rr.advisories],
                "contributions": [asdict(m) for m in rr.contributions],
                "recommendations": [asdict(r) for r in rr.recommendations],
            }
            for rr in result.repo_reports
        ],
    }


def write_json(path: str, result: ScanResult) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_dict(result), fh, indent=2, sort_keys=True)


def write_access_csv(path: str, result: ScanResult) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["repo", "login", "permission", "access_via", "priority",
                    "score", "relative_score_pct", "days_since_activity",
                    "commits", "prs_opened", "prs_merged", "reviews", "evidence"])
        for rr in result.repo_reports:
            for r in rr.recommendations:
                m = r.metrics
                w.writerow([r.repo, r.login, r.permission, r.access_via, r.priority,
                            r.score, r.relative_score, r.days_since_activity,
                            m["commits"], m["prs_opened"], m["prs_merged"], m["reviews"],
                            " | ".join(r.reasons)])


def write_members_csv(path: str, result: ScanResult) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["repo", "login", "is_owner", "is_bot", "permission", "access_via",
                    "commits", "prs_opened", "prs_merged", "reviews",
                    "score", "relative_score_pct", "days_since_activity"])
        for rr in result.repo_reports:
            for m in rr.contributions:
                w.writerow([rr.repo.name, m.login, m.is_owner, m.is_bot, m.permission,
                            m.access_via, m.metrics.commits, m.metrics.prs_opened,
                            m.metrics.prs_merged, m.metrics.reviews, m.score,
                            m.relative_score, m.days_since_activity])


def write_advisories_csv(path: str, result: ScanResult) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["repo", "ghsa_id", "severity", "package", "state",
                    "age_days", "is_mock", "summary"])
        for rr in result.repo_reports:
            for a in rr.advisories:
                w.writerow([a.repo, a.ghsa_id, a.severity, a.package, a.state,
                            a.age_days, a.is_mock, a.summary])
