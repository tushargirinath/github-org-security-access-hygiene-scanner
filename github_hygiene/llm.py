"""
Optional plain-English risk summary via the Anthropic Messages API.

This is the one place the tool can call an LLM, and it is *off by default*:
nothing here runs unless the user passes --ai-summary AND a key is present. The
core scanner stays fully deterministic and dependency-free; this module is a thin
convenience layer that turns the already-computed summary statistics into a short
paragraph a security lead can paste into a ticket.

Security / privacy notes (called out because this is a security tool):
  * Only AGGREGATE statistics already present in report.json are sent (counts by
    severity, repo names, the top few suggestions). No tokens, secrets, or file
    contents leave the machine.
  * Uses stdlib urllib only -- no anthropic SDK, no third-party deps.
  * Any failure (no key, network error, API error, bad model) returns None and
    the scan/report/dashboard proceed unchanged.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import List, Optional

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-3-5-haiku-latest"


def build_prompt(summary: dict, sample_suggestions: Optional[List[dict]] = None) -> str:
    """Build the user prompt from aggregate stats. Kept pure and importable so a
    reviewer can see exactly what would be sent to the API."""
    adv = summary["advisories"]
    acc = summary["access"]
    tot = summary["totals"]
    lines = [
        f"Organization: {summary['org']}",
        f"Scan mode: {summary['mode']}",
        f"Repositories: {tot['repos']} total, {tot['analysed']} analysed, "
        f"{tot['archived']} archived, {tot['forks']} forks.",
        f"Open advisories: {adv['total_open']} "
        f"(critical {adv['open_by_severity']['critical']}, "
        f"high {adv['open_by_severity']['high']}, "
        f"medium {adv['open_by_severity']['medium']}, "
        f"low {adv['open_by_severity']['low']}).",
    ]
    if adv.get("oldest_unresolved"):
        o = adv["oldest_unresolved"]
        lines.append(f"Oldest unresolved advisory: {o['age_days']} days old "
                     f"({o['severity']} in {o['repo']}, {o['package']}).")
    if summary.get("most_affected_repos"):
        top = ", ".join(f"{r['repo']} ({r['open_advisories']} open)"
                        for r in summary["most_affected_repos"][:3])
        lines.append(f"Most exposed repos: {top}.")
    lines.append(
        f"Access-removal suggestions: {acc['total_suggestions']} "
        f"(high {acc['by_priority']['high']}, medium {acc['by_priority']['medium']}, "
        f"low {acc['by_priority']['low']}).")
    if sample_suggestions:
        lines.append("Top suggestions:")
        for s in sample_suggestions[:5]:
            lines.append(
                f"  - {s['login']} on {s['repo']} ({s['permission']}, {s['priority']} priority)")

    return (
        "You are a security operations assistant. Write a concise, factual risk "
        "summary (4-6 sentences, no bullet points) for a security lead based on "
        "the GitHub org scan data below. Lead with the single most urgent item, "
        "state the overall advisory and access-hygiene posture, and end with the "
        "one action you'd take first. Do not invent data beyond what is given. "
        "Remember access removals are review suggestions, not automatic actions.\n\n"
        + "\n".join(lines)
    )


def summarise(
    summary: dict,
    api_key: Optional[str] = None,
    model: str = DEFAULT_MODEL,
    sample_suggestions: Optional[List[dict]] = None,
    timeout: int = 30,
) -> Optional[str]:
    """Return a short natural-language risk summary, or None on any problem."""
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None

    prompt = build_prompt(summary, sample_suggestions)
    payload = json.dumps({
        "model": model,
        "max_tokens": 400,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")

    req = urllib.request.Request(
        ANTHROPIC_URL,
        data=payload,
        method="POST",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        parts = body.get("content", [])
        text = "".join(p.get("text", "") for p in parts if p.get("type") == "text")
        return text.strip() or None
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, KeyError):
        # Fail soft: the summary is a nicety, never a dependency.
        return None
