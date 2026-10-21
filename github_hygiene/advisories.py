"""Advisory handling: normalise real Dependabot alerts, and provide a clearly
-labelled synthetic fallback for when the security API is not accessible (e.g.
scanning a public org you don't administer -> the endpoint returns 403).

Any advisory that did not come from the live API is stamped `is_mock=True` and
the dashboard renders a visible "MOCK" badge for it -- per the brief's
requirement to state clearly where and why something was mocked.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import List, Optional

from .models import Advisory


def _age_days(created_at: Optional[str], now: datetime) -> int:
    if not created_at:
        return 0
    try:
        dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        return 0
    return max(0, (now - dt).days)


def normalise_alert(repo: str, alert: dict, now: datetime) -> Advisory:
    """Map a GitHub Dependabot-alert JSON object to our Advisory model."""
    adv = alert.get("security_advisory", {}) or {}
    vuln = alert.get("security_vulnerability", {}) or {}
    pkg = (vuln.get("package") or alert.get("dependency", {}).get("package", {}) or {})
    ecosystem = pkg.get("ecosystem", "")
    name = pkg.get("name", "unknown")
    severity = (vuln.get("severity") or adv.get("severity") or "low").lower()
    return Advisory(
        repo=repo,
        ghsa_id=adv.get("ghsa_id", "GHSA-unknown"),
        severity=severity,
        package=f"{ecosystem}:{name}" if ecosystem else name,
        summary=adv.get("summary", ""),
        state=alert.get("state", "open"),
        created_at=alert.get("created_at", ""),
        age_days=_age_days(alert.get("created_at"), now),
        is_mock=False,
    )


# A tiny, realistic pool for synthesising advisories deterministically per repo.
_SYNTH_POOL = [
    ("critical", "pip:django", "SQL injection via unsanitised ORM query"),
    ("high", "npm:lodash", "Prototype pollution in merge/set"),
    ("high", "pip:pyyaml", "Arbitrary code execution via unsafe load"),
    ("medium", "npm:axios", "SSRF through unvalidated redirect"),
    ("medium", "pip:requests", "Proxy-Authorization header leak on redirect"),
    ("low", "npm:tmp", "Insecure temp-file creation (dev dependency)"),
]


def synth_advisories(repo: str, now: datetime, seed_extra: str = "") -> List[Advisory]:
    """Deterministic synthetic advisories for a repo, used only when the real
    security API is unavailable. Clearly flagged is_mock=True."""
    h = int(hashlib.sha256((repo + seed_extra).encode()).hexdigest(), 16)
    count = h % 4  # 0..3 advisories
    out: List[Advisory] = []
    for i in range(count):
        sev, pkg, summary = _SYNTH_POOL[(h >> (i * 3)) % len(_SYNTH_POOL)]
        age = 10 + ((h >> (i * 5)) % 300)
        state = "open" if (h >> i) % 3 else "fixed"
        out.append(Advisory(
            repo=repo, ghsa_id=f"GHSA-synthetic-{abs(h) % 9999:04d}-{i}",
            severity=sev, package=pkg, summary=summary + "  [SYNTHETIC SAMPLE]",
            state=state, created_at="", age_days=age, is_mock=True,
        ))
    return out
