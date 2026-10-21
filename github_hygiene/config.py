"""
Central configuration for the GitHub org security & access-hygiene scanner.

Everything that encodes *judgment* (scoring weights, decay half-life, the
thresholds that turn a score into a "review for removal" suggestion) lives here
in one place, so a reviewer can see and tune the policy without reading the
engine. The rationale for each number is in docs/design_writeup.md and mirrored
in the comments below.

Zero third-party dependencies: standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Dict


# --------------------------------------------------------------------------- #
# Contribution scoring policy
# --------------------------------------------------------------------------- #
# A member's contribution to a repo is a weighted sum of activity events inside
# a lookback window, multiplied by a recency decay factor. See scoring.py.
#
# Weights encode "what a unit of each activity is worth". PRs and reviews are
# valued above raw commits on purpose:
#   - a merged PR is completed, integrated, usually reviewed work;
#   - reviews are a maintainership signal and are the reason senior/admin
#     accounts with few commits still legitimately hold access.
# These are deliberately simple, documented, and easy to tune.

DEFAULT_WEIGHTS: Dict[str, float] = {
    "commit": 1.0,        # a commit authored on the default branch
    "pr_opened": 2.0,     # opening a PR = an intentional unit of work
    "pr_merged": 3.0,     # a merged PR = completed + integrated work
    "review": 2.0,        # a submitted PR review = maintainership signal
}


@dataclass
class ScoringConfig:
    """Tunable policy for turning raw activity into a contribution score and a
    (human-reviewed) access-removal suggestion."""

    # How far back we look for activity. Access hygiene is about *current*
    # justification, so we bound the window and additionally decay by recency.
    lookback_days: int = 180  # 6 months

    # Exponential recency decay: an event's weight halves every `half_life_days`.
    # activity today -> ~1.0x, 90d ago -> 0.5x, 180d -> 0.25x, 360d -> ~0.06x.
    half_life_days: float = 90.0

    weights: Dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))

    # ---- Removal-suggestion thresholds (all must hold; owners always exempt) --
    # relative_score is the member's contribution as a % of the repo's top
    # contributor. Below this, they contribute marginally vs. active maintainers.
    rel_threshold: float = 15.0  # percent

    # An absolute floor so we don't flag people on repos where *everyone* is
    # active (high bar) yet also catch truly-dormant access. Expressed in the
    # same weighted+decayed units as the score.
    abs_floor: float = 3.0

    # Days since the member's last activity on the repo before access is
    # considered "stale". Zero-activity-in-window always counts as stale.
    stale_days: int = 180

    # Repos younger than this (days) have too little history to judge fairly;
    # recommendations are suppressed and the repo is flagged instead.
    new_repo_days: int = 30

    # Permission levels considered "high privilege" (worth prioritising for
    # cleanup). Read/triage access is low risk and de-prioritised.
    high_privilege = ("admin", "maintain", "write")

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Accounts that must never be auto-suggested for removal
# --------------------------------------------------------------------------- #
# Bots / service accounts: detected by GitHub account type == "Bot", a
# "[bot]" login suffix, or this allowlist of common automation identities.
# They are excluded from removal suggestions and surfaced separately, because
# revoking a service account is an operational change, not an access-hygiene one.
KNOWN_BOT_LOGINS = {
    "dependabot",
    "dependabot[bot]",
    "github-actions",
    "github-actions[bot]",
    "renovate",
    "renovate[bot]",
    "codecov",
    "codecov[bot]",
    "mergify",
    "mergify[bot]",
    "pre-commit-ci",
    "pre-commit-ci[bot]",
    "snyk-bot",
    "imgbot",
    "allcontributors[bot]",
    "web-flow",  # GitHub's web-UI merge author
}


# --------------------------------------------------------------------------- #
# Advisory severity ordering / weights (for "most affected repos" ranking)
# --------------------------------------------------------------------------- #
SEVERITY_ORDER = ("critical", "high", "medium", "low")
SEVERITY_WEIGHT = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 1.0}


# --------------------------------------------------------------------------- #
# API / networking defaults
# --------------------------------------------------------------------------- #
@dataclass
class ApiConfig:
    api_root: str = "https://api.github.com"
    # GitHub recommends this Accept header; the version pins response shape.
    accept: str = "application/vnd.github+json"
    api_version: str = "2022-11-28"
    user_agent: str = "github-org-hygiene-scanner/1.0 (+interview-task)"
    per_page: int = 100  # max page size -> fewest requests

    # Depth caps keep a live run bounded on large orgs (see design writeup,
    # "behaviour on a 100+ repo org"). They limit *pages*, not correctness of
    # the hygiene signal, and are configurable.
    max_commit_pages: int = 5      # up to 500 recent commits / repo
    max_pr_pages: int = 5          # up to 500 recent PRs / repo
    max_pull_reviews: int = 300    # cap review lookups per repo

    # When remaining rate-limit budget drops below this, pause until reset.
    rate_limit_floor: int = 25
    # Never sleep longer than this for a rate-limit reset (fail soft instead).
    max_sleep_seconds: int = 900
