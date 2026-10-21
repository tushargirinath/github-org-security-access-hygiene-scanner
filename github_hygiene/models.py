"""Typed data models for the scanner (stdlib dataclasses only).

These describe the *normalised* view of GitHub data the rest of the tool works
with, so the engine never touches raw API JSON directly. Every model is
JSON-serialisable via `dataclasses.asdict` for the report output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Dict


# --------------------------------------------------------------------------- #
# Repositories & advisories
# --------------------------------------------------------------------------- #
@dataclass
class Repo:
    name: str
    full_name: str
    private: bool
    archived: bool
    fork: bool
    disabled: bool
    default_branch: str
    pushed_at: Optional[str]
    created_at: Optional[str]
    size_kb: int = 0

    @property
    def is_empty(self) -> bool:
        # GitHub reports size 0 and a null pushed_at for freshly-created / empty
        # repos; either signal means "no content to analyse".
        return self.size_kb == 0 or self.pushed_at is None


@dataclass
class Advisory:
    """A dependency vulnerability alert (Dependabot) normalised to the fields
    the dashboard needs."""
    repo: str
    ghsa_id: str
    severity: str            # critical | high | medium | low
    package: str             # ecosystem:name
    summary: str
    state: str               # open | fixed | dismissed | auto_dismissed
    created_at: str
    age_days: int
    is_mock: bool = False    # True when synthesised (see advisories.py)


# --------------------------------------------------------------------------- #
# Members & their contribution
# --------------------------------------------------------------------------- #
@dataclass
class ContributionMetrics:
    """Raw activity counts for one member on one repo, inside the lookback
    window."""
    commits: int = 0
    prs_opened: int = 0
    prs_merged: int = 0
    reviews: int = 0
    last_activity: Optional[str] = None  # ISO date of most recent event

    def as_counts(self) -> Dict[str, int]:
        return {
            "commits": self.commits,
            "prs_opened": self.prs_opened,
            "prs_merged": self.prs_merged,
            "reviews": self.reviews,
        }


@dataclass
class MemberContribution:
    """A member's access to, and contribution on, a single repo — plus the
    derived scores. This is the row the access review is built from."""
    login: str
    account_type: str                 # User | Bot
    permission: str                   # admin | maintain | write | triage | read | unknown
    access_via: str                   # direct | team | outside_collaborator | contributor
    is_owner: bool
    is_bot: bool
    metrics: ContributionMetrics = field(default_factory=ContributionMetrics)

    raw_score: float = 0.0            # weighted event sum (pre-recency)
    recency_factor: float = 0.0       # 0..1
    score: float = 0.0                # raw_score * recency_factor
    relative_score: float = 0.0       # 0..100, vs repo's top contributor
    days_since_activity: Optional[int] = None


@dataclass
class AccessRecommendation:
    """A *suggestion* (never an action) that a member's access to a repo be
    reviewed for removal, with the evidence that produced it."""
    repo: str
    login: str
    permission: str
    access_via: str
    score: float
    relative_score: float
    days_since_activity: Optional[int]
    metrics: Dict[str, int]
    priority: str                     # high | medium | low
    reasons: List[str]                # human-readable evidence


# --------------------------------------------------------------------------- #
# Per-repo and org-wide roll-ups
# --------------------------------------------------------------------------- #
@dataclass
class RepoReport:
    repo: Repo
    flags: List[str] = field(default_factory=list)   # archived, fork, empty, new, single_maintainer, ...
    advisories: List[Advisory] = field(default_factory=list)
    contributions: List[MemberContribution] = field(default_factory=list)
    recommendations: List[AccessRecommendation] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)   # e.g. "recommendations suppressed: new repo"


@dataclass
class ScanResult:
    org: str
    generated_at: str
    mode: str                          # authorized | public-limited | mock
    config: dict
    owners: List[str]
    repo_reports: List[RepoReport] = field(default_factory=list)
    api_calls: int = 0
    warnings: List[str] = field(default_factory=list)
