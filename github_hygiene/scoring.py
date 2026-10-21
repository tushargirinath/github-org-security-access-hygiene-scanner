"""
Contribution scoring and access-removal recommendations.

This module is the *judgment* of the tool and is deliberately pure (no I/O, no
network) so it can be unit-tested in isolation and reviewed as policy.

Model in one paragraph
----------------------
For each (member, repo) we take four activity counts inside a lookback window
-- commits authored, PRs opened, PRs merged, and PR reviews submitted -- and
combine them into a weighted `raw_score`. We then multiply by a `recency_factor`
that decays exponentially with the days since the member's last activity on that
repo (half-life 90 days by default). The product is the `contribution score`.
Within a repo we also express each member's score as a `relative_score`
(0-100) against the repo's most active contributor, because "enough
contribution" only means something relative to that repo's baseline.

Why this shape (short version; full rationale in docs/design_writeup.md):
* Weighting PRs/merges/reviews above raw commits rewards completed, integrated,
  reviewed work over commit volume, and protects reviewers/maintainers (often
  admins) who legitimately commit little.
* Recency decay encodes the actual question we're answering -- "does this
  person *still* need access?" -- rather than "were they ever active?".
* A removal suggestion requires BOTH a low relative score AND a low absolute
  score AND staleness, so we neither punish everyone on a busy repo nor keep
  everyone on a dormant one.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import List, Optional

from .config import ScoringConfig
from .models import (
    MemberContribution,
    AccessRecommendation,
    ContributionMetrics,
)


def _days_between(iso_ts: Optional[str], now: datetime) -> Optional[int]:
    if not iso_ts:
        return None
    try:
        # GitHub timestamps look like 2024-01-02T03:04:05Z
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (now - dt).days)


def raw_score(metrics: ContributionMetrics, cfg: ScoringConfig) -> float:
    """Weighted sum of activity events (pre-recency)."""
    w = cfg.weights
    return (
        metrics.commits * w["commit"]
        + metrics.prs_opened * w["pr_opened"]
        + metrics.prs_merged * w["pr_merged"]
        + metrics.reviews * w["review"]
    )


def recency_factor(days_since_activity: Optional[int], cfg: ScoringConfig) -> float:
    """Exponential decay in [0, 1]. No activity -> 0.0."""
    if days_since_activity is None:
        return 0.0
    return math.pow(0.5, days_since_activity / cfg.half_life_days)


def score_member(
    mc: MemberContribution,
    cfg: ScoringConfig,
    now: Optional[datetime] = None,
) -> MemberContribution:
    """Populate raw_score / recency_factor / score / days_since_activity on a
    MemberContribution (mutates and returns it)."""
    now = now or datetime.now(timezone.utc)
    mc.days_since_activity = _days_between(mc.metrics.last_activity, now)
    mc.raw_score = raw_score(mc.metrics, cfg)
    mc.recency_factor = recency_factor(mc.days_since_activity, cfg)
    mc.score = round(mc.raw_score * mc.recency_factor, 4)
    return mc


def assign_relative_scores(members: List[MemberContribution]) -> None:
    """Set relative_score (0-100) for each member vs. the repo's top *human*
    contributor.

    Bots are excluded from the baseline: a repo whose commits are dominated by
    an automation account (e.g. dependency bumps) must not deflate every human's
    relative score and cause spurious removal suggestions. If the repo has no
    human activity, we fall back to the overall max so the math stays defined."""
    human_top = max((m.score for m in members if not m.is_bot), default=0.0)
    top = human_top if human_top > 0 else max((m.score for m in members), default=0.0)
    for m in members:
        m.relative_score = round(100.0 * m.score / top, 1) if top > 0 else 0.0


def _priority(mc: MemberContribution, cfg: ScoringConfig) -> str:
    """Rank a suggestion by the *blast radius* of the unused access.

    Every suggestion is already stale by construction (see recommend_for_member),
    so recency does not discriminate between them -- what a security lead triages
    on is "how much damage could this idle grant do?". That is a function of the
    permission level and whether the account is external:

      * admin / maintain -> can change code, settings, releases, or protections.
      * an *outside* collaborator with write -> external write access is a
        supply-chain exposure and warrants the same urgency.
      * plain (internal) write -> can push code: medium.
      * triage / read / unknown -> limited blast radius: low.

    Note: in public-limited mode permission is "unknown", so suggestions there
    are correctly capped at low priority -- we cannot assert blast radius without
    the collaborator/permission data that mode lacks.
    """
    perm = mc.permission
    outside = mc.access_via == "outside_collaborator"
    if perm in ("admin", "maintain") or (outside and perm == "write"):
        return "high"
    if perm == "write":
        return "medium"
    return "low"


def recommend_for_member(
    mc: MemberContribution,
    cfg: ScoringConfig,
    is_sole_maintainer: bool,
) -> Optional[AccessRecommendation]:
    """Return a removal *suggestion* if the member's access looks unjustified,
    else None. Never returns an action -- only a reviewable recommendation.

    Hard exclusions (never suggested):
      * org owners
      * bots / service accounts
      * the sole active human contributor of a repo (they are the maintainer)
    """
    if mc.is_owner or mc.is_bot or is_sole_maintainer:
        return None

    stale = (mc.days_since_activity is None) or (mc.days_since_activity > cfg.stale_days)
    low_relative = mc.relative_score < cfg.rel_threshold
    low_absolute = mc.score < cfg.abs_floor

    if not (stale and low_relative and low_absolute):
        return None

    reasons: List[str] = []
    if mc.metrics.commits == 0 and mc.metrics.prs_opened == 0 and mc.metrics.reviews == 0:
        reasons.append("No commits, PRs, or reviews in the lookback window.")
    else:
        reasons.append(
            "Low activity: "
            f"{mc.metrics.commits} commits, {mc.metrics.prs_opened} PRs opened, "
            f"{mc.metrics.prs_merged} merged, {mc.metrics.reviews} reviews."
        )
    if mc.days_since_activity is None:
        reasons.append("No recorded activity on this repo in the window.")
    else:
        reasons.append(f"Last activity ~{mc.days_since_activity} days ago.")
    reasons.append(
        f"Contribution is {mc.relative_score:.0f}% of the repo's top contributor "
        f"(threshold {cfg.rel_threshold:.0f}%)."
    )
    if mc.permission in cfg.high_privilege:
        reasons.append(
            f"Holds '{mc.permission}' access — elevated privilege with little recent use."
        )
    if mc.access_via == "outside_collaborator":
        reasons.append("Outside collaborator — external access warrants extra scrutiny.")

    return AccessRecommendation(
        repo="",  # filled in by the scanner (it knows the repo context)
        login=mc.login,
        permission=mc.permission,
        access_via=mc.access_via,
        score=mc.score,
        relative_score=mc.relative_score,
        days_since_activity=mc.days_since_activity,
        metrics=mc.metrics.as_counts(),
        priority=_priority(mc, cfg),
        reasons=reasons,
    )
