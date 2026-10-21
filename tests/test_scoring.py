"""Unit tests for the scoring policy (pure, deterministic).

Run: python -m unittest tests.test_scoring   (from the tushar-task/ dir)
"""
import math
import unittest
from datetime import datetime, timezone, timedelta

from github_hygiene.config import ScoringConfig
from github_hygiene.models import MemberContribution, ContributionMetrics
from github_hygiene import scoring

NOW = datetime(2025, 1, 1, tzinfo=timezone.utc)


def iso(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT00:00:00Z")


def mk(login="alice", perm="write", via="direct", owner=False, bot=False,
       commits=0, prs=0, merged=0, reviews=0, last=None):
    return MemberContribution(
        login=login, account_type="Bot" if bot else "User",
        permission=perm, access_via=via, is_owner=owner, is_bot=bot,
        metrics=ContributionMetrics(commits=commits, prs_opened=prs,
                                    prs_merged=merged, reviews=reviews,
                                    last_activity=last),
    )


class TestRawScore(unittest.TestCase):
    def test_weighted_sum(self):
        cfg = ScoringConfig()
        m = ContributionMetrics(commits=2, prs_opened=1, prs_merged=1, reviews=3)
        # 2*1 + 1*2 + 1*3 + 3*2 = 2+2+3+6 = 13
        self.assertEqual(scoring.raw_score(m, cfg), 13.0)


class TestRecency(unittest.TestCase):
    def test_decay_points(self):
        cfg = ScoringConfig(half_life_days=90)
        self.assertAlmostEqual(scoring.recency_factor(0, cfg), 1.0)
        self.assertAlmostEqual(scoring.recency_factor(90, cfg), 0.5)
        self.assertAlmostEqual(scoring.recency_factor(180, cfg), 0.25)
        self.assertEqual(scoring.recency_factor(None, cfg), 0.0)


class TestScoreMember(unittest.TestCase):
    def test_score_is_raw_times_recency(self):
        cfg = ScoringConfig(half_life_days=90)
        mc = mk(commits=10, last=iso(90))
        scoring.score_member(mc, cfg, now=NOW)
        self.assertEqual(mc.days_since_activity, 90)
        self.assertAlmostEqual(mc.raw_score, 10.0)
        self.assertAlmostEqual(mc.recency_factor, 0.5)
        self.assertAlmostEqual(mc.score, 5.0)


class TestRelative(unittest.TestCase):
    def test_relative_scaling(self):
        cfg = ScoringConfig()
        a = mk("a", commits=100, last=iso(1)); scoring.score_member(a, cfg, NOW)
        b = mk("b", commits=10, last=iso(1)); scoring.score_member(b, cfg, NOW)
        scoring.assign_relative_scores([a, b])
        self.assertEqual(a.relative_score, 100.0)
        self.assertTrue(0 < b.relative_score < 20)

    def test_all_zero_no_divzero(self):
        cfg = ScoringConfig()
        a = mk("a"); scoring.score_member(a, cfg, NOW)
        scoring.assign_relative_scores([a])
        self.assertEqual(a.relative_score, 0.0)


class TestRecommendations(unittest.TestCase):
    def setUp(self):
        self.cfg = ScoringConfig()

    def _prep(self, members):
        for m in members:
            scoring.score_member(m, self.cfg, NOW)
        scoring.assign_relative_scores(members)

    def test_owner_never_flagged(self):
        owner = mk("owner", perm="admin", owner=True, last=iso(400))  # very stale
        self._prep([owner])
        self.assertIsNone(scoring.recommend_for_member(owner, self.cfg, False))

    def test_bot_never_flagged(self):
        bot = mk("dependabot[bot]", bot=True, last=None)
        self._prep([bot])
        self.assertIsNone(scoring.recommend_for_member(bot, self.cfg, False))

    def test_single_human_repo_not_flagged(self):
        solo = mk("solo", last=iso(400))
        self._prep([solo])
        self.assertIsNone(scoring.recommend_for_member(solo, self.cfg, True))

    def test_active_member_not_flagged(self):
        top = mk("top", commits=200, last=iso(1))
        active = mk("active", commits=60, last=iso(2))
        self._prep([top, active])
        self.assertIsNone(scoring.recommend_for_member(active, self.cfg, False))

    def test_stale_low_member_flagged(self):
        top = mk("top", commits=200, last=iso(1))
        stale = mk("stale", perm="admin", last=iso(400))  # zero activity, admin
        self._prep([top, stale])
        rec = scoring.recommend_for_member(stale, self.cfg, False)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.priority, "high")   # admin + very stale
        self.assertTrue(any("No commits" in r for r in rec.reasons))

    def test_recent_but_low_not_flagged_due_to_recency(self):
        # Contributed little but *recently* -> not stale -> keep (benefit of doubt).
        top = mk("top", commits=200, last=iso(1))
        recent_low = mk("newbie", commits=1, last=iso(3))
        self._prep([top, recent_low])
        self.assertIsNone(scoring.recommend_for_member(recent_low, self.cfg, False))


class TestPriority(unittest.TestCase):
    """Priority reflects blast radius (permission + external exposure), because
    every suggestion is already stale so recency cannot discriminate."""

    def setUp(self):
        self.cfg = ScoringConfig()

    def _flag(self, perm, via="direct"):
        top = mk("top", commits=200, last=iso(1))
        m = mk("idle", perm=perm, via=via, last=iso(400))  # zero activity, stale
        for x in (top, m):
            scoring.score_member(x, self.cfg, NOW)
        scoring.assign_relative_scores([top, m])
        rec = scoring.recommend_for_member(m, self.cfg, False)
        self.assertIsNotNone(rec, f"{perm}/{via} should be flagged")
        return rec.priority

    def test_admin_is_high(self):
        self.assertEqual(self._flag("admin"), "high")

    def test_maintain_is_high(self):
        self.assertEqual(self._flag("maintain"), "high")

    def test_internal_write_is_medium(self):
        self.assertEqual(self._flag("write"), "medium")

    def test_outside_write_is_high(self):
        # external write access is a supply-chain exposure -> escalated
        self.assertEqual(self._flag("write", via="outside_collaborator"), "high")

    def test_read_is_low(self):
        self.assertEqual(self._flag("read"), "low")

    def test_unknown_is_low(self):
        # public-limited mode has no permission data -> cannot claim blast radius
        self.assertEqual(self._flag("unknown", via="contributor"), "low")


if __name__ == "__main__":
    unittest.main(verbosity=2)
