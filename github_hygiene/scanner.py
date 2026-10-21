"""
Scanner: orchestrates the full org scan and produces a ScanResult.

Flow per run:
  1. Resolve the org and its owners (owners are always protected downstream).
  2. Enumerate every repo (pagination), tagging archived / fork / empty / new.
  3. For each analysable repo:
       a. Determine members with access + permission + how they got it
          (direct / via-team / outside collaborator). If the collaborators API
          is not accessible (public org), fall back to the contributors list and
          run in "public-limited" mode.
       b. Quantify each member's contribution (commits, PRs opened/merged,
          reviews) inside the lookback window, and their recency.
       c. Score, rank, and produce access-removal *suggestions* (never actions).
       d. Pull Dependabot advisories (or a clearly-labelled synthetic set when
          the security API is gated).

The same code runs unchanged against the real GitHubClient and the MockGitHubClient.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from .advisories import normalise_alert, synth_advisories
from .client import GitHubError
from .config import ApiConfig, ScoringConfig, KNOWN_BOT_LOGINS
from .models import (
    Advisory, ContributionMetrics, MemberContribution, Repo, RepoReport, ScanResult,
)
from . import scoring


def _parse(iso_ts: Optional[str]) -> Optional[datetime]:
    if not iso_ts:
        return None
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _is_bot(login: str, account_type: str) -> bool:
    return (
        account_type == "Bot"
        or login.endswith("[bot]")
        or login.lower() in KNOWN_BOT_LOGINS
    )


class Scanner:
    def __init__(self, client, org: str,
                 scoring_cfg: Optional[ScoringConfig] = None,
                 api_cfg: Optional[ApiConfig] = None,
                 now: Optional[datetime] = None):
        self.client = client
        self.org = org
        self.scfg = scoring_cfg or ScoringConfig()
        self.acfg = api_cfg or ApiConfig()
        self.now = now or datetime.now(timezone.utc)
        self.window_start = self.now - timedelta(days=self.scfg.lookback_days)
        self.window_iso = self.window_start.strftime("%Y-%m-%dT%H:%M:%SZ")
        self._fell_back = False
        self.warnings: List[str] = []

    # ------------------------------------------------------------------ #
    def scan(self) -> ScanResult:
        self.client.get(f"orgs/{self.org}")  # verify org exists / access
        owners = self._resolve_owners()
        repos = self._list_repos()

        reports: List[RepoReport] = []
        for i, repo in enumerate(repos, 1):
            if getattr(self.client, "verbose", False):
                print(f"[{i}/{len(repos)}] Scanning {repo.name}...")
            reports.append(self._analyse_repo(repo, owners))

        mode = "public-limited" if self._fell_back else "authorized"
        return ScanResult(
            org=self.org,
            generated_at=self.now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            mode=mode,
            config={"scoring": self.scfg.to_dict(),
                    "lookback_days": self.scfg.lookback_days},
            owners=owners,
            repo_reports=reports,
            api_calls=getattr(self.client, "api_calls", 0),
            warnings=self.warnings,
        )

    # ------------------------------------------------------------------ #
    def _resolve_owners(self) -> List[str]:
        members, ok = self.client.paginate_optional(
            f"orgs/{self.org}/members", {"role": "admin", "per_page": 100})
        if not ok or not members:
            self.warnings.append(
                "Could not read the org owner list (needs org membership/admin). "
                "Owner-exclusion cannot be guaranteed in this mode — verify any "
                "suggestion against the real owners before acting.")
            return []
        return sorted({m["login"] for m in members})

    def _list_repos(self) -> List[Repo]:
        repos: List[Repo] = []
        for r in self.client.paginate(f"orgs/{self.org}/repos",
                                      {"per_page": self.acfg.per_page, "type": "all"}):
            repos.append(Repo(
                name=r["name"], full_name=r.get("full_name", f"{self.org}/{r['name']}"),
                private=r.get("private", False), archived=r.get("archived", False),
                fork=r.get("fork", False), disabled=r.get("disabled", False),
                default_branch=r.get("default_branch", "main"),
                pushed_at=r.get("pushed_at"), created_at=r.get("created_at"),
                size_kb=r.get("size", 0),
            ))
        return sorted(repos, key=lambda x: x.name)

    # ------------------------------------------------------------------ #
    def _analyse_repo(self, repo: Repo, owners: List[str]) -> RepoReport:
        report = RepoReport(repo=repo)
        if repo.archived:
            report.flags.append("archived")
        if repo.fork:
            report.flags.append("fork")

        # brand-new / empty repos: not enough to judge -> skip analysis.
        created = _parse(repo.created_at)
        is_new = created is not None and (self.now - created).days < self.scfg.new_repo_days
        if repo.is_empty:
            report.flags.append("empty")
            report.notes.append("Empty repo — no content to analyse; skipped.")
            return report

        # advisories (independent of member analysis)
        report.advisories = self._advisories_for_repo(repo)

        members, perms, access_via = self._members_for_repo(repo)
        if not members:
            report.notes.append("No members/collaborators resolved for this repo.")
            return report

        metrics = self._metrics_for_repo(repo, set(members))

        owner_set = set(owners)
        contribs: List[MemberContribution] = []
        for login in members:
            acct_type = perms.get(login, {}).get("type", "User")
            mc = MemberContribution(
                login=login,
                account_type=acct_type,
                permission=perms.get(login, {}).get("permission", "unknown"),
                access_via=access_via.get(login, "direct"),
                is_owner=login in owner_set,
                is_bot=_is_bot(login, acct_type),
                metrics=metrics.get(login, ContributionMetrics()),
            )
            scoring.score_member(mc, self.scfg, now=self.now)
            contribs.append(mc)

        scoring.assign_relative_scores(contribs)
        contribs.sort(key=lambda m: m.score, reverse=True)
        report.contributions = contribs

        # single active human contributor -> protect them (bus-factor note).
        active_humans = [m for m in contribs if not m.is_bot and m.score > 0]
        sole_maintainer = active_humans[0].login if len(active_humans) == 1 else None
        if sole_maintainer:
            report.flags.append("single_maintainer")
            report.notes.append(
                f"Single active maintainer ('{sole_maintainer}') — bus-factor risk; "
                "not suggested for removal.")

        if is_new:
            report.flags.append("new_repo")
            report.notes.append(
                f"Repo created <{self.scfg.new_repo_days}d ago — access "
                "recommendations suppressed (insufficient history).")
            return report

        for mc in contribs:
            rec = scoring.recommend_for_member(
                mc, self.scfg, is_sole_maintainer=(mc.login == sole_maintainer))
            if rec:
                rec.repo = repo.name
                if repo.archived:
                    rec.reasons.append(
                        "Repo is archived — access is unused and low-risk today, "
                        "but can be restored on unarchive; good candidate for bulk cleanup.")
                report.recommendations.append(rec)
        # deterministic ordering: priority then score asc
        prio = {"high": 0, "medium": 1, "low": 2}
        report.recommendations.sort(key=lambda r: (prio[r.priority], r.score, r.login))
        return report

    # ------------------------------------------------------------------ #
    def _members_for_repo(self, repo: Repo):
        """Returns (member_logins, perms{login:{permission,type}}, access_via{login:str})."""
        all_collabs, ok = self.client.paginate_optional(
            f"repos/{self.org}/{repo.name}/collaborators",
            {"affiliation": "all", "per_page": self.acfg.per_page})
        if ok:
            direct, _ = self.client.paginate_optional(
                f"repos/{self.org}/{repo.name}/collaborators",
                {"affiliation": "direct", "per_page": self.acfg.per_page})
            outside, _ = self.client.paginate_optional(
                f"repos/{self.org}/{repo.name}/collaborators",
                {"affiliation": "outside", "per_page": self.acfg.per_page})
            direct_set = {c["login"] for c in direct}
            outside_set = {c["login"] for c in outside}
            perms, via, logins = {}, {}, []
            for c in all_collabs:
                login = c["login"]
                logins.append(login)
                perms[login] = {"permission": c.get("role_name", "unknown"),
                                "type": c.get("type", "User")}
                if login in outside_set:
                    via[login] = "outside_collaborator"
                elif login in direct_set:
                    via[login] = "direct"
                else:
                    via[login] = "team"
            return logins, perms, via

        # ---- public-limited fallback: use contributors as the population ----
        self._fell_back = True
        contributors = list(self.client.paginate(
            f"repos/{self.org}/{repo.name}/contributors", {"per_page": self.acfg.per_page}))
        perms, via, logins = {}, {}, []
        for c in contributors:
            login = c["login"]
            logins.append(login)
            perms[login] = {"permission": "unknown", "type": c.get("type", "User")}
            via[login] = "contributor"
        return logins, perms, via

    def _advisories_for_repo(self, repo: Repo) -> List[Advisory]:
        alerts, ok = self.client.paginate_optional(
            f"repos/{self.org}/{repo.name}/dependabot/alerts",
            {"state": "all", "per_page": self.acfg.per_page})
        if ok:
            return [normalise_alert(repo.name, a, self.now) for a in alerts]
        # gated (public org) -> clearly-labelled synthetic advisories
        return synth_advisories(repo.name, self.now)

    # ------------------------------------------------------------------ #
    def _metrics_for_repo(self, repo: Repo, member_set) -> Dict[str, ContributionMetrics]:
        m: Dict[str, ContributionMetrics] = {}

        def touch(login: str) -> ContributionMetrics:
            return m.setdefault(login, ContributionMetrics())

        def bump_activity(cm: ContributionMetrics, iso_ts: Optional[str]):
            d = _parse(iso_ts)
            if d is None:
                return
            if cm.last_activity is None or d > _parse(cm.last_activity):
                cm.last_activity = iso_ts

        # commits (default branch, since window start)
        for c in self.client.paginate(
                f"repos/{self.org}/{repo.name}/commits",
                {"since": self.window_iso, "per_page": self.acfg.per_page},
                max_pages=self.acfg.max_commit_pages):
            author = c.get("author") or {}
            login = author.get("login")
            date = (c.get("commit", {}).get("author", {}) or {}).get("date")
            if not login:
                continue  # commit not linked to a GitHub account -> can't attribute
            cm = touch(login)
            if _parse(date) and _parse(date) >= self.window_start:
                cm.commits += 1
                bump_activity(cm, date)

        # pull requests
        pr_numbers: List[int] = []
        for pr in self.client.paginate(
                f"repos/{self.org}/{repo.name}/pulls",
                {"state": "all", "sort": "updated", "direction": "desc",
                 "per_page": self.acfg.per_page},
                max_pages=self.acfg.max_pr_pages):
            login = (pr.get("user") or {}).get("login")
            if not login:
                continue
            created = _parse(pr.get("created_at"))
            merged = _parse(pr.get("merged_at"))
            counted = False
            if created and created >= self.window_start:
                cm = touch(login); cm.prs_opened += 1; bump_activity(cm, pr.get("created_at"))
                counted = True
            if merged and merged >= self.window_start:
                cm = touch(login); cm.prs_merged += 1; bump_activity(cm, pr.get("merged_at"))
                counted = True
            if (created and created >= self.window_start) or (merged and merged >= self.window_start) or counted:
                if pr.get("number") is not None:
                    pr_numbers.append(pr["number"])

        # reviews (bounded by max_pull_reviews PRs)
        for number in pr_numbers[: self.acfg.max_pull_reviews]:
            try:
                for rev in self.client.paginate(
                        f"repos/{self.org}/{repo.name}/pulls/{number}/reviews",
                        {"per_page": self.acfg.per_page}):
                    login = (rev.get("user") or {}).get("login")
                    submitted = rev.get("submitted_at")
                    if not login:
                        continue
                    if _parse(submitted) and _parse(submitted) >= self.window_start:
                        cm = touch(login); cm.reviews += 1; bump_activity(cm, submitted)
            except GitHubError as ge:
                if getattr(self.client, "verbose", False):
                    print(f"  [warning] could not fetch reviews for PR #{number}: {ge}")

        return m
