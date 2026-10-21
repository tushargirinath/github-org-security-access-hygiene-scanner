# GitHub Org Security & Access-Hygiene Scanner

A read-only tool that scans **every repository in a GitHub organization** and
produces two things a security lead can act on in minutes:

1. **A consolidated security-advisory report** — all Dependabot alerts across the
   org, by severity, state (open / fixed / dismissed), and age, with the oldest
   unresolved surfaced first.
2. **A data-driven access review** — members whose contribution no longer
   justifies their access, ranked by blast radius, each with plain-English
   evidence.

Both land in a **single self-contained `dashboard.html`** designed to be read in
under two minutes. **Access removals are always suggestions for human review —
the tool never revokes anything.**

## Why it looks the way it does

- **Zero dependencies — Python standard library only.** Nothing to `pip install`;
  the whole thing is auditable and runs anywhere Python 3.9+ does. For a security
  tool, "no supply chain of its own" is a feature.
- **Read-only.** It only ever reads the GitHub API. It has no code path that
  writes, and access changes are recommendations, not actions.
- **Idempotent.** Re-runs reproduce byte-identical output (proven in
  `docs/RUN_LOG.md`) and use an ETag cache so unchanged data returns `304`
  without consuming the primary rate limit.
- **Honest when blind.** Against an org you don't administer, it degrades to a
  clearly-labelled *public-limited* mode instead of guessing.

## Quick start (no credentials needed)

```bash
# offline demo against the built-in synthetic org
python -m github_hygiene --mock -o sample_output
# then open in a browser
sample_output/dashboard.html 
```

Run the tests:

```bash
python -m unittest discover -s tests -v      # 17 tests, all offline
```

Scan a real org (read-only, short-lived token — run on your own machine):

```bash
export GITHUB_TOKEN=ghp_xxx_readonly
python -m github_hygiene --org YOUR_ORG --cache-dir .cache -o out

then open -- .\out\dashboard.html
```

See **`docs/RUNBOOK.md`** for token scopes, scheduling, flags, and troubleshooting.

## What a run produces

```
<output-dir>/
  dashboard.html      # the 2-minute security-lead view (self-contained, offline)
  report.json         # complete machine-readable results
  access_review.csv   # one row per access-removal SUGGESTION, with evidence
  advisories.csv      # every advisory across the org
  members.csv         # every (member, repo) contribution row
  run_manifest.json   # run metadata + SHA-256 of each data file (idempotency proof)
```

## How access suggestions are decided (short version)

For each `(member, repo)` in a 180-day window: `score = (1·commits + 2·prs +
3·merges + 2·reviews) · 0.5^(days_idle/90)`, expressed relative to the top
**human** contributor. A removal is suggested only when a grant is **stale AND
low-relative AND low-absolute**, and owners, bots, and sole maintainers are never
suggested. Priority is **blast radius** (admin/maintain or outside-write = high;
internal write = medium; read/unknown = low). Full justification and the edge-case
handling are in **`docs/DESIGN.md`**.

## Repository layout

```
github_hygiene/        # the tool (stdlib-only Python, ~2,400 lines)
  __main__.py          #   CLI entrypoint:  python -m github_hygiene
  client.py            #   read-only GitHub REST client (pagination, rate limits, ETag cache)
  scanner.py           #   orchestrates the per-repo scan
  scoring.py           #   contribution scoring + access recommendation logic
  advisories.py        #   Dependabot alert normalisation
  dashboard.py         #   self-contained HTML dashboard renderer
  report.py            #   JSON + CSV writers, summary computation
  mock.py              #   built-in synthetic org (offline demo + tests)
  llm.py               #   OPTIONAL, off-by-default plain-English risk summary
  models.py, config.py #   data classes and tunables
tests/                 # 17 unit tests over the graded logic
n8n/                   # importable workflow JSON + honest notes on the tooling
docs/
  DESIGN.md            # 1-page design write-up (scoring, assumptions, scale)
  RUN_LOG.md           # step-by-step run with captured outputs
  AI_USAGE.md          # AI/LLM usage disclosure
  RUNBOOK.md           # setup, token scopes, scheduling, troubleshooting
sample_output/         # captured authorized run (open dashboard.html)
sample_output_public/  # captured public-limited run
```

## Reading guide for the reviewer

Start with **`docs/DESIGN.md`** (the reasoning), then open
**`sample_output/dashboard.html`** (the deliverable) and skim
**`docs/RUN_LOG.md`** (proof it runs and is idempotent). `docs/AI_USAGE.md`
covers AI usage; `n8n/n8n_notes.md` covers the automation-tooling experience.
