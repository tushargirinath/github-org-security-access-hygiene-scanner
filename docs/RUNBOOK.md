# Runbook — setup, running, scheduling, troubleshooting

Operational guide for running the scanner. For *why* it works the way it does,
see `docs/DESIGN.md`; for a captured example run, see `docs/RUN_LOG.md`.

## 1. Prerequisites

- **Python 3.9 or newer.** Check with `python3 --version`.
- **No packages to install** — the tool uses only the Python standard library.
- For a real scan: a **GitHub token** (see scopes below). Not needed for `--mock`.

## 2. Token scopes (least privilege)

Use the **smallest, shortest-lived, read-only** token that works. The tool never
writes, so no write scope is ever required.

- **Public org (e.g. `astral-sh`), not an admin:** a token with **public read**
  is enough. You will get *public-limited* mode — public repos and contributors,
  priorities capped at `low`, advisories shown as synthetic samples, and an
  owner-exclusion warning. A **fine-grained PAT** with read-only "Public
  repositories" access is ideal.
- **Your own org, full picture:** read-only access to **Contents/Metadata**,
  **Administration → read** (to read collaborators and org members/owners), and
  **Dependabot alerts → read**. With a classic PAT this is roughly `read:org` +
  `repo` (repo is broad — prefer a fine-grained PAT scoped to the org).

Set it in the environment (preferred) or pass `--token`:

```bash
export GITHUB_TOKEN=ghp_xxx_readonly_short_lived
```

> **Security note.** Run the live scan on your own machine. Do not paste an
> org-admin or security token into any shared/sandbox environment. Rotate/revoke
> the token after use.

## 3. Running

### Offline demo (no token)

```bash
python3 -m github_hygiene --mock -o sample_output              # authorized simulation
python3 -m github_hygiene --mock --public -o sample_output_pub # public-limited simulation
```

### Real org

```bash
python3 -m github_hygiene --org YOUR_ORG --cache-dir .cache -o out
# open out/dashboard.html
```

`--cache-dir` stores ETags so repeat runs are cheap and idempotent — always set
it for real runs. Then open the generated `dashboard.html` in any browser
(`xdg-open` / `open` / `start`).

### Optional plain-English summary (off by default)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python3 -m github_hygiene --org YOUR_ORG --ai-summary -o out
```

Adds one honest paragraph to the dashboard. Sends only aggregate stats, fails
soft if the key/API is unavailable, and never affects the numbers. Details in
`docs/AI_USAGE.md`.

## 4. All flags

| Flag | Purpose |
|---|---|
| `--mock` | Use the built-in synthetic org (offline, no token). |
| `--public` | With `--mock`, simulate a public org (exercise the fallback). |
| `--org NAME` | GitHub org login to scan via the real API. |
| `--token TOKEN` | GitHub token (or set `GITHUB_TOKEN`). Read-only. |
| `--lookback-days N` | Activity window (default 180). |
| `--now ISO8601` | Override "now" for reproducible runs (defaults to fixture date under `--mock`). |
| `--cache-dir DIR` | ETag cache dir for cheap, idempotent re-runs (real API). |
| `--verbose` | Print each API call. |
| `-o, --output-dir DIR` | Where to write outputs (default `sample_output`). |
| `--ai-summary` | Add the optional LLM risk summary (needs a key). |
| `--ai-key KEY` | Anthropic key (or set `ANTHROPIC_API_KEY`). |
| `--ai-model NAME` | Anthropic model (default `claude-3-5-haiku-latest`). |

## 5. Scheduling

### Option A — cron (simplest)

```cron
# every Monday 06:00, scan and refresh the dashboard
0 6 * * 1  cd /opt/github-hygiene && GITHUB_TOKEN=$(cat /etc/gh/token) \
           python3 -m github_hygiene --org YOUR_ORG --cache-dir .cache -o /var/www/hygiene >> /var/log/hygiene.log 2>&1
```

### Option B — n8n (conditional alerting + delivery)

Import `n8n/github_hygiene_workflow.json`. It runs the scan on a schedule, parses
`report.json`, and **emails the security lead only when there's something to act
on** (open critical/high advisories or a high-priority access suggestion),
attaching the dashboard. Setup and the honest trade-offs are in
`n8n/n8n_notes.md`. The security logic stays in the audited Python core; n8n only
schedules and delivers.

## 6. Rate limits & large orgs

The client budgets the primary rate limit (pausing before exhaustion), honours
secondary-limit `Retry-After`, and caps per-repo pagination. On a **100+ repo
org** it runs serially and safely — it just takes longer and leans on the ETag
cache. See `docs/DESIGN.md` for the GraphQL + parallelism changes that make it
fast at that scale.

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `provide --org NAME or --mock` | No data source given. Add one. |
| Runs in `public-limited` unexpectedly | Token missing or lacks org/admin read. Advisories will be synthetic; owner exclusion can't be guaranteed. |
| "Could not read the org owner list" warning | Expected without org membership/admin — verify suggestions against real owners before acting. |
| Advisories look synthetic (`MOCK` badges) | Dependabot alerts API not readable with this token — grant Dependabot-alerts read, or accept public-limited. |
| Slow on a big org | Normal; set `--cache-dir` so subsequent runs reuse `304`s. |
| AI summary didn't appear | Off unless `--ai-summary` + a valid key; it fails soft by design. |

## 8. Verifying idempotency yourself

```bash
python3 -m github_hygiene --mock -o a
python3 -m github_hygiene --mock -o b
diff a/report.json b/report.json && echo "identical"
# or compare the SHA-256 block in a/run_manifest.json vs b/run_manifest.json
```
