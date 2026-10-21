# n8n workflow — setup and honest notes on the tooling

This folder contains `github_hygiene_workflow.json`, an importable n8n workflow
that operationalises the scanner: **run on a schedule → parse the report →
alert a human only when something needs attention → attach the dashboard.**

It is deliberately a *thin* orchestration layer. The judgment (scoring, access
logic, rate-limit handling, pagination) lives in the audited, unit-tested Python
core; n8n handles scheduling, notification, and delivery — the things it is
genuinely good at. This is the "hybrid" design, and the reasons for it are below.

## What the workflow does

```
Every Monday 06:00  →  Config  →  Run scan (Python core)  →  Read report.json
   →  Summarise & decide (Code)  →  Anything to report? (IF)
        ├─ yes →  Read dashboard.html  →  Email the security lead (attach dashboard)
        └─ no  →  All clear (no-op)
```

* **Config** — one place to set the org, the output directory, and the notify
  address. No secrets here.
* **Run scan** — an Execute Command node that runs
  `python -m github_hygiene --org <org> --token $GITHUB_TOKEN --cache-dir … -o <out>`.
  The token comes from the host environment, not the workflow.
* **Summarise & decide** — a Code node that parses `report.json` and only raises
  an alert when there are open critical/high advisories or high-priority access
  suggestions, so the channel does not become noise.
* **Email** — sends the plain-text summary and attaches the self-contained
  `dashboard.html`. Swap this node for Slack/Teams/PagerDuty as needed.

## Setup

1. **Host prerequisites.** The n8n host (or a custom n8n Docker image) must have
   Python 3.9+ and the `github_hygiene` package available on `PYTHONPATH`. No
   third-party Python packages are required — the tool is standard-library only.
2. **Credentials.** Set `GITHUB_TOKEN` in the n8n host environment (or wire an
   n8n credential and reference it). Use a **read-only, short-lived** token.
   Configure SMTP credentials in n8n for the email node.
3. **Import.** n8n → *Workflows* → *Import from File* → select
   `github_hygiene_workflow.json`.
4. **Edit the Config node** — set your `org`, `outputDir`, and `notifyEmail`.
5. **Persisted volume.** Point `outputDir` at a mounted volume so the
   `--cache-dir` (ETag cache) survives between runs — that is what keeps repeat
   runs cheap and idempotent (unchanged resources return `304` and don't consume
   the primary rate limit).
6. **Test run**, then **Activate** to enable the weekly schedule.

## Honest challenges hit with the automation tooling (n8n)

The brief asks for a candid account. These are the real ones:

* **Secrets in nodes.** It is easy to accidentally hard-code a token into an
  Execute Command string. I kept the token in the host environment
  (`$GITHUB_TOKEN`) and reference it, so the exported workflow JSON contains no
  secret. This is a genuine footgun in n8n and worth calling out.
* **Python availability on the n8n host.** The stock n8n Docker image has no
  Python. In production you either build a small custom image (n8n + Python +
  the package) or run the scanner as a sidecar/service the workflow calls over
  HTTP. I chose Execute Command for the take-home because it is the clearest to
  read; the HTTP-service variant is the more robust production choice.
* **Binary vs. JSON handling.** n8n treats file reads as *binary* items. Parsing
  `report.json` needed a Code node that pulls the binary buffer
  (`getBinaryDataBuffer`) and `JSON.parse`s it; passing the dashboard to the
  email meant reading it into a named binary property and attaching by that name.
  This is a common n8n stumbling block (people expect the file node to hand back
  parsed JSON).
* **Why not implement the whole thing in n8n?** I tried framing it as pure-n8n
  HTTP-Request nodes and stopped: correctly paginating the REST API (Link
  headers), budgeting the primary rate limit, honouring secondary-limit
  `Retry-After`, and doing ETag conditional requests would take a large, brittle
  web of Loop/IF/Wait nodes that is hard to test and review. Those concerns
  belong in code with unit tests — exactly what a security team needs to audit.
  Hence hybrid: n8n for scheduling and delivery, Python for the logic.
* **Determinism / testing.** n8n workflows are awkward to unit-test. Keeping all
  judgment in the Python core means the gradable logic is covered by
  `tests/test_scoring.py`, and the workflow stays thin enough to verify by
  inspection.

## Alternative: no n8n

Everything the workflow does can be reproduced with a one-line cron entry
calling the same command — see `docs/RUNBOOK.md`. n8n adds the nice-to-haves
(conditional alerting, easy channel swaps, run history, retries) without owning
any of the security logic.
