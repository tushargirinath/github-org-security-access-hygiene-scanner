# AI / LLM usage disclosure

The brief asks for a candid account of how AI/LLM tools were used. There are two
separate things to disclose: the optional LLM **feature inside the tool**, and
how I used **AI assistance while building** the project.

## 1. The optional LLM feature in the product

The scanner can add a short plain-English risk summary to the top of the
dashboard. It is deliberately conservative:

- **Off by default.** It only runs with the explicit `--ai-summary` flag *and* a
  key present (`ANTHROPIC_API_KEY` or `--ai-key`). Nothing calls out to any model
  otherwise — every default run, and every test, is fully offline.
- **It never sees secrets, tokens, or source code.** The only thing sent is the
  already-computed **aggregate summary** (counts of open advisories by severity,
  the oldest-unresolved age, and a small, already-derived list of suggestion
  priorities). No repository contents, no member emails, no token — see
  `build_prompt()` in `github_hygiene/llm.py` for exactly what is assembled.
- **It fails soft.** No key, network error, HTTP error, or malformed response →
  the function returns `None` and the dashboard renders exactly as it would
  without the flag. The LLM is never on the critical path.
- **It has no authority.** The summary is descriptive text only; it cannot change
  a score, add or remove a suggestion, or take any action. All access items
  remain human-review suggestions regardless of what the summary says.
- **Model & transport.** Anthropic Messages API over stdlib `urllib`
  (default model `claude-3-5-haiku-latest`), so the feature adds **no third-party
  dependency** — consistent with the rest of the tool.

Why include it at all: a security lead skimming for two minutes benefits from one
honest sentence of context, but the numeric report must never *depend* on a
model. Hence: additive, gated, and fail-soft.

## 2. How I used AI while building this

I used an AI coding assistant as a pair-programmer, and I want to be transparent
about where and how:

- **Where it helped:** scaffolding boilerplate (argparse wiring, CSV/JSON writers,
  the HTML/CSS of the dashboard), drafting docstrings and these write-ups, and
  rubber-ducking the scoring design (e.g. surfacing that my first priority model
  left the `low` tier unreachable).
- **What I owned and verified myself:** the scoring model and its weights, the
  three-gate removal condition, the blast-radius priority tiers, and every edge
  case were **my** design decisions — each is justified in `docs/DESIGN.md` and
  pinned down by unit tests I reviewed. I ran the full suite (17 tests) and the
  sample scans myself and checked the outputs against expectations (e.g. the
  reviewer-with-few-commits is *not* flagged; owners and the sole maintainer are
  excluded).
- **Judgement, not autopilot.** I treated AI output as a draft to be checked, not
  as truth. The one place I found a real logic smell (all suggestions collapsing
  to one priority), I redesigned the model rather than papering over it, and added
  tests to lock the fix.

In short: AI accelerated the typing; the security judgement, the verification, and
the decisions behind the numbers are mine.
