"""
Self-contained static HTML dashboard generator.

Design goals (the brief grades "readable by a non-engineer in under 2 minutes"):
  * A risk-posture header that gives the verdict in one glance.
  * The actionable list -- suggested access reviews -- placed above the fold,
    each row carrying its own evidence.
  * Per-repo detail available but tucked into collapsible cards.

No external assets: charts are hand-rendered as inline SVG/CSS bars and all data
is embedded, so the file opens offline with no network and no dependencies.
"""

from __future__ import annotations

import html
import json
from typing import List, Optional

from .models import ScanResult
from .report import compute_summary, to_dict
from .config import SEVERITY_ORDER

SEV_COLOR = {"critical": "#B4232A", "high": "#E4572E", "medium": "#E8A33D", "low": "#6B7A8D"}
PRIO_COLOR = {"high": "#B4232A", "medium": "#E8A33D", "low": "#6B7A8D"}


def _esc(s) -> str:
    return html.escape(str(s), quote=True)


CSS = """
:root{
  --paper:#EEF2F7; --panel:#FFFFFF; --ink:#1B2733; --muted:#5B6B7B;
  --line:#DCE3EC; --indigo:#3A47B8; --indigo-soft:#EAECFB;
  --ok:#2E7D5B; --shadow:0 1px 2px rgba(20,35,55,.06),0 6px 20px rgba(20,35,55,.06);
  color-scheme:light;
}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);
  font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  font-size:15px;line-height:1.5;-webkit-font-smoothing:antialiased}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-variant-numeric:tabular-nums}
.wrap{max-width:1120px;margin:0 auto;padding:28px 22px 80px}
a{color:var(--indigo)}
h1,h2,h3{margin:0;font-weight:640;letter-spacing:-.01em}
.eyebrow{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);font-weight:700}

/* header */
.masthead{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;
  padding-bottom:16px;border-bottom:2px solid var(--ink)}
.masthead h1{font-size:26px}
.masthead .org{font-family:ui-monospace,Menlo,monospace;color:var(--indigo)}
.meta{text-align:right;color:var(--muted);font-size:12.5px}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;
  letter-spacing:.03em;border:1px solid var(--line)}
.badge.mode{background:var(--indigo-soft);color:var(--indigo);border-color:#cfd4f5}
.badge.public{background:#FFF3E6;color:#9A5B12;border-color:#f3d9b8}

/* verdict strip */
.verdict{margin:18px 0 6px;background:var(--panel);border:1px solid var(--line);border-left:5px solid var(--indigo);
  border-radius:12px;padding:16px 18px;box-shadow:var(--shadow);display:flex;gap:26px;flex-wrap:wrap;align-items:center}
.verdict .line{font-size:15.5px}
.verdict b{font-weight:680}

/* kpi cards */
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:16px 0 8px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;box-shadow:var(--shadow)}
.card .k{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);font-weight:700}
.card .v{font-size:30px;font-weight:680;margin-top:4px}
.card .v small{font-size:13px;color:var(--muted);font-weight:500}
.sevbar{display:flex;height:8px;border-radius:6px;overflow:hidden;margin-top:10px;background:#eef1f5}
.sevbar span{display:block;height:100%}
.sevkey{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px;font-size:11.5px;color:var(--muted)}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:4px;vertical-align:-1px}

@media(max-width:820px){.kpis{grid-template-columns:repeat(2,1fr)}}

section{margin-top:30px}
.sec-h{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:12px}
.sec-h h2{font-size:18px}
.sec-h .hint{color:var(--muted);font-size:12.5px}

/* most affected */
.bars{display:flex;flex-direction:column;gap:8px;background:var(--panel);border:1px solid var(--line);
  border-radius:12px;padding:16px 18px;box-shadow:var(--shadow)}
.barrow{display:grid;grid-template-columns:170px 1fr 46px;align-items:center;gap:12px;font-size:13px}
.barrow .name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.track{background:#eef1f5;border-radius:6px;height:14px;overflow:hidden}
.fill{height:100%;background:linear-gradient(90deg,#E4572E,#B4232A)}

/* tables */
.controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.controls input,.controls select{font:inherit;padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:#fff}
.controls input{min-width:220px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
  border-radius:12px;overflow:hidden;box-shadow:var(--shadow)}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13.5px}
th{background:#F7F9FC;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
tr:last-child td{border-bottom:none}
.prio{font-size:11px;font-weight:800;letter-spacing:.04em;padding:2px 8px;border-radius:6px;color:#fff;text-transform:uppercase}
.chip{display:inline-block;font-size:11px;padding:1px 7px;border-radius:6px;border:1px solid var(--line);color:var(--muted);margin:1px 3px 1px 0}
.chip.sev{color:#fff;border:none}
.who{font-weight:640}
.ev{color:var(--muted);font-size:12.5px;margin-top:3px}
.metrics{color:var(--muted);font-size:12px;white-space:nowrap}
.flagpill{font-size:11px;padding:2px 8px;border-radius:999px;background:#F1F4F8;border:1px solid var(--line);color:var(--muted);margin-right:6px}
.flagpill.warn{background:#FDECEC;border-color:#f3c9c9;color:#a12b2b}
.flagpill.good{background:#E9F6EF;border-color:#c4e6d3;color:#22694a}

/* repo accordion */
.repo{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin-bottom:12px;box-shadow:var(--shadow);overflow:hidden}
.repo>summary{cursor:pointer;list-style:none;padding:14px 18px;display:flex;align-items:center;gap:12px;justify-content:space-between}
.repo>summary::-webkit-details-marker{display:none}
.repo summary .rn{font-family:ui-monospace,Menlo,monospace;font-weight:640}
.repo summary .rmeta{color:var(--muted);font-size:12.5px}
.repo .body{padding:0 18px 16px}
.note{background:#F7F9FC;border:1px dashed var(--line);border-radius:8px;padding:8px 12px;color:var(--muted);font-size:12.5px;margin:8px 0}
.banner{background:#FFF3E6;border:1px solid #f3d9b8;color:#8a5211;border-radius:10px;padding:10px 14px;font-size:13px;margin:14px 0}
.ai{background:linear-gradient(180deg,#F3F1FB,#FFFFFF);border:1px solid #d9d5f3;border-radius:12px;padding:14px 18px;margin:14px 0;box-shadow:var(--shadow)}
.ai p{margin:6px 0 8px;font-size:14.5px;line-height:1.55}
.ai .aifoot{color:var(--muted);font-size:11.5px}
.footer{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px}
.hidden{display:none!important}
"""

JS = """
function applyFilters(){
  var q=(document.getElementById('q').value||'').toLowerCase();
  var p=document.getElementById('prio').value;
  document.querySelectorAll('#rec-body tr').forEach(function(tr){
    var okp = (p==='all')||(tr.dataset.prio===p);
    var okq = !q || tr.dataset.search.indexOf(q)>-1;
    tr.classList.toggle('hidden', !(okp&&okq));
  });
  var vis=document.querySelectorAll('#rec-body tr:not(.hidden)').length;
  document.getElementById('reccount').textContent=vis;
}
function expandAll(open){document.querySelectorAll('details.repo').forEach(function(d){d.open=open;});}
document.addEventListener('DOMContentLoaded',function(){
  var q=document.getElementById('q'), p=document.getElementById('prio');
  if(q) q.addEventListener('input',applyFilters);
  if(p) p.addEventListener('change',applyFilters);
});
"""


def _sevbar(counts: dict) -> str:
    total = sum(counts.values()) or 1
    segs = ""
    for s in SEVERITY_ORDER:
        c = counts.get(s, 0)
        if c:
            segs += f'<span style="width:{100*c/total:.1f}%;background:{SEV_COLOR[s]}"></span>'
    key = " ".join(
        f'<span><i class="dot" style="background:{SEV_COLOR[s]}"></i>{s} {counts.get(s,0)}</span>'
        for s in SEVERITY_ORDER)
    return f'<div class="sevbar">{segs}</div><div class="sevkey">{key}</div>'


def _kpis(summary: dict) -> str:
    adv = summary["advisories"]; acc = summary["access"]; tot = summary["totals"]
    oldest = adv["oldest_unresolved"]
    oldest_txt = (f'{oldest["age_days"]}<small> days · {_esc(oldest["severity"])}</small>'
                  if oldest else "—")
    prio = acc["by_priority"]
    return f"""
    <div class="kpis">
      <div class="card">
        <div class="k">Open advisories</div>
        <div class="v">{adv['total_open']}</div>
        {_sevbar(adv['open_by_severity'])}
      </div>
      <div class="card">
        <div class="k">Oldest unresolved</div>
        <div class="v mono">{oldest_txt}</div>
        <div class="sevkey">{_esc(oldest['repo']) if oldest else ''} · {_esc(oldest['package']) if oldest else ''}</div>
      </div>
      <div class="card">
        <div class="k">Repos scanned</div>
        <div class="v mono">{tot['repos']}</div>
        <div class="sevkey">{tot['analysed']} analysed · {tot['archived']} archived · {tot['forks']} forks · {tot['skipped_empty']} empty</div>
      </div>
      <div class="card">
        <div class="k">Access reviews suggested</div>
        <div class="v mono">{acc['total_suggestions']}</div>
        <div class="sevkey">
          <span><i class="dot" style="background:{PRIO_COLOR['high']}"></i>high {prio['high']}</span>
          <span><i class="dot" style="background:{PRIO_COLOR['medium']}"></i>med {prio['medium']}</span>
          <span><i class="dot" style="background:{PRIO_COLOR['low']}"></i>low {prio['low']}</span>
        </div>
      </div>
    </div>"""


def _most_affected(summary: dict) -> str:
    rows = summary["most_affected_repos"]
    if not rows:
        return ""
    top = max((r["advisory_risk_weight"] for r in rows), default=1) or 1
    body = ""
    for r in rows:
        w = r["advisory_risk_weight"]
        body += (f'<div class="barrow"><div class="name mono">{_esc(r["repo"])}</div>'
                 f'<div class="track"><div class="fill" style="width:{100*w/top:.0f}%"></div></div>'
                 f'<div class="mono" style="text-align:right">{r["open_advisories"]}</div></div>')
    return f"""
    <section>
      <div class="sec-h"><h2>Most exposed repositories</h2>
        <span class="hint">bar = severity-weighted open advisories · number = open count</span></div>
      <div class="bars">{body}</div>
    </section>"""


def _rec_rows(result: ScanResult) -> str:
    rows = []
    for rr in result.repo_reports:
        for rec in rr.recommendations:
            m = rec.metrics
            search = f'{rec.repo} {rec.login} {rec.permission} {rec.access_via}'.lower()
            reasons = "<br>".join(_esc(x) for x in rec.reasons)
            metrics = (f'{m["commits"]}c · {m["prs_opened"]}pr · '
                       f'{m["prs_merged"]}merged · {m["reviews"]}rev')
            rows.append((rec.priority, rec.score, f"""
      <tr data-prio="{rec.priority}" data-search="{_esc(search)}">
        <td><span class="prio" style="background:{PRIO_COLOR[rec.priority]}">{rec.priority}</span></td>
        <td class="mono">{_esc(rec.repo)}</td>
        <td><span class="who">{_esc(rec.login)}</span><br>
            <span class="chip">{_esc(rec.permission)}</span>
            <span class="chip">{_esc(rec.access_via.replace('_',' '))}</span></td>
        <td class="metrics">{metrics}<br>last activity: {rec.days_since_activity if rec.days_since_activity is not None else '—'}d ago</td>
        <td><div class="ev">{reasons}</div></td>
      </tr>"""))
    prio_rank = {"high": 0, "medium": 1, "low": 2}
    rows.sort(key=lambda t: (prio_rank[t[0]], t[1]))
    return "".join(r[2] for r in rows) or (
        '<tr><td colspan="5" style="color:var(--muted)">No access-removal suggestions — '
        'every member with access shows sufficient recent contribution.</td></tr>')


def _repo_cards(result: ScanResult) -> str:
    cards = []
    for rr in result.repo_reports:
        flag_html = ""
        for f in rr.flags:
            cls = "flagpill"
            if f in ("archived", "empty", "single_maintainer"):
                cls += " warn" if f != "single_maintainer" else " warn"
            flag_html += f'<span class="{cls}">{_esc(f.replace("_"," "))}</span>'
        open_adv = sum(1 for a in rr.advisories if a.state == "open")

        # advisory chips
        adv_html = ""
        for a in sorted(rr.advisories, key=lambda x: SEVERITY_ORDER.index(x.severity) if x.severity in SEVERITY_ORDER else 9):
            mock = ' <span class="chip">MOCK</span>' if a.is_mock else ""
            adv_html += (f'<div style="margin:4px 0"><span class="chip sev" style="background:{SEV_COLOR.get(a.severity,"#888")}">'
                         f'{_esc(a.severity)}</span> <span class="mono">{_esc(a.package)}</span> '
                         f'<span class="chip">{_esc(a.state)}</span> '
                         f'<span class="metrics">{a.age_days}d old</span>{mock} — {_esc(a.summary)}</div>')
        if not rr.advisories:
            adv_html = '<div class="metrics">No advisories.</div>'

        # member table
        mrows = ""
        for m in rr.contributions:
            tags = ""
            if m.is_owner: tags += '<span class="flagpill good">owner</span>'
            if m.is_bot: tags += '<span class="flagpill">bot</span>'
            mrows += (f'<tr><td class="who">{_esc(m.login)}{tags}</td>'
                      f'<td><span class="chip">{_esc(m.permission)}</span></td>'
                      f'<td class="metrics">{_esc(m.access_via.replace("_"," "))}</td>'
                      f'<td class="mono">{m.metrics.commits}</td><td class="mono">{m.metrics.prs_opened}</td>'
                      f'<td class="mono">{m.metrics.prs_merged}</td><td class="mono">{m.metrics.reviews}</td>'
                      f'<td class="mono">{m.score:.1f}</td><td class="mono">{m.relative_score:.0f}%</td>'
                      f'<td class="mono">{m.days_since_activity if m.days_since_activity is not None else "—"}</td></tr>')
        notes = "".join(f'<div class="note">{_esc(n)}</div>' for n in rr.notes)
        member_block = (f"""<table><thead><tr>
              <th>Member</th><th>Perm</th><th>Access</th><th>Commits</th><th>PRs</th>
              <th>Merged</th><th>Reviews</th><th>Score</th><th>Rel</th><th>Idle d</th>
            </tr></thead><tbody>{mrows}</tbody></table>""" if mrows else "")

        cards.append(f"""
      <details class="repo">
        <summary>
          <span><span class="rn">{_esc(rr.repo.name)}</span> {flag_html}</span>
          <span class="rmeta">{open_adv} open advisories · {len(rr.recommendations)} suggestions · {len(rr.contributions)} members</span>
        </summary>
        <div class="body">
          {notes}
          <div class="eyebrow" style="margin:12px 0 6px">Advisories</div>
          {adv_html}
          <div class="eyebrow" style="margin:14px 0 6px">Members &amp; contribution (lookback window)</div>
          {member_block}
        </div>
      </details>""")
    return "".join(cards)


def render(result: ScanResult, ai_summary: Optional[str] = None) -> str:
    summary = compute_summary(result)
    adv = summary["advisories"]; acc = summary["access"]
    mode = result.mode
    mode_badge = ('<span class="badge mode">AUTHORIZED SCAN</span>'
                  if mode == "authorized" else
                  '<span class="badge public">PUBLIC-LIMITED SCAN</span>')

    verdict = (f'<b>{adv["open_by_severity"]["critical"]}</b> critical and '
               f'<b>{adv["open_by_severity"]["high"]}</b> high advisories open across '
               f'<b>{summary["totals"]["analysed"]}</b> active repos; '
               f'<b>{acc["total_suggestions"]}</b> access grants flagged for review '
               f'(<b>{acc["by_priority"]["high"]}</b> high priority). Owners are never flagged.')

    banners = ""
    if adv["contains_mock"]:
        banners += ('<div class="banner"><b>Note:</b> security-advisory data for this run is '
                    '<b>synthetic (clearly labelled “MOCK”)</b> because the Dependabot/security API '
                    'requires org-admin access not available for a public org. Contribution and access '
                    'data are real. See the write-up for exactly where mocking applies.</div>')
    for w in result.warnings:
        banners += f'<div class="banner">{_esc(w)}</div>'

    data_json = json.dumps(to_dict(result))

    ai_block = ""
    if ai_summary:
        ai_block = (
            '<div class="ai"><div class="eyebrow">AI risk summary '
            '<span class="chip">generated</span></div>'
            f'<p>{_esc(ai_summary)}</p>'
            '<div class="aifoot">Generated locally via the Anthropic API from the '
            'aggregate scan statistics. Advisory. Verify against the tables below.</div></div>')

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access &amp; Advisory Hygiene — {_esc(result.org)}</title>
<style>{CSS}</style></head>
<body><div class="wrap">
  <header class="masthead">
    <div>
      <div class="eyebrow">GitHub org security &amp; access-hygiene review</div>
      <h1><span class="org">{_esc(result.org)}</span></h1>
    </div>
    <div class="meta">
      {mode_badge}<br>
      generated {_esc(result.generated_at)}<br>
      lookback {result.config.get('lookback_days','?')} days · {result.api_calls} API calls
    </div>
  </header>

  <div class="verdict"><div class="line">{verdict}</div></div>
  {ai_block}
  {banners}

  {_kpis(summary)}
  {_most_affected(summary)}

  <section>
    <div class="sec-h">
      <h2>Suggested access reviews <span class="hint">— human review only; nothing is revoked automatically</span></h2>
      <span class="hint"><b id="reccount">{acc['total_suggestions']}</b> shown</span>
    </div>
    <div class="controls">
      <input id="q" placeholder="Filter by repo, member, permission…">
      <select id="prio">
        <option value="all">All priorities</option>
        <option value="high">High only</option>
        <option value="medium">Medium only</option>
        <option value="low">Low only</option>
      </select>
    </div>
    <table><thead><tr>
      <th>Priority</th><th>Repo</th><th>Member</th><th>Recent activity</th><th>Why flagged</th>
    </tr></thead><tbody id="rec-body">{_rec_rows(result)}</tbody></table>
  </section>

  <section>
    <div class="sec-h"><h2>Per-repository detail</h2>
      <span class="hint"><a href="#" onclick="expandAll(true);return false">expand all</a> ·
      <a href="#" onclick="expandAll(false);return false">collapse all</a></span></div>
    {_repo_cards(result)}
  </section>

  <div class="footer">
    Generated by the GitHub org hygiene scanner (zero-dependency Python).
    Access-removal items are <b>suggestions for human review</b>, never automatic actions.
    Data mode: <b>{_esc(mode)}</b>.
  </div>
</div>
<script id="report-data" type="application/json">{data_json}</script>
<script>{JS}</script>
</body></html>"""
