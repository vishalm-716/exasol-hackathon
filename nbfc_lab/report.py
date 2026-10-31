"""Build a single self-contained HTML dashboard (no internet needed to open it)."""
from __future__ import annotations

import html
import json

import numpy as np
import pandas as pd

E = html.escape

CSS = """
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;
--grid:#e1e0d9;--axis:#c3c2b7;--ring:rgba(11,11,11,.10);--s1:#2a78d6;--s2:#eb6834;--good:#0ca30c;
--warn:#fab219;--crit:#d03b3b;--goodtxt:#006300;--seq1:#cde2fb;--seq2:#86b6ef;--seq3:#3987e5;--seq4:#1c5cab;--seq5:#0d366b;
--div-neg:#2a78d6;--div-pos:#e34948;--hi1:#0b0b0b;--hi2:#0b0b0b;--hi3:#fcfcfb;--hi4:#fcfcfb;--hi5:#fcfcfb}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;
--ink:#f0efec;--ink2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);--s1:#3987e5;
--s2:#d95926;--goodtxt:#0ca30c;--seq1:#184f95;--seq2:#1c5cab;--seq3:#2a78d6;--seq4:#5598e7;--seq5:#9ec5f4;--div-neg:#3987e5;--div-pos:#e66767;--hi1:#f0efec;--hi2:#f0efec;--hi3:#f0efec;--hi4:#0b0b0b;--hi5:#0b0b0b}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#898781;
--grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);--s1:#3987e5;--s2:#d95926;--goodtxt:#0ca30c;--seq1:#184f95;
--seq2:#1c5cab;--seq3:#2a78d6;--seq4:#5598e7;--seq5:#9ec5f4;--div-neg:#3987e5;--div-pos:#e66767;--hi1:#f0efec;--hi2:#f0efec;--hi3:#f0efec;--hi4:#0b0b0b;--hi5:#0b0b0b}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:24px 16px 64px}
header h1{font-size:26px;margin:0 0 4px;letter-spacing:-.01em}header p{margin:0;color:var(--ink2)}
.banner{margin:16px 0;padding:10px 14px;border-radius:10px;background:var(--surface);box-shadow:0 0 0 1px var(--ring);color:var(--ink2);font-size:13px}
nav{display:flex;gap:6px;margin:20px 0;flex-wrap:wrap}nav button{font:inherit;padding:8px 14px;border-radius:999px;border:0;
background:var(--surface);color:var(--ink2);box-shadow:0 0 0 1px var(--ring);cursor:pointer}
nav button[aria-selected="true"]{background:var(--ink);color:var(--page)}
section.tab{display:none}section.tab.on{display:block}
h2{font-size:20px;margin:32px 0 6px}h3{font-size:16px;margin:24px 0 6px}.lead{color:var(--ink2);margin:0 0 14px;max-width:780px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.tile{background:var(--surface);border-radius:12px;padding:14px 16px;box-shadow:0 0 0 1px var(--ring)}
.tile .k{font-size:12px;color:var(--ink2);text-transform:uppercase;letter-spacing:.04em}
.tile .v{font-size:28px;font-weight:600;margin-top:2px}.tile .s{font-size:13px;color:var(--muted)}
.card{background:var(--surface);border-radius:12px;padding:16px;box-shadow:0 0 0 1px var(--ring);margin-top:12px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13.5px}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--grid);vertical-align:top}
th{color:var(--ink2);font-weight:600}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:600;padding:2px 8px;border-radius:999px;box-shadow:0 0 0 1px var(--ring)}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:13px;color:var(--ink2);margin:6px 0}
.legend span{display:inline-flex;align-items:center;gap:6px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:760px){.grid2{grid-template-columns:1fr}}
svg text{fill:var(--muted);font-size:11px;font-family:inherit}svg .lbl{fill:var(--ink2);font-size:12px}
.tip{position:fixed;pointer-events:none;background:var(--ink);color:var(--page);font-size:12px;padding:6px 8px;border-radius:6px;opacity:0;transition:opacity .1s;max-width:280px;z-index:9}
.hm td{text-align:center;font-size:12.5px}.hm td.cell{border:2px solid var(--surface);border-radius:6px}
.note{font-size:13px;color:var(--ink2)}code{font-size:12.5px}
footer{margin-top:40px;font-size:12.5px;color:var(--muted)}
"""

JS = """
const tip=document.createElement('div');tip.className='tip';document.body.appendChild(tip);
document.addEventListener('mousemove',e=>{const t=e.target.closest('[data-tip]');if(!t){tip.style.opacity=0;return}
tip.textContent=t.dataset.tip;tip.style.opacity=1;tip.style.left=Math.min(e.clientX+12,innerWidth-290)+'px';tip.style.top=(e.clientY+12)+'px'});
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{document.querySelectorAll('nav button').forEach(x=>x.setAttribute('aria-selected','false'));
b.setAttribute('aria-selected','true');document.querySelectorAll('section.tab').forEach(s=>s.classList.toggle('on',s.id===b.dataset.t))});
"""


def _tile(k, v, s=""):
    return f'<div class="tile"><div class="k">{E(k)}</div><div class="v">{E(str(v))}</div><div class="s">{E(s)}</div></div>'


def _table(df: pd.DataFrame, num_cols=(), fmt=None) -> str:
    fmt = fmt or {}
    head = "".join(f'<th class="{"n" if c in num_cols else ""}">{E(str(c))}</th>' for c in df.columns)
    rows = []
    for _, r in df.iterrows():
        cells = []
        for c in df.columns:
            v = r[c]
            txt = fmt[c](v) if c in fmt else (f"{v:,.4g}" if isinstance(v, (float, np.floating)) else str(v))
            cells.append(f'<td class="{"n" if c in num_cols else ""}">{txt if c in fmt else E(txt)}</td>')
        rows.append("<tr>" + "".join(cells) + "</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def _status_pill(action):
    color = {"BLOCK": "var(--crit)", "HOLD": "var(--warn)", "ALLOW": "var(--good)"}[action]
    icon = {"BLOCK": "&#10005;", "HOLD": "&#9208;", "ALLOW": "&#10003;"}[action]
    return f'<span class="pill"><span class="dot" style="background:{color}"></span>{icon} {action}</span>'


SCENARIO_NAMES = {"initial_access": "1. Exploit deprecated upload API", "recon": "2. Recon of payment APIs via web shell",
                  "direct_disburse_dummy_ref": "3. Direct payouts with dummy references",
                  "beneficiary_swap": "4. Real loans, beneficiary swapped to mule"}


def _secs(v):
    return "in the same second as" if v < 1 else f"{v:.0f} seconds after"


# ------------------------------------------------------------------ charts
def attack_timeline(out: pd.DataFrame, res: dict) -> str:
    atk = out[out.label == "attack"]
    t0, t1 = atk.ts.min() - 60, atk.ts.max() + 60
    legit = out[(out.label == "legit") & (out.ts.between(t0, t1))]
    lanes = [("initial_access", "Exploit deprecated upload API"), ("recon", "Recon via web shell"),
             ("direct_disburse_dummy_ref", "Direct payout, dummy refs"), ("beneficiary_swap", "Beneficiary swap to mule"),
             ("normal", "Legitimate traffic")]
    W, L, rowh, T = 1000, 210, 34, 10
    H = T + rowh * len(lanes) + 56
    pw = W - L - 16
    X = lambda ts: L + pw * (ts - t0) / (t1 - t0)
    col = {"BLOCK": "var(--crit)", "HOLD": "var(--warn)", "ALLOW": "var(--good)"}
    o = [f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" aria-label="Attack timeline">']
    m = int(np.ceil(t0 / 120) * 120)
    while m < t1:
        x = X(m)
        s = int(m % 86400)
        o.append(f'<line x1="{x:.1f}" x2="{x:.1f}" y1="{T}" y2="{T+rowh*len(lanes)}" stroke="var(--grid)"/>'
                 f'<text x="{x:.1f}" y="{T+rowh*len(lanes)+16}" text-anchor="middle">{s//3600:02d}:{(s%3600)//60:02d}</text>')
        m += 120
    for i, (sc, name) in enumerate(lanes):
        y = T + i * rowh + rowh / 2
        o.append(f'<text class="lbl" x="{L-10}" y="{y+4}" text-anchor="end">{E(name)}</text>')
        evs = legit if sc == "normal" else atk[atk.scenario == sc]
        for _, e in evs.iterrows():
            amt = f", ₹{e.amount/1e5:,.1f} lakh" if e.amount else ""
            rules = ", ".join(e.rules) if e.rules else "no rule hit"
            o.append(f'<circle cx="{X(e.ts):.1f}" cy="{y + (np.random.default_rng(int(e.seq_no)).uniform(-6, 6)):.1f}" r="4" '
                     f'fill="{col[e.action]}" stroke="var(--surface)" stroke-width="1.5" '
                     f'data-tip="{E(e.api)} · {e.action}{amt} · {E(rules)}"/>')
    for j, (label, key) in enumerate([("First alert", "first_alert"), ("Credential revoked", "incident_opened")]):
        hh, mm, ss = map(int, res["attack_window"][key].split(":"))
        ts = int(atk.ts.min() // 86400) * 86400 + hh * 3600 + mm * 60 + ss
        x = X(ts)
        o.append(f'<line x1="{x:.1f}" x2="{x:.1f}" y1="{T}" y2="{T+rowh*len(lanes)}" stroke="var(--ink2)" stroke-dasharray="3 3"/>'
                 f'<text class="lbl" x="{x+5:.1f}" y="{T+rowh*len(lanes)+30+14*j}">{label} {res["attack_window"][key]}</text>')
    o.append("</svg>")
    legend = ('<div class="legend"><span><span class="dot" style="background:var(--crit)"></span>&#10005; Blocked</span>'
              '<span><span class="dot" style="background:var(--warn)"></span>&#9208; Held for maker-checker</span>'
              '<span><span class="dot" style="background:var(--good)"></span>&#10003; Allowed</span></div>')
    return legend + "".join(o)


# ------------------------------------------------------------------ page
def build(cyber: dict, path: str, generated: str):
    r = cyber["result"]

    rules = r["rules"].rename(columns={"rule": "Control", "what_it_checks": "What it checks",
                                       "advisory_action": "CIAD-2026-0046 recommended action",
                                       "attack_events_caught": "Attack events caught",
                                       "legit_events_flagged": "Legit events flagged"})
    layers = pd.DataFrame([{"Configuration": k, "Fraud payouts stopped": f"{v['attack_disbursals_stopped_pct']}%",
                            "Amount stopped (₹ Cr)": v["amount_stopped_cr"],
                            "Legit payouts held/blocked": f"{v['legit_disbursals_held_or_blocked_pct']}%"}
                           for k, v in r["layers"].items()])
    scen = r["scenarios"].assign(scenario=lambda d: d.scenario.map(SCENARIO_NAMES)).rename(columns={"scenario": "Attack stage", "events": "API calls", "stopped": "Stopped",
                                          "amount_attempted_cr": "Amount attempted (₹ Cr)", "first_seen": "First seen"})
    li = r["log_integrity"]
    inc = r["incidents"][0] if r["incidents"] else None

    blueprint = pd.DataFrame([
        ("§5 Principle 1 · Assume Breach", "Engine assumes the attacker is already inside, on a whitelisted server; source allow-listing alone is not trusted"),
        ("§5 Principle 2 · Zero Trust", "Every payout must prove KYC, sanction and beneficiary stages with a signed stage token; static tokens are blocked"),
        ("§5 Principle 8 · Security Automation with Human Oversight", "Hard-rule breaches auto-block; AI anomalies are HELD for a human maker-checker, not auto-rejected"),
        ("§8 item 4 · Behavioural Analytics and Anomaly Detection", "Per-client Isolation Forest on velocity, cadence regularity, bank fan-out, amount and token age"),
        ("§8 item 10 · Security Automation", "Circuit breaker revokes the credential and opens an incident within seconds"),
        ("§10 · Incident Response", "Incident record with auto-actions; logs hash-chained so deletion is provable"),
        ("§13 Phase II (8–30 days)", "\"Implement behaviour-based detection\" and API security assessment — this repo is a reference build for that step"),
    ], columns=["CERT-In Blueprint (v1.0, 25.05.2026)", "How this repo applies it"])

    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NBFC AI Risk Lab</title><style>{CSS}</style></head><body><div class="wrap">
<header><h1>NBFC AI Risk Lab</h1><p>Real-time, explainable AI defence against disbursement-API fraud at NBFCs.</p></header>
<div class="banner">All data is synthetic. Figures show how the method behaves on simulated data; they are not performance claims for any real lender. Not a validated production model.</div>
<nav role="tablist"><button data-t="cyber" aria-selected="true">Disbursement API defence</button>
<button data-t="gov" aria-selected="false">Governance</button></nav>

<section class="tab on" id="cyber">
<h2>Disbursement API defence: CERT-In Advisory CIAD-2026-0046</h2>
<p class="lead">In a replay of the attack pattern CERT-In described on 9 Oct 2026, the engine stopped all {r['money']['attack_disbursals']} fraudulent payouts (₹{r['money']['attempted_cr']} Cr). It raised its first alert {_secs(r['attack_window']['seconds_to_first_alert'])} the first malicious call and revoked the stolen credential at {r['attack_window']['incident_opened']}, before the first fraudulent payout was even attempted at {r['attack_window']['first_fraudulent_payout_attempt']}.</p>
<div class="tiles">{_tile("Fraud attempted", f"₹{r['money']['attempted_cr']} Cr", f"{r['money']['attack_disbursals']} payout calls")}
{_tile("Fraud paid out", f"₹{r['money']['paid_out_cr']:g} Cr", "with the engine")}
{_tile("Without the engine", f"₹{r['without_engine']['loss_cr']} Cr", "lost; found at end-of-day recon")}
{_tile("Legit payouts held", f"{r['legit']['held_for_review']} of {r['legit']['disbursals']}", f"₹{r['legit']['held_amount_cr']} Cr to maker-checker; 0 blocked")}</div>
<div class="card"><h3 style="margin-top:0">Attack timeline, live day</h3>{attack_timeline(cyber['out'], r)}
<p class="note">Attacker calls come from the entity's own whitelisted app server, so IP allow-listing alone would not stop them.</p></div>
<h3>Which layer stops what</h3>
<p class="lead">The AI layer alone misses the first few payouts, before a velocity pattern exists, and the slow beneficiary swaps that look like normal traffic. Cryptographic stage binding catches those. AI adds early behavioural warning; it does not replace hard controls.</p>
<div class="card">{_table(layers)}</div>
<h3>Attack stages</h3><div class="card">{_table(scen, num_cols=('API calls','Stopped','Amount attempted (₹ Cr)'))}</div>
<h3>Controls mapped to the advisory</h3><div class="card">{_table(rules, num_cols=('Attack events caught','Legit events flagged'))}</div>
<h3>Log tampering detected</h3>
<p class="lead">The attacker deleted {li['missing_records']} log lines after the campaign. The hash chain exposes {len(li['gaps'])} gaps and {li['broken_links']} broken links out of {li['original_records']:,} records, so deletion is provable.</p>
<h3>Incident opened automatically</h3><div class="card">{_table(pd.DataFrame([{'Credential': inc['token_id'], 'Client': inc['client_id'], 'Source': inc['src_ip'], 'Trigger': inc['trigger'], 'Automatic actions': '; '.join(inc['auto_actions'])}])) if inc else 'None'}
<p class="note">Next step for a human: report to CERT-In / CSIRT-Fin with relevant logs, as the advisory directs. Confirm the current reporting timeline in the CERT-In directions.</p></div>
<h3>Alignment with the CERT-In Blueprint on AI-assisted exploitation</h3><div class="card">{_table(blueprint)}</div>
<p class="note">Engine latency on this machine: median {r['latency_ms']['p50']} ms, 99th percentile {r['latency_ms']['p99']} ms per event over {r['latency_ms']['events']:,} events. This is a Python reference build, not a production benchmark.</p>
</section>

<section class="tab" id="gov">
<h2>Governance built in</h2>
<p class="lead">The engine is built to answer the questions a board, auditor or regulator will ask.</p>
<div class="card"><table><thead><tr><th>Question</th><th>How the lab answers it</th></tr></thead><tbody>
<tr><td>Who decides?</td><td>Only deterministic hard-control breaches block automatically. AI anomalies are HELD for a human maker-checker.</td></tr>
<tr><td>Can we explain a decision?</td><td>Every BLOCK and HOLD carries the named rules that fired, each mapped to a CERT-In recommended action.</td></tr>
<tr><td>What if the AI is wrong?</td><td>Hard controls stand on their own; the AI layer only adds early warning. A false positive delays a payout for review; it never rejects one.</td></tr>
<tr><td>Will it still work next quarter?</td><td>Per-client behavioural baselines are retrained on recent clean traffic; thresholds are reviewed when the HOLD rate drifts.</td></tr>
<tr><td>Can logs be trusted?</td><td>Hash-chained audit trail; any deletion or edit breaks the chain.</td></tr>
</tbody></table></div>
<p class="note">The model card and the control-mapping document are in the repo's <code>docs/</code> folder.</p>
</section>
<footer>NBFC AI Risk Lab · Apache-2.0 · Synthetic data only. Generated {E(generated)}.</footer>
</div><script>{JS}</script></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
