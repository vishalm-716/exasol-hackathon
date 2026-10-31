"""Measure what the engine achieved on the simulated attack."""
from __future__ import annotations

from collections import Counter

import pandas as pd

from .engine import RULES, HashChainLog, _ablate


def _fmt_clock(ts: float) -> str:
    s = int(ts % 86400)
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


def evaluate(out: pd.DataFrame, eng, deleted: set) -> dict:
    disb = out[out.api == "disburse"]
    atk = out[out.label == "attack"]
    atk_disb = disb[disb.label == "attack"]
    legit_disb = disb[disb.label == "legit"]

    stopped = atk_disb[atk_disb.action != "ALLOW"]
    first_atk = atk.ts.min()
    first_alert = atk[atk.action != "ALLOW"].ts.min()
    first_money = atk_disb.ts.min()

    layers = {}
    for name, (r, m) in {"Hard controls only": (True, False), "Behavioural AI only": (False, True),
                         "Both layers": (True, True)}.items():
        o = _ablate(out, r, m)
        d = o[o.api == "disburse"]
        a, l_ = d[d.label == "attack"], d[d.label == "legit"]
        layers[name] = {
            "attack_disbursals_stopped_pct": round(100 * (a.action != "ALLOW").mean(), 1),
            "amount_stopped_cr": round(a.loc[a.action != "ALLOW", "amount"].sum() / 1e7, 2),
            "legit_disbursals_held_or_blocked_pct": round(100 * (l_.action != "ALLOW").mean(), 2),
        }

    scen = (
        atk.groupby("scenario")
        .agg(events=("action", "size"),
             stopped=("action", lambda s: int((s != "ALLOW").sum())),
             amount_attempted_cr=("amount", lambda s: round(s.sum() / 1e7, 2)),
             first_seen=("ts", "min"))
        .reset_index()
        .sort_values("first_seen")
    )
    scen["first_seen"] = scen["first_seen"].map(_fmt_clock)

    rule_hits = Counter(r for rs in atk.rules for r in rs)
    rule_table = pd.DataFrame(
        [{"rule": k, "what_it_checks": RULES[k][0], "advisory_action": RULES[k][1],
          "attack_events_caught": rule_hits.get(k, 0),
          "legit_events_flagged": int(sum(k in rs for rs in out[out.label == "legit"].rules))}
         for k in RULES]
    )

    # Tamper evidence: attacker deletes log lines from the local copy.
    tampered = [r for r in eng.log.records if r["seq_no"] not in deleted]
    integrity = HashChainLog.verify(tampered)
    integrity["original_records"] = len(eng.log.records)

    # Counterfactual: no engine. Every attacker disbursal is paid, and is only found
    # at end-of-day reconciliation (bank statement vs loan records).
    no_ctrl_loss = atk_disb.amount.sum()
    recon_breaks = int(atk_disb.loan_ref.str.startswith("LN9").sum())

    holds = legit_disb[legit_disb.action == "HOLD"]
    return {
        "attack_window": {"first_attack_event": _fmt_clock(first_atk),
                          "first_alert": _fmt_clock(first_alert),
                          "seconds_to_first_alert": round(first_alert - first_atk, 1),
                          "first_fraudulent_payout_attempt": _fmt_clock(first_money),
                          "incident_opened": _fmt_clock(eng.incidents[0]["opened_ts"]) if eng.incidents else None},
        "money": {"attempted_cr": round(no_ctrl_loss / 1e7, 2),
                  "stopped_cr": round(stopped.amount.sum() / 1e7, 2),
                  "paid_out_cr": round(atk_disb.loc[atk_disb.action == "ALLOW", "amount"].sum() / 1e7, 2),
                  "attack_disbursals": int(len(atk_disb)), "attack_disbursals_stopped": int(len(stopped))},
        "legit": {"disbursals": int(len(legit_disb)),
                  "allowed": int((legit_disb.action == "ALLOW").sum()),
                  "held_for_review": int(len(holds)),
                  "blocked": int((legit_disb.action == "BLOCK").sum()),
                  "held_amount_cr": round(holds.amount.sum() / 1e7, 2)},
        "without_engine": {"loss_cr": round(no_ctrl_loss / 1e7, 2),
                           "found_by": "end-of-day reconciliation (after funds left to mule accounts)",
                           "reconciliation_breaks": recon_breaks,
                           "beneficiary_swaps_missed_by_recon": int((atk_disb.scenario == "beneficiary_swap").sum())},
        "layers": layers,
        "scenarios": scen,
        "rules": rule_table,
        "log_integrity": integrity,
        "latency_ms": {"p50": round(float(out.latency_ms.quantile(0.5)), 3),
                       "p99": round(float(out.latency_ms.quantile(0.99)), 2),
                       "events": int(len(out))},
        "incidents": eng.incidents,
    }
