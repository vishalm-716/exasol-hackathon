"""Run everything with one command:

    python run_all.py

Outputs go to ./outputs:
    dashboard.html            open in any browser (works offline)
    summary.json              headline numbers
    api_decisions_live.csv    every live-day API call with ALLOW / HOLD / BLOCK and reasons
"""
from __future__ import annotations

import datetime as dt
import json
import os
import time
import warnings

warnings.filterwarnings("ignore")

from nbfc_lab.cyber.analysis import evaluate
from nbfc_lab.cyber.engine import run_stream
from nbfc_lab.cyber.simulator import SimConfig, simulate
from nbfc_lab.report import build

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs")


def step(msg):
    print(f"  - {msg}", flush=True)


def main():
    os.makedirs(OUT, exist_ok=True)
    t_start = time.time()
    print("NBFC AI Risk Lab (synthetic data)")

    cfg = SimConfig()
    step(f"Simulating {cfg.baseline_days} days of normal disbursal API traffic + attack day (CIAD-2026-0046 pattern)")
    events, _, deleted = simulate(cfg)
    step("Learning normal behaviour, then replaying the live day event by event")
    eng, out = run_stream(events, cfg.baseline_days)
    res = evaluate(out, eng, deleted)

    step("Writing outputs")
    o = out.copy()
    o["rules"] = o["rules"].apply(lambda r: "|".join(r))
    o.to_csv(os.path.join(OUT, "api_decisions_live.csv"), index=False)

    summary = {"cyber": {k: res[k] for k in ("attack_window", "money", "legit", "without_engine", "layers",
                                             "log_integrity", "latency_ms")}}
    summary["cyber"]["log_integrity"] = {k: v for k, v in res["log_integrity"].items() if k != "gaps"}
    with open(os.path.join(OUT, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    build({"result": res, "out": out}, os.path.join(OUT, "dashboard.html"), dt.date.today().strftime("%d %b %Y"))

    m = res["money"]
    print("\nResults")
    print(f"  Fraud attempted Rs {m['attempted_cr']} Cr, paid out Rs {m['paid_out_cr']} Cr "
          f"({m['attack_disbursals_stopped']} of {m['attack_disbursals']} payouts stopped)")
    print(f"  {res['legit']['held_for_review']} of {res['legit']['disbursals']} legit payouts held for review, "
          f"{res['legit']['blocked']} blocked")
    print(f"  Behavioural AI alone stopped {res['layers']['Behavioural AI only']['attack_disbursals_stopped_pct']}%; "
          f"with hard controls {res['layers']['Both layers']['attack_disbursals_stopped_pct']}%")
    print(f"\nDone in {time.time() - t_start:.0f}s. Open outputs/dashboard.html in your browser.")


if __name__ == "__main__":
    main()
