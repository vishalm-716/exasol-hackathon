"""Real-time disbursement API protection engine.

Two layers, evaluated on every API call as it arrives:

Layer 1 - Hard controls (deterministic, BLOCK). Each rule maps to a
          recommended action in CERT-In Advisory CIAD-2026-0046.
Layer 2 - Behavioural anomaly model (Isolation Forest, HOLD for maker-checker).
          Learns what normal disbursal traffic looks like and flags
          script-like velocity, regular cadence, bank fan-out, odd amounts.

Plus:
* Circuit breaker - repeated blocks on one credential revoke that credential
  and open an incident (advisory: "disable compromised accounts, suspend
  affected APIs").
* Tamper-evident audit log - every event is hash-chained, so deleted or
  edited log lines are detectable (advisory TTP: "deletion/truncation of logs").

AI recommends; humans decide on HOLDs. Every decision is logged with reasons.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .simulator import APP_SERVERS, BATCH_SERVER, sign_stage

# Rule id -> (description, CIAD-2026-0046 recommended action it implements)
RULES = {
    "R01_REF_NOT_FOUND": ("Disbursal reference has no sanctioned loan record",
                          "Validate every payout against sanctioned/approved records; reject reference identifiers with no corresponding records"),
    "R02_STAGE_BINDING_FAIL": ("Missing or invalid stage token: KYC/sanction/beneficiary stages not proven",
                               "Bind multi-stage transaction flows cryptographically so debit-stage APIs cannot be invoked without preceding validation stages"),
    "R03_AMOUNT_OVER_SANCTION": ("Amount exceeds sanctioned amount or per-transaction ceiling",
                                 "Enforce per-transaction and per-day cumulative ceilings at the API/payment stage"),
    "R04_DAILY_CEILING": ("Client's cumulative disbursal for the day exceeds ceiling",
                          "Enforce per-transaction and per-day cumulative ceilings at the API/payment stage"),
    "R05_BENEFICIARY_MISMATCH": ("Beneficiary differs from the penny-drop verified account",
                                 "Apply beneficiary validation (penny-drop, name-to-account matching) on all disbursement paths"),
    "R06_STATIC_TOKEN": ("Long-lived static API token in use",
                         "Enforce per-session authentication on all APIs; eliminate long-lived static tokens"),
    "R07_SOURCE_NOT_ALLOWED": ("Call from a source not allowed for this client / API",
                               "Remove internet exposure of internal applications; restrict egress; enforce geofencing"),
    "R08_DUPLICATE_DISBURSAL": ("Loan already disbursed",
                                "Validate every payout against sanctioned/approved records"),
    "R09_UNKNOWN_OR_DEPRECATED_API": ("Call to an API not in the approved inventory",
                                      "Maintain a complete API inventory; formally decommission deprecated and unused APIs"),
    "R10_TOKEN_REVOKED": ("Credential revoked by circuit breaker",
                          "Upon detection: disable compromised accounts, suspend affected APIs, rotate all credentials"),
    "ML_BEHAVIOUR_ANOMALY": ("Behaviour unlike normal disbursal traffic (velocity, cadence, fan-out, amount)",
                             "Implement real-time monitoring of fund transfers with velocity, amount-band and new-beneficiary checks; adopt behavioural anti-automation controls"),
}

API_INVENTORY = {"create_loan", "kyc_verify", "sanction", "beneficiary_verify", "disburse"}
CLIENT_SOURCES = {"los-app": set(APP_SERVERS), "disb-batch": {BATCH_SERVER}}
ML_FEATURES = ["calls_token_60s", "calls_client_10m", "interarrival_cv", "distinct_banks_client_10m",
               "log_amount_ratio", "log_token_age", "off_hours"]


# --------------------------------------------------------------------------
# Tamper-evident log
# --------------------------------------------------------------------------
class HashChainLog:
    """Append-only log where each record carries hash(prev_hash + record)."""

    def __init__(self):
        self.records: list[dict] = []
        self._prev = "0" * 64

    def append(self, seq_no: int, payload: dict):
        body = json.dumps(payload, sort_keys=True, default=str)
        h = hashlib.sha256((self._prev + body).encode()).hexdigest()
        self.records.append({"seq_no": seq_no, "prev": self._prev, "hash": h, "body": body})
        self._prev = h

    @staticmethod
    def verify(records: list[dict]) -> dict:
        """Return sequence gaps and broken links found in a (possibly tampered) copy."""
        gaps, broken = [], []
        prev_seq, prev_hash = None, "0" * 64
        for r in records:
            if prev_seq is not None and r["seq_no"] != prev_seq + 1:
                gaps.append((prev_seq + 1, r["seq_no"] - 1))
            if r["prev"] != prev_hash or hashlib.sha256((r["prev"] + r["body"]).encode()).hexdigest() != r["hash"]:
                broken.append(r["seq_no"])
            prev_seq, prev_hash = r["seq_no"], r["hash"]
        missing = sum(b - a + 1 for a, b in gaps)
        return {"intact": not gaps and not broken, "gaps": gaps, "missing_records": missing,
                "broken_links": len(broken)}


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------
@dataclass
class EngineConfig:
    per_txn_ceiling: float = 5_000_000.0
    per_client_daily_ceiling: float | None = None  # None = learn 1.25 x highest baseline day per client
    max_token_age_min: float = 60.0
    breaker_blocks: int = 3            # blocks on one token ...
    breaker_window_s: float = 300.0    # ... within this window => revoke
    ml_contamination_pct: float = 0.5  # HOLD rate tolerated on normal traffic (percent)


@dataclass
class Engine:
    cfg: EngineConfig = field(default_factory=EngineConfig)

    def __post_init__(self):
        self.lms = {}                  # loan_ref -> sanctioned record seen on the stream
        self.disbursed = set()
        self.tok_calls = defaultdict(deque)
        self.client_calls = defaultdict(deque)  # (ts, bank)
        self.client_day_total = defaultdict(float)
        self.blocks_by_token = defaultdict(deque)
        self.revoked = {}
        self.incidents = []
        self.product_median = {}
        self.daily_ceiling = getattr(self, "daily_ceiling", {})
        self.model = {}
        self.threshold = {}
        self.log = HashChainLog()

    # ---------------- learning "normal" ----------------
    def fit_baseline(self, baseline: pd.DataFrame):
        disb = baseline[baseline.api == "disburse"]
        self.product_median = disb.groupby("product")["amount"].median().to_dict()
        daily = disb.groupby(["client_id", "day"])["amount"].sum().groupby("client_id").max()
        self.daily_ceiling = {c: v * 1.25 for c, v in daily.items()}
        feats = []
        for ev in baseline.to_dict("records"):
            f = self._observe(ev, learning=True)
            if f is not None:
                feats.append({**f, "client_id": ev["client_id"]})
        X = pd.DataFrame(feats)
        # One behavioural baseline per API client: the app and the night batch behave differently.
        self.model, self.threshold = {}, {}
        for client, g in X.groupby("client_id"):
            m = IsolationForest(n_estimators=150, random_state=0).fit(g[ML_FEATURES])
            self.model[client] = m
            self.threshold[client] = float(np.percentile(m.decision_function(g[ML_FEATURES]),
                                                         self.cfg.ml_contamination_pct))
        self.__post_init_state_only()
        return X

    def __post_init_state_only(self):
        """Reset streaming state (keep learned model) before going live."""
        keep = (self.model, self.threshold, self.product_median, self.daily_ceiling)
        self.__post_init__()
        self.model, self.threshold, self.product_median, self.daily_ceiling = keep

    # ---------------- feature computation ----------------
    def _observe(self, ev: dict, learning: bool = False):
        """Update streaming state; return ML features for disburse calls."""
        ts = ev["ts"]
        if ev["api"] == "sanction":
            self.lms[ev["loan_ref"]] = {"amount": ev["amount"], "beneficiary": None, "verified": False}
        elif ev["api"] == "beneficiary_verify" and ev["loan_ref"] in self.lms and ev.get("result") == "MATCH":
            self.lms[ev["loan_ref"]].update(beneficiary=ev["beneficiary"], verified=True)
        if ev["api"] != "disburse":
            return None

        tq = self.tok_calls[ev["token_id"]]
        tq.append(ts)
        while tq and tq[0] < ts - 600:
            tq.popleft()
        cq = self.client_calls[ev["client_id"]]
        cq.append((ts, ev["beneficiary"][:5]))
        while cq and cq[0][0] < ts - 600:
            cq.popleft()

        recent = list(tq)[-9:]
        gaps = np.diff(recent)
        cv = float(np.std(gaps) / np.mean(gaps)) if len(gaps) >= 3 and np.mean(gaps) > 0 else 1.0
        med = self.product_median.get(ev["product"], 1_000_000.0)
        hour = (ts % 86400) / 3600
        return {
            "calls_token_60s": sum(1 for x in tq if x >= ts - 60),
            "calls_client_10m": len(cq),
            "interarrival_cv": min(cv, 3.0),
            "distinct_banks_client_10m": len({b for _, b in cq}),
            "log_amount_ratio": float(np.log(max(ev["amount"], 1) / med)),
            "log_token_age": float(np.log1p(ev["token_age_min"])),
            "off_hours": int(hour < 7 or hour > 21),
        }

    # ---------------- decision ----------------
    def process(self, ev: dict) -> dict:
        t0 = time.perf_counter()
        ts, api, ref, tok = ev["ts"], ev["api"], ev["loan_ref"], ev["token_id"]
        hits = []

        if tok and tok in self.revoked:
            hits.append("R10_TOKEN_REVOKED")
        if api not in API_INVENTORY:
            hits.append("R09_UNKNOWN_OR_DEPRECATED_API")
        if ev["token_age_min"] > self.cfg.max_token_age_min:
            hits.append("R06_STATIC_TOKEN")
        allowed = CLIENT_SOURCES.get(ev["client_id"])
        if allowed is None or ev["src_ip"] not in allowed:
            hits.append("R07_SOURCE_NOT_ALLOWED")

        feats = self._observe(ev)
        ml_score = None
        if api == "disburse":
            rec = self.lms.get(ref)
            if rec is None:
                hits.append("R01_REF_NOT_FOUND")
            else:
                expected = sign_stage(ref, "beneficiary_verify", rec["amount"], rec["beneficiary"] or "")
                if ev["stage_token"] != expected or ev["beneficiary"] != rec["beneficiary"]:
                    hits.append("R02_STAGE_BINDING_FAIL")
                if not rec["verified"] or ev["beneficiary"] != rec["beneficiary"]:
                    hits.append("R05_BENEFICIARY_MISMATCH")
                if ev["amount"] > rec["amount"] + 0.5:
                    hits.append("R03_AMOUNT_OVER_SANCTION")
                if ref in self.disbursed:
                    hits.append("R08_DUPLICATE_DISBURSAL")
            if ev["amount"] > self.cfg.per_txn_ceiling and "R03_AMOUNT_OVER_SANCTION" not in hits:
                hits.append("R03_AMOUNT_OVER_SANCTION")
            day_key = (ev["client_id"], int(ts // 86400))
            ceiling = self.cfg.per_client_daily_ceiling or self.daily_ceiling.get(ev["client_id"], 0.0)
            if self.client_day_total[day_key] + ev["amount"] > ceiling:
                hits.append("R04_DAILY_CEILING")
            if self.model:
                m = self.model.get(ev["client_id"])
                if m is None:  # a client that never disbursed before is anomalous by definition
                    hits.append("ML_BEHAVIOUR_ANOMALY")
                else:
                    ml_score = float(m.decision_function(pd.DataFrame([feats])[ML_FEATURES])[0])
                    if ml_score < self.threshold[ev["client_id"]]:
                        hits.append("ML_BEHAVIOUR_ANOMALY")

        hard = [h for h in hits if not h.startswith("ML_")]
        if hard:
            action = "BLOCK"
        elif hits:
            action = "HOLD"  # sent to maker-checker queue, not paid until a human approves
        else:
            action = "ALLOW"

        if action == "ALLOW" and api == "disburse":
            self.disbursed.add(ref)
            self.client_day_total[(ev["client_id"], int(ts // 86400))] += ev["amount"]

        # Circuit breaker
        if action == "BLOCK" and tok:
            bq = self.blocks_by_token[tok]
            bq.append(ts)
            while bq and bq[0] < ts - self.cfg.breaker_window_s:
                bq.popleft()
            if len(bq) >= self.cfg.breaker_blocks and tok not in self.revoked:
                self.revoked[tok] = ts
                self.incidents.append({
                    "opened_ts": ts, "token_id": tok, "client_id": ev["client_id"], "src_ip": ev["src_ip"],
                    "trigger": f"{len(bq)} blocked calls within {int(self.cfg.breaker_window_s)}s",
                    "auto_actions": ["Revoke token", "Suspend disburse API for client pending review",
                                     "Snapshot logs and host for forensics", "Page SOC + CISO"],
                })

        latency_ms = (time.perf_counter() - t0) * 1000
        decision = {"seq_no": ev["seq_no"], "ts": ts, "api": api, "action": action, "rules": hits,
                    "ml_score": ml_score, "latency_ms": latency_ms}
        self.log.append(ev["seq_no"], {**{k: ev[k] for k in ("ts", "api", "loan_ref", "client_id", "src_ip",
                                                               "amount", "beneficiary")}, "action": action})
        return decision


def run_stream(events: pd.DataFrame, baseline_days: int, cfg: EngineConfig | None = None, use_rules=True,
               use_ml=True):
    """Train on baseline days, then replay the live days event by event."""
    eng = Engine(cfg or EngineConfig())
    base = events[events.day < baseline_days]
    live = events[events.day >= baseline_days]
    # Keep LMS state from baseline (sanctions that happened earlier are still valid).
    eng.fit_baseline(base)
    for ev in base.to_dict("records"):
        eng._observe(ev)
        if ev["api"] == "disburse":
            eng.disbursed.add(ev["loan_ref"])
    decisions = [eng.process(ev) for ev in live.to_dict("records")]
    out = live.reset_index(drop=True).join(pd.DataFrame(decisions).drop(columns=["seq_no", "ts", "api"]))
    if not use_rules or not use_ml:
        out = _ablate(out, use_rules, use_ml)
    return eng, out


def _ablate(out: pd.DataFrame, use_rules: bool, use_ml: bool) -> pd.DataFrame:
    """Recompute actions as if only one layer existed (for the layer comparison)."""
    o = out.copy()

    def act(rules):
        r = [x for x in rules if x != "R10_TOKEN_REVOKED"]  # breaker depends on rules
        hard = [x for x in r if not x.startswith("ML_")] if use_rules else []
        ml = [x for x in r if x.startswith("ML_")] if use_ml else []
        return "BLOCK" if hard else ("HOLD" if ml else "ALLOW")

    o["action"] = o["rules"].apply(act)
    return o
