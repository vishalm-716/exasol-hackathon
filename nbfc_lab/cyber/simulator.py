"""Synthetic disbursement API traffic, including the attack described in
CERT-In Advisory CIAD-2026-0046 (09 Oct 2026, severity Critical):
"Threat Actors Exploiting Payment and Disbursement APIs for Unauthorized
Fund Transfers in BFSI Entities".

Legitimate flow (what the lending application does):
    create_loan -> kyc_verify -> sanction -> beneficiary_verify -> disburse

Each stage returns a signed *stage token*. The disburse call must present the
token issued at the beneficiary_verify stage. This is the "cryptographic
binding of multi-stage transaction flows" the advisory recommends.

Attack flow (what the advisory describes):
    exploit internet-facing app / deprecated upload API  -> web shell
    -> steal payment API credentials (long-lived static token)
    -> call disburse DIRECTLY from the entity's own whitelisted server,
       skipping KYC, sanction and beneficiary verification
    -> dummy reference numbers, limits exceeded, mule accounts at many banks
    -> delete / truncate logs

Everything is synthetic. IP ranges use documentation / private ranges.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

import numpy as np
import pandas as pd

STAGES = ["create_loan", "kyc_verify", "sanction", "beneficiary_verify", "disburse"]
BANKS = ["HDFC0", "ICIC0", "SBIN0", "UTIB0", "PUNB0", "BARB0", "KKBK0", "YESB0", "IDIB0", "CNRB0",
         "UBIN0", "INDB0", "FDRL0", "AUBL0", "RATN0"]
APP_SERVERS = ["10.20.1.11", "10.20.1.12", "10.20.1.13"]      # whitelisted internal app tier
BATCH_SERVER = "10.20.2.21"                                    # legitimate night batch
HOSTING_IPS = ["203.0.113.45", "198.51.100.77", "203.0.113.90"]  # attacker infra (doc ranges)

# Demo signing key. In production this lives in an HSM / secrets manager and rotates.
STAGE_KEY = b"demo-only-rotate-me"


def sign_stage(loan_ref: str, stage: str, amount: float, beneficiary: str) -> str:
    msg = f"{loan_ref}|{stage}|{amount:.2f}|{beneficiary}".encode()
    return hmac.new(STAGE_KEY, msg, hashlib.sha256).hexdigest()[:32]


@dataclass
class SimConfig:
    seed: int = 11
    baseline_days: int = 3          # clean history used to learn "normal"
    live_days: int = 1              # day on which the attack happens
    loans_per_day: int = 900
    attack_start_hour: float = 14.25  # 14:15 — during business hours, to hide in traffic
    attack_disbursals: int = 60
    beneficiary_swap_attacks: int = 6   # subtle variant: real loan, mule beneficiary
    logs_deleted: int = 25


def _legit_day(rng, day: int, n: int, start_id: int):
    """One day of legitimate loan flows. Returns (events, sanction_register rows)."""
    events, register = [], []
    t0 = day * 86400
    for k in range(n):
        ref = f"LN{start_id + k:07d}"
        product = rng.choice(["FARM", "MSME", "CV", "SCF"], p=[0.30, 0.35, 0.25, 0.10])
        amt = float(np.round({
            "FARM": rng.lognormal(11.8, 0.5), "MSME": rng.lognormal(13.2, 0.6),
            "CV": rng.lognormal(13.9, 0.4), "SCF": rng.lognormal(14.2, 0.7)}[product], -2))
        amt = min(amt, 4_500_000)
        bene = f"{rng.choice(BANKS)}{rng.integers(10**8, 10**9)}"
        # Business-hours start (09:30–18:30) with mild clustering.
        start = t0 + rng.uniform(9.5, 18.5) * 3600
        token = f"sess-{rng.integers(10**9)}"
        server = rng.choice(APP_SERVERS)
        t = start
        stage_token = None
        for stage in STAGES:
            t += rng.uniform(20, 600) if stage != "disburse" else rng.uniform(60, 3600)
            night_batch = stage == "disburse" and rng.random() < 0.08
            if night_batch:  # some disbursals are released by the overnight batch job
                t = t0 + 86400 + rng.uniform(1.5, 3.0) * 3600  # next day 01:30–03:00
            ev = dict(ts=t, api=stage, loan_ref=ref, product=product,
                      client_id="disb-batch" if night_batch else "los-app",
                      src_ip=BATCH_SERVER if night_batch else server,
                      token_id=f"batch-{day}" if night_batch else token,
                      token_age_min=float(rng.uniform(0, 25)),
                      amount=amt if stage in ("sanction", "disburse") else 0.0,
                      beneficiary=bene if stage in ("beneficiary_verify", "disburse") else "",
                      stage_token="", label="legit", scenario="normal")
            if stage == "beneficiary_verify":
                ev["result"] = "MATCH"
                stage_token = sign_stage(ref, "beneficiary_verify", amt, bene)
            if stage == "disburse":
                ev["stage_token"] = stage_token
            events.append(ev)
        register.append(dict(loan_ref=ref, product=product, sanctioned_amount=amt,
                             beneficiary=bene, beneficiary_verified=True, sanction_day=day))
    return events, register


def _attack(rng, cfg: SimConfig, day: int, register: pd.DataFrame):
    """Attack campaign modelled on CIAD-2026-0046."""
    ev = []
    t = day * 86400 + cfg.attack_start_hour * 3600

    # 1) Initial access: abuse of a deprecated, unauthenticated upload API from hosting infra.
    for i in range(8):
        t += rng.uniform(5, 40)
        ev.append(dict(ts=t, api="legacy_upload_v1", loan_ref="", product="", client_id="anonymous",
                       src_ip=rng.choice(HOSTING_IPS), token_id="", token_age_min=0.0, amount=0.0,
                       beneficiary="", stage_token="", label="attack", scenario="initial_access"))
    # 2) Recon of payment APIs via web shell (now from inside: whitelisted app server).
    shell_ip = APP_SERVERS[0]
    for i in range(10):
        t += rng.uniform(3, 15)
        ev.append(dict(ts=t, api="payment_api_probe", loan_ref="", product="", client_id="los-app",
                       src_ip=shell_ip, token_id="static-7f3a", token_age_min=60 * 24 * 410.0,
                       amount=0.0, beneficiary="", stage_token="", label="attack", scenario="recon"))
    # 3) Scripted direct disbursal: dummy refs, limits exceeded, mule accounts, no stage token.
    t += 120
    mule_banks = rng.choice(BANKS, size=cfg.attack_disbursals)
    for i in range(cfg.attack_disbursals):
        t += rng.normal(6.0, 0.4)  # machine-regular cadence
        amt = float(np.round(rng.uniform(1_800_000, 9_500_000), -3))
        ev.append(dict(ts=t, api="disburse", loan_ref=f"LN9{rng.integers(10**6):06d}",
                       product="MSME", client_id="los-app", src_ip=shell_ip,
                       token_id="static-7f3a", token_age_min=60 * 24 * 410.0, amount=amt,
                       beneficiary=f"{mule_banks[i]}{rng.integers(10**8, 10**9)}",
                       stage_token="", label="attack", scenario="direct_disburse_dummy_ref"))
    # 4) Subtle variant: REAL sanctioned-but-not-yet-disbursed loans, amount within sanction,
    #    beneficiary swapped to a mule. Forged stage token (attacker lacks the signing key).
    pick = register.sample(cfg.beneficiary_swap_attacks, random_state=int(rng.integers(1e6)))
    for _, r in pick.iterrows():
        t += rng.uniform(30, 90)
        ev.append(dict(ts=t, api="disburse", loan_ref=r.loan_ref, product=r["product"],
                       client_id="los-app", src_ip=shell_ip, token_id="static-7f3a",
                       token_age_min=60 * 24 * 410.0, amount=float(r.sanctioned_amount),
                       beneficiary=f"{rng.choice(BANKS)}{rng.integers(10**8, 10**9)}",
                       stage_token=hashlib.md5(str(rng.random()).encode()).hexdigest(),
                       label="attack", scenario="beneficiary_swap"))
    return ev


def simulate(cfg: SimConfig | None = None):
    """Return (events_df, sanction_register_df, deleted_seq_numbers).

    events_df is ordered by time and carries a monotonic seq_no as logged.
    """
    cfg = cfg or SimConfig()
    rng = np.random.default_rng(cfg.seed)
    events, register = [], []
    next_id = 1
    for d in range(cfg.baseline_days + cfg.live_days):
        e, r = _legit_day(rng, d, cfg.loans_per_day, next_id)
        next_id += cfg.loans_per_day
        events += e
        register += r
    reg = pd.DataFrame(register)
    live_day = cfg.baseline_days
    # Loans sanctioned on the live day whose disbursal happens after the attack starts.
    df_tmp = pd.DataFrame(events)
    attack_t = live_day * 86400 + cfg.attack_start_hour * 3600
    # Subtle-variant targets: beneficiary already verified before the attack, payout not yet made.
    verified_before = set(df_tmp[(df_tmp.api == "beneficiary_verify") & (df_tmp.ts < attack_t)].loan_ref)
    paid_later = set(df_tmp[(df_tmp.api == "disburse") & (df_tmp.ts > attack_t + 1800)].loan_ref)
    events += _attack(rng, cfg, live_day, reg[reg.loan_ref.isin(verified_before & paid_later)])

    df = pd.DataFrame(events).sort_values("ts").reset_index(drop=True)
    df["result"] = df.get("result", pd.Series(index=df.index)).fillna("")
    df["seq_no"] = np.arange(1, len(df) + 1)
    df["day"] = (df["ts"] // 86400).astype(int)
    df["hour"] = (df["ts"] % 86400) / 3600

    # Anti-forensics: attacker deletes some log lines AFTER the campaign.
    atk = df.index[df.label == "attack"]
    deleted = rng.choice(df.loc[atk, "seq_no"].values, size=cfg.logs_deleted, replace=False)
    return df, reg, set(int(x) for x in deleted)
