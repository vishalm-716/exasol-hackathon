"""Run with:  python -m pytest -q      (or without pytest:  python tests/test_lab.py)"""
import inspect
import os
import sys
import warnings

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import pytest
    fixture = pytest.fixture(scope="module")
except ImportError:  # allow running with plain Python
    def fixture(f):
        return f

warnings.filterwarnings("ignore")

from nbfc_lab.cyber.analysis import evaluate
from nbfc_lab.cyber.engine import Engine, HashChainLog, run_stream
from nbfc_lab.cyber.simulator import SimConfig, sign_stage, simulate


@fixture
def cyber():
    cfg = SimConfig(loans_per_day=300, attack_disbursals=30)
    ev, reg, deleted = simulate(cfg)
    eng, out = run_stream(ev, cfg.baseline_days)
    return eng, out, evaluate(out, eng, deleted)


# ---------------- cyber ----------------
def test_no_fraudulent_payout_succeeds(cyber):
    _, _, r = cyber
    assert r["money"]["paid_out_cr"] == 0
    assert r["money"]["attack_disbursals_stopped"] == r["money"]["attack_disbursals"]


def test_no_legitimate_payout_blocked(cyber):
    _, _, r = cyber
    assert r["legit"]["blocked"] == 0
    assert r["legit"]["held_for_review"] / r["legit"]["disbursals"] < 0.03


def test_circuit_breaker_revokes_stolen_token(cyber):
    eng, _, _ = cyber
    assert "static-7f3a" in eng.revoked and eng.incidents


def test_beneficiary_swap_caught_by_stage_binding(cyber):
    _, out, _ = cyber
    swaps = out[out.scenario == "beneficiary_swap"]
    assert len(swaps) and swaps.rules.apply(lambda r: "R02_STAGE_BINDING_FAIL" in r).all()


def test_stage_token_binds_amount_and_beneficiary():
    t = sign_stage("LN1", "beneficiary_verify", 100000.0, "HDFC0123")
    assert t != sign_stage("LN1", "beneficiary_verify", 100001.0, "HDFC0123")
    assert t != sign_stage("LN1", "beneficiary_verify", 100000.0, "HDFC0999")


def test_hash_chain_detects_deletion_and_edit():
    log = HashChainLog()
    for i in range(1, 11):
        log.append(i, {"i": i})
    assert HashChainLog.verify(log.records)["intact"]
    deleted = [r for r in log.records if r["seq_no"] != 5]
    assert HashChainLog.verify(deleted)["missing_records"] == 1
    edited = [dict(r) for r in log.records]
    edited[3]["body"] = '{"i": 999}'
    assert HashChainLog.verify(edited)["broken_links"] >= 1


def test_unknown_api_blocked():
    eng = Engine()
    d = eng.process(dict(seq_no=1, ts=0.0, api="legacy_upload_v1", loan_ref="", product="", client_id="anonymous",
                         src_ip="203.0.113.45", token_id="", token_age_min=0.0, amount=0.0, beneficiary="",
                         stage_token="", result=""))
    assert d["action"] == "BLOCK" and "R09_UNKNOWN_OR_DEPRECATED_API" in d["rules"]


def test_ai_layer_only_holds_never_blocks(cyber):
    _, out, _ = cyber
    ml_only = out[out.rules.apply(lambda r: r == ["ML_BEHAVIOUR_ANOMALY"])]
    assert (ml_only.action == "HOLD").all()


def test_ai_alone_catches_most_but_not_all(cyber):
    _, _, r = cyber
    ai = r["layers"]["Behavioural AI only"]["attack_disbursals_stopped_pct"]
    assert 50 < ai < 100     # useful early warning, but not a replacement for hard controls


if __name__ == "__main__":
    cache, failed = {}, 0
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        args = []
        for p in inspect.signature(fn).parameters:
            if p not in cache:
                cache[p] = globals()[p]()
            args.append(cache[p])
        try:
            fn(*args)
            print(f"PASS  {name}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {name}  {e}")
    print(f"\n{len(tests) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
