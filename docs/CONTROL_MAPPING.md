# Control mapping

## CERT-In Advisory CIAD-2026-0046 (9 Oct 2026)

Recommended actions from the advisory, and where this repo implements or demonstrates each.

| Advisory recommended action | In this repo | Where |
| --- | --- | --- |
| Enforce MFA for payment platforms, admin portals, payment/bank APIs, remote access | Not simulated; out of scope for an API engine. Enforce at the identity provider | – |
| Maintain a complete API inventory; decommission deprecated and unused APIs | Calls to any API not in the inventory are blocked (`R09`) | `engine.py` |
| Per-session authentication on all APIs; eliminate long-lived static tokens | Tokens older than 60 minutes are blocked (`R06`) | `engine.py` |
| Bind multi-stage transaction flows cryptographically | HMAC stage token issued at beneficiary verification, bound to loan, amount and beneficiary; required by disburse (`R02`) | `simulator.py`, `engine.py` |
| Maker-checker or second-level verification for all fund movement | Behavioural anomalies are HELD for a human checker | `engine.py` |
| Validate every payout against sanctioned records; reject unknown references | `R01`, `R08` | `engine.py` |
| Per-transaction and per-day cumulative ceilings | `R03`, `R04` (daily ceiling learned as 1.25 × highest baseline day per client) | `engine.py` |
| Beneficiary validation (penny-drop, name match) and velocity limits | `R05`; velocity in the behavioural model | `engine.py` |
| Restrict outbound (egress) traffic by allow-listing | Source allow-list per client (`R07`). Egress filtering belongs in the network layer | `engine.py` |
| Store API keys in secrets manager / HSM; rotate | Demo key is a constant marked "rotate me"; replace with HSM-held key | `simulator.py` |
| Real-time monitoring with velocity, amount-band and new-beneficiary checks; automated blocking or holding | Whole engine; ALLOW / HOLD / BLOCK per call | `engine.py` |
| Near-real-time reconciliation with bank / aggregator statements | Counterfactual shows what end-of-day reconciliation finds when no engine exists | `analysis.py` |
| Centralised logging, retention of at least 180 days | Hash-chained decision log; retention is a storage policy | `engine.py` |
| EDR with tamper protection | Out of scope (endpoint control) | – |
| Behavioural anti-automation (rate limiting, sequence binding) | Timing-regularity feature, velocity features, stage binding | `engine.py` |
| Remove internet exposure of internal apps; geofencing under change control | Out of scope (network control) | – |
| Isolate dev, test and production | Out of scope | – |
| Regular VA/PT including API security testing | The simulator can be reused as a test harness for API controls | `simulator.py` |
| On detection: disable accounts, suspend APIs, preserve evidence, rotate credentials, report to CERT-In / CSIRT-Fin | Circuit breaker revokes credential and opens an incident record with these actions; reporting stays a human step | `engine.py` |

## CERT-In Blueprint on AI-assisted exploitation (v1.0, 25 May 2026)

| Blueprint reference | How the repo applies it |
| --- | --- |
| §5 Principle 1 – Assume Breach | Attacker is modelled inside the trusted perimeter; IP allow-listing alone is not trusted |
| §5 Principle 2 – Zero Trust | Every payout must prove preceding stages; no long-lived tokens |
| §5 Principle 8 – Security Automation with Human Oversight | Auto-block only on deterministic breaches; AI anomalies go to a human |
| §8 item 4 – Behavioural Analytics and Anomaly Detection | Per-client Isolation Forest including suspicious API activity |
| §8 item 10 – Security Automation | Circuit breaker and incident record |
| §10 – Incident Response | Incident record; tamper-evident logs for forensics |
| §13 Phase II (8–30 days) | "Implement behaviour-based detection" and API security assessments |

## Moving from demo to production (checklist)

- [ ] Replace the simulator with a feed from the API gateway / WAF (streaming, not batch)
- [ ] Issue stage tokens from the LOS; sign with an HSM-held key; rotate
- [ ] Put the engine inline (or as a gateway policy) so a BLOCK actually stops the call
- [ ] Connect HOLD to the existing maker-checker queue with an SLA
- [ ] Ship the hash-chained log to write-once storage outside the app servers
- [ ] Run as a shadow mode for at least a few weeks; tune thresholds before enforcing
- [ ] Independent review of rules and model; record in the model inventory
- [ ] Red-team the controls using the simulator's attack scenarios plus new ones
