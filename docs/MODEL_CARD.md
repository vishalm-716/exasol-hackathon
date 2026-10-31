# Model card

The model is trained and evaluated on **synthetic data only**. Metrics below are what `python run_all.py` produces with the default seeds. They show the method works as designed; they say nothing about performance on real API traffic.

## Disbursement API behavioural anomaly model

| Item | Detail |
| --- | --- |
| Purpose | Flag disbursal API calls whose behaviour is unlike that client's normal traffic, for maker-checker review |
| Method | Isolation Forest, one per API client (the lending app and the night batch behave differently) |
| Features | Calls per token in 60 s, calls per client in 10 min, regularity of timing (coefficient of variation of gaps), distinct beneficiary banks in 10 min, amount vs product median, token age, off-hours flag |
| Threshold | 0.5th percentile of baseline scores per client |
| Action | HOLD only. Hard controls, not the model, are allowed to BLOCK |
| Default results | Alone: stops ~83% of fraudulent payouts with ~0.8% of legit payouts held. With hard controls: 100% stopped, 0 legit blocked |
| Known limits | Learns "normal" from three synthetic days. A real deployment needs weeks of clean baseline, seasonality handling, and periodic retraining with drift checks. An attacker who mimics normal pace evades it, which is why it sits behind deterministic controls |
