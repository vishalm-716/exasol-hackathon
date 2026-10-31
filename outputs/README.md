# outputs

`python run_all.py` writes its results here:

| File | What it is |
| --- | --- |
| `dashboard.html` | Offline dashboard. Open it in any browser |
| `summary.json` | Headline numbers from the run |
| `api_decisions_live.csv` | Every live-day API call with ALLOW / HOLD / BLOCK and the rules that fired |
| `attack_replay.gif`, `attack_replay.mp4` | Created by `python tools/make_replay_video.py` |

The `dashboard.html` committed here is from the default run, so you can see the result without running anything. All data is synthetic.
