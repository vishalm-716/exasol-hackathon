"""Make a square animated GIF + MP4 replay of the attack from the lab's real output.

    python run_all.py                  # creates outputs/api_decisions_live.csv and summary.json
    python tools/make_replay_video.py  # creates outputs/attack_replay.gif and .mp4 (MP4 needs ffmpeg)

Every number in the animation is read from the run's outputs (synthetic data).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pandas as pd
from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "outputs")
W = H = 1080
FPS = 12

BG, PANEL, INK, INK2, MUTED, GRID = "#111110", "#1a1a19", "#f0efec", "#c3c2b7", "#898781", "#2c2c2a"
RED, GREEN, AMBER, BLUE = "#e66767", "#0ca30c", "#fab219", "#3987e5"

FONT_DIRS = ["/usr/share/fonts/opentype/inter", "/Library/Fonts", "C:/Windows/Fonts"]


def font(weight: str, size: int):
    names = {"bold": ["Inter-Bold.otf", "arialbd.ttf", "Arial Bold.ttf"],
             "semi": ["Inter-SemiBold.otf", "arialbd.ttf", "Arial Bold.ttf"],
             "reg": ["Inter-Regular.otf", "arial.ttf", "Arial.ttf"]}[weight]
    for d in FONT_DIRS:
        for n in names:
            p = os.path.join(d, n)
            if os.path.exists(p):
                return ImageFont.truetype(p, size)
    return ImageFont.load_default(size)


F = {k: font(*k.split("_")[0:1], int(k.split("_")[1])) for k in
     ["bold_64", "bold_52", "bold_40", "bold_30", "semi_30", "semi_24", "reg_30", "reg_26", "reg_22", "reg_20"]}


def wrap(d: ImageDraw.ImageDraw, text: str, f, width: int) -> list[str]:
    lines, cur = [], ""
    for w in text.split():
        t = (cur + " " + w).strip()
        if d.textlength(t, font=f) <= width:
            cur = t
        else:
            lines.append(cur)
            cur = w
    return lines + [cur]


def base(footer=True):
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    if footer:
        d.text((60, H - 56), "NBFC AI Risk Lab  ·  open source  ·  simulated on synthetic data", font=F["reg_20"], fill=MUTED)
    return im, d


def clock(ts):
    s = int(ts % 86400)
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


def main():
    dec = pd.read_csv(os.path.join(OUT, "api_decisions_live.csv"))
    summ = json.load(open(os.path.join(OUT, "summary.json")))["cyber"]
    atk = dec[dec.label == "attack"]
    t0, t1 = atk.ts.min() - 30, atk.ts.max() + 30
    win = dec[dec.ts.between(t0, t1)].sort_values("ts")
    money = summ["money"]
    aw = summ["attack_window"]
    layers = summ["layers"]
    frames: list[Image.Image] = []

    def hold(im, seconds):
        frames.extend([im] * int(seconds * FPS))

    # ---------- Scene 1: the problem ----------
    im, d = base()
    d.text((60, 250), "CERT-In Advisory CIAD-2026-0046", font=F["semi_30"], fill=RED)
    d.text((60, 296), "9 Oct 2026  ·  Severity: Critical", font=F["reg_26"], fill=MUTED)
    y = 400
    for line in wrap(d, "Attackers are calling NBFC disbursal APIs directly, from the lender's own whitelisted servers.",
                     F["bold_52"], W - 120):
        d.text((60, y), line, font=F["bold_52"], fill=INK)
        y += 68
    y += 30
    for line in wrap(d, "KYC, sanction and beneficiary checks are skipped. Money goes to mule accounts in minutes.",
                     F["reg_30"], W - 120):
        d.text((60, y), line, font=F["reg_30"], fill=INK2)
        y += 44
    y += 40
    d.text((60, y), "I built an open-source engine to stop it. Here is the replay.", font=F["semi_30"], fill=BLUE)
    hold(im, 3.5)

    # ---------- Scene 2: live replay ----------
    lanes = [("initial_access", "Exploit old upload API"), ("recon", "Recon via web shell"),
             ("direct_disburse_dummy_ref", "Fake payouts"), ("beneficiary_swap", "Swap to mule a/c"),
             ("normal", "Legit traffic")]
    L, R, TOP, RH = 330, W - 60, 430, 82
    X = lambda ts: L + (R - L) * (ts - t0) / (t1 - t0)
    col = {"BLOCK": RED, "HOLD": AMBER, "ALLOW": GREEN}
    n_frames = 7 * FPS
    marks = []
    for label, key in [("First alert", "first_alert"), ("Credential revoked", "incident_opened")]:
        hh, mm, ss = map(int, aw[key].split(":"))
        marks.append((label, int(t0 // 86400) * 86400 + hh * 3600 + mm * 60 + ss))
    for k in range(n_frames + 1):
        now = t0 + (t1 - t0) * k / n_frames
        seen = win[win.ts <= now]
        a = seen[(seen.label == "attack") & (seen.api == "disburse")]
        im, d = base()
        d.text((60, 60), "Replay of the attack", font=F["semi_24"], fill=MUTED)
        d.text((60, 92), clock(now), font=F["bold_64"], fill=INK)
        # counters
        tiles = [("Fraud attempted", f"₹{a.amount.sum() / 1e7:.2f} Cr", INK),
                 ("Fraud paid out", f"₹{a.loc[a.action == 'ALLOW', 'amount'].sum() / 1e7:.2f} Cr", GREEN),
                 ("Calls blocked", f"{int((seen.label.eq('attack') & seen.action.ne('ALLOW')).sum())}", RED)]
        for i, (k_, v, c) in enumerate(tiles):
            x = 60 + i * 330
            d.rounded_rectangle((x, 200, x + 310, 330), 16, fill=PANEL)
            d.text((x + 20, 216), k_, font=F["reg_22"], fill=INK2)
            d.text((x + 20, 252), v, font=F["bold_52"], fill=c)
        # lanes
        for i, (sc, name) in enumerate(lanes):
            y = TOP + i * RH + RH // 2
            d.text((60, y - 14), name, font=F["reg_26"], fill=INK2)
            d.line((L, y, R, y), fill=GRID, width=2)
        for _, e in seen.iterrows():
            i = [s for s, _ in lanes].index(e.scenario) if e.scenario in [s for s, _ in lanes] else 4
            y = TOP + i * RH + RH // 2 + ((int(e.seq_no) * 7919) % 25 - 12)
            x = X(e.ts)
            r = 8 if e.label == "attack" else 5
            d.ellipse((x - r, y - r, x + r, y + r), fill=col[e.action], outline=BG, width=2)
        for label, ts in marks:
            if now >= ts:
                x = X(ts)
                for yy in range(TOP - 10, TOP + RH * len(lanes), 14):
                    d.line((x, yy, x, yy + 7), fill=INK2, width=2)
                d.text((x + 8, TOP + RH * len(lanes) + 6 + (30 if label.startswith("Cred") else 0)),
                       f"{label} {clock(ts)}", font=F["semi_24"], fill=INK)
        # legend
        lx = 60
        for lab, c in [("Blocked", RED), ("Held for human check", AMBER), ("Allowed", GREEN)]:
            d.ellipse((lx, 942, lx + 18, 960), fill=c)
            d.text((lx + 28, 937), lab, font=F["reg_22"], fill=INK2)
            lx += 60 + d.textlength(lab, font=F["reg_22"])
        frames.append(im)
    hold(frames[-1], 2.0)

    # ---------- Scene 3: outcome ----------
    im, d = base()
    d.text((60, 220), "Outcome", font=F["semi_24"], fill=MUTED)
    d.text((60, 260), f"₹{money['attempted_cr']} Cr attempted.", font=F["bold_64"], fill=INK)
    d.text((60, 342), f"₹{money['paid_out_cr']:g} paid out.", font=F["bold_64"], fill=GREEN)
    y = 480
    for t in [f"Stolen credential revoked at {aw['incident_opened']}, before the first fake payout at {aw['first_fraudulent_payout_attempt']}.",
              f"{summ['legit']['held_for_review']} of {summ['legit']['disbursals']} genuine payouts held for a human check. None blocked.",
              f"Attacker deleted {summ['log_integrity']['missing_records']} log lines. The hash-chained log proved it."]:
        for line in wrap(d, t, F["reg_30"], W - 150):
            d.text((100, y), line, font=F["reg_30"], fill=INK2)
            y += 44
        d.ellipse((64, y - 44 * len(wrap(d, t, F['reg_30'], W - 150)) + 14, 78,
                   y - 44 * len(wrap(d, t, F['reg_30'], W - 150)) + 28), fill=BLUE)
        y += 26
    hold(im, 4.5)

    # ---------- Scene 4: the lesson ----------
    ai, both = layers["Behavioural AI only"]["attack_disbursals_stopped_pct"], layers["Both layers"]["attack_disbursals_stopped_pct"]
    for k in range(int(1.5 * FPS) + 1):
        p = k / (1.5 * FPS)
        im, d = base()
        d.text((60, 110), "The lesson for boards", font=F["semi_24"], fill=MUTED)
        d.text((60, 150), "AI alone is not enough.", font=F["bold_64"], fill=INK)
        for i, (lab, v, c) in enumerate([("Behavioural AI only", ai, AMBER), ("AI + hard controls", both, BLUE)]):
            y = 320 + i * 170
            d.text((60, y), lab, font=F["semi_30"], fill=INK2)
            d.rounded_rectangle((60, y + 50, W - 60, y + 110), 12, fill=PANEL)
            w = (W - 120) * v / 100 * p
            if w > 24:
                d.rounded_rectangle((60, y + 50, 60 + w, y + 110), 12, fill=c)
            d.text((W - 60 - d.textlength(f"{v * p:.0f}% stopped", font=F["bold_40"]), y - 6),
                   f"{v * p:.0f}% stopped", font=F["bold_40"], fill=INK)
        y = 690
        for line in wrap(d, "AI missed the first payouts and the slow beneficiary swaps. Cryptographic binding of each "
                            "loan stage caught them. Use AI for early warning, on top of controls that cannot be skipped.",
                         F["reg_30"], W - 120):
            d.text((60, y), line, font=F["reg_30"], fill=INK2)
            y += 44
        frames.append(im)
    hold(frames[-1], 4.5)

    # ---------- Scene 5: call to action ----------
    im, d = base(footer=False)
    d.text((60, 330), "NBFC AI Risk Lab", font=F["bold_64"], fill=INK)
    d.text((60, 420), "Open source  ·  Apache-2.0  ·  runs in one command", font=F["reg_30"], fill=INK2)
    y = 510
    for t in ["Real-time defence for CIAD-2026-0046", "Hard controls + behavioural AI, human in the loop",
              "Every control mapped to the advisory"]:
        d.ellipse((60, y + 12, 74, y + 26), fill=BLUE)
        d.text((92, y), t, font=F["reg_30"], fill=INK)
        y += 54
    d.text((60, H - 56), "Synthetic data only. Not a production model.", font=F["reg_20"], fill=MUTED)
    hold(im, 3.5)

    # ---------- write ----------
    gif = os.path.join(OUT, "attack_replay.gif")
    # Build one palette from a sample of every scene, so no brand colour is lost.
    sample = [frames[i] for i in range(0, len(frames), max(1, len(frames) // 12))] + [frames[-1]]
    strip = Image.new("RGB", (W, H * len(sample)))
    for i, f in enumerate(sample):
        strip.paste(f, (0, H * i))
    pal = strip.resize((W // 4, H * len(sample) // 4)).quantize(colors=96, method=Image.Quantize.MEDIANCUT)
    q = [f.quantize(palette=pal, dither=Image.Dither.NONE) for f in frames]
    q[0].save(gif, save_all=True, append_images=q[1:], duration=int(1000 / FPS), loop=0, optimize=True)
    print(f"GIF: {gif}  ({len(frames)} frames, {len(frames) / FPS:.0f}s, {os.path.getsize(gif) / 1e6:.1f} MB)")

    if shutil.which("ffmpeg"):
        tmp = os.path.join(OUT, "_frames")
        os.makedirs(tmp, exist_ok=True)
        for i, f in enumerate(frames):
            f.save(os.path.join(tmp, f"{i:05d}.png"))
        mp4 = os.path.join(OUT, "attack_replay.mp4")
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(FPS), "-i", os.path.join(tmp, "%05d.png"),
                        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-r", "30", mp4], check=True)
        shutil.rmtree(tmp)
        print(f"MP4: {mp4}  ({os.path.getsize(mp4) / 1e6:.1f} MB)")
    else:
        print("ffmpeg not found: skipped MP4", file=sys.stderr)


if __name__ == "__main__":
    main()
