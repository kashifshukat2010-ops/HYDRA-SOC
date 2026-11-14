# HYDRA — Self-Regenerating Autonomous Defense Architecture

A SOC dashboard showing an autonomous cyber-defense loop working end to end: **detect → deceive → respond → heal**.

Final year project — BS Cybersecurity, Bahauddin Zakariya University.

## What it does

Three AI agents guard a Docker lab, each wrapped in **bounded autonomy** (every agent card on the dashboard states what the agent CAN and CANNOT do):

- **Hunter** (detect-only) — scans containers, tails the central log, writes findings reports. Cannot touch anything.
- **Deceiver** (deceive-only) — fake SSH honeypot with an adaptive tarpit. Slows attackers down and records every move. Cannot touch real systems.
- **Responder** (supervised) — reads Hunter's report and runs approved playbooks only: isolate a container, restart it (self-healing). Human approval gate built in.

The dashboard visualizes it all live: agent cards, findings table, honeypot transcripts, kill-chain pipeline, threat radar, lab network map, and a one-click presentation mode (`?viva=1`).

## Run it

**Easiest — the app:** `HYDRA-SOC.exe` (Windows app, no Python needed) is coming to [Releases](../../releases) soon.

**From source:** Python 3.8+ (standard library only — nothing to pip install):

```
python HYDRA.py
```

Opens `http://127.0.0.1:8080` in your browser automatically. Proven in a live attack demo (11 Oct 2026): attacker hit the honeypot → 3 failed SSH logins → tarpit engaged → fake shell → Hunter found 5 findings → Responder restarted the compromised containers. One full loop, on one screen.

## Why this exists

AI attackers now move at machine speed — a human-speed SOC can't answer them. HYDRA answers with autonomous agents that are fast *and* fenced in: speed without a leash is a liability, so every agent operates inside a declared boundary it cannot cross.

## License

MIT — do what you like, keep the credit. Built by Muhammad Kashif Shoukat.
