"""HYDRA SOC dashboard — SINGLE-FILE edition.

Everything (web server + data layer + presentation + logo) in this one
file. Pure Python standard library, zero installs, works fully offline.

Run it (VS Code: just press Run, or F5)::

    python HYDRA.py              # opens http://127.0.0.1:8080 in your browser
    python HYDRA.py --port 9090

Put this file in a folder next to your ``findings/`` and ``logs/``
folders (it also works one level deeper). Read-only: it only READS
logs/ and findings/ — never writes, never touches Docker.

With no logs yet it shows friendly empty states, never a traceback.
"""

import argparse
import base64  # noqa: F401  (kept: part of the original stdlib-only set)
import datetime
import glob
import html
import json
import math
import os
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


# =========================================================================== #
# DATA LAYER (read-only)                                                      #
# =========================================================================== #
def _find_repo_root():
    # PyInstaller .exe (frozen) builds have no usable __file__ — it points at a
    # temp extraction folder.  Point at the folder the .exe runs from instead,
    # so findings/ and logs/ sitting next to the .exe are found.  Normal runs
    # keep the original script-folder behaviour.
    if getattr(sys, "frozen", False):  # running as a PyInstaller bundle
        here = os.path.dirname(os.path.abspath(sys.executable))
    else:
        here = os.path.dirname(os.path.abspath(__file__))
    for cand in (here, os.path.dirname(here)):
        if os.path.isdir(os.path.join(cand, "findings")) or \
                os.path.isdir(os.path.join(cand, "logs")):
            return cand
    return here


REPO_ROOT = _find_repo_root()
LOG_PATH = os.path.join(REPO_ROOT, "logs", "hydra.log")
FINDINGS_DIR = os.path.join(REPO_ROOT, "findings")
DECEPTION_DIR = os.path.join(FINDINGS_DIR, "deception")

AGENTS = ("hunter", "deceiver", "responder")

# The bounded-autonomy contract, shown on every agent card. This is the
# part of the dashboard the examiner will ask about: each card states not
# just what the agent DOES, but what it is FORBIDDEN from doing.
AUTONOMY = {
    "hunter": {
        "level": "detect-only",
        "can": "Scan containers, tail the central log, write findings reports.",
        "cannot": "Kill, delete, quarantine, restart, or change anything.",
    },
    "deceiver": {
        "level": "deceive-only",
        "can": "Run the fake SSH honeypot, log attacker moves, tarpit them.",
        "cannot": "Attack back, connect outward, or touch real containers.",
    },
    "responder": {
        "level": "supervised",
        "can": "Propose playbooks; run routine ones on managed containers "
               "only with --auto/--approve.",
        "cannot": "Touch anything not labelled hydra.role; act without "
                  "approval by default.",
    },
}


# --------------------------------------------------------------------------- #
# low-level loading                                                           #
# --------------------------------------------------------------------------- #
def _safe_json_line(line):
    """Parse one JSON line; return None instead of raising, ever."""
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def load_events(limit=2000):
    """All parsed events from logs/hydra.log, oldest first.

    Returns [] when the log is missing/empty/unreadable — never raises.
    The log rotates at ~1 MB, so reading it whole is cheap.
    """
    events = []
    try:
        with open(LOG_PATH, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                obj = _safe_json_line(line)
                if obj is not None:
                    events.append(obj)
    except OSError:
        return []
    return events[-limit:]


def _details(event):
    d = event.get("details")
    return d if isinstance(d, dict) else {}


# --------------------------------------------------------------------------- #
# (a) agent status cards                                                      #
# --------------------------------------------------------------------------- #
def agent_status(events):
    """Per-agent: autonomy contract + last-seen timestamp + event count."""
    status = {}
    for agent in AGENTS:
        agent_events = [e for e in events if e.get("agent") == agent]
        last = agent_events[-1].get("timestamp") if agent_events else None
        status[agent] = {
            "level": AUTONOMY[agent]["level"],
            "can": AUTONOMY[agent]["can"],
            "cannot": AUTONOMY[agent]["cannot"],
            "events": len(agent_events),
            "last_seen": last,
        }
    return status


# --------------------------------------------------------------------------- #
# (b) findings table                                                          #
# --------------------------------------------------------------------------- #
def latest_findings_report():
    """(report_dict|None, path|None) for the newest hunter report."""
    try:
        paths = sorted(
            glob.glob(os.path.join(FINDINGS_DIR, "hunter_findings_*.json")),
            key=os.path.getmtime,
        )
    except OSError:
        paths = []
    if not paths:
        return None, None
    path = paths[-1]
    try:
        with open(path, encoding="utf-8") as fh:
            report = json.load(fh)
        if not isinstance(report, dict):
            return None, path
        return report, path
    except (OSError, ValueError):
        return None, path


# --------------------------------------------------------------------------- #
# (c) honeypot activity                                                       #
# --------------------------------------------------------------------------- #
def honeypot_stats(events):
    """Login attempts per src_ip, tarpit adaptations, session counts."""
    attempts = [e for e in events
                if e.get("event_type") == "honeypot_login_attempt"]
    per_ip = {}
    for e in attempts:
        ip = _details(e).get("src_ip", "?")
        per_ip[ip] = per_ip.get(ip, 0) + 1
    adaptations = [e for e in events
                   if e.get("event_type") == "honeypot_adaptation"]
    sessions = [e for e in events
                if e.get("event_type") == "honeypot_session"]
    return {
        "attempts": len(attempts),
        "unique_ips": len(per_ip),
        "sessions": len(sessions),
        "adaptations": len(adaptations),
        "per_ip": sorted(per_ip.items(), key=lambda kv: kv[1], reverse=True),
        "recent_adaptations": list(reversed(adaptations[-10:])),
    }


def list_transcripts():
    """Newest-first [{name, mtime}] of findings/deception/*.json."""
    try:
        paths = sorted(
            glob.glob(os.path.join(DECEPTION_DIR, "*.json")),
            key=os.path.getmtime, reverse=True)
    except OSError:
        return []
    out = []
    for path in paths:
        try:
            out.append({"name": os.path.basename(path),
                        "mtime": os.path.getmtime(path)})
        except OSError:
            continue
    return out


def load_transcript(name):
    """Session dict for a transcript basename, or None.

    The name must be a plain basename already present in the deception
    directory — no path traversal, no surprises.
    """
    if not name or not name.endswith(".json"):
        return None
    if "/" in name or "\\" in name or ".." in name:
        return None
    allowed = {t["name"] for t in list_transcripts()}
    if name not in allowed:
        return None
    path = os.path.realpath(os.path.join(DECEPTION_DIR, name))
    if os.path.dirname(path) != os.path.realpath(DECEPTION_DIR):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            obj = json.load(fh)
        return obj if isinstance(obj, dict) else None
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# (d) responder playbook runs                                                 #
# --------------------------------------------------------------------------- #
def responder_runs(events):
    """Pair playbook_started/completed by action_id, newest first.

    Also returns refused actions (the safety gate firing — good news to
    show on a dashboard) and recent plans.
    """
    started = {}
    order = []
    runs = []
    for e in events:
        etype = e.get("event_type")
        d = _details(e)
        if etype == "playbook_started":
            aid = d.get("action_id")
            if aid and aid not in started:
                started[aid] = e
                order.append(aid)
        elif etype == "playbook_completed":
            aid = d.get("action_id")
            if aid and aid in started:
                runs.append({"started": started.pop(aid), "completed": e})
                order.remove(aid)
    # started but never completed (still running / agent killed mid-run)
    for aid in reversed(order):
        runs.append({"started": started[aid], "completed": None})
    refusals = [e for e in events if e.get("event_type") == "action_refused"]
    plans = [e for e in events if e.get("event_type") == "responder_plan"]
    return {
        "runs": runs,
        "refusals": list(reversed(refusals[-10:])),
        "plans": list(reversed(plans[-5:])),
    }


# --------------------------------------------------------------------------- #
# (e) event timeline                                                          #
# --------------------------------------------------------------------------- #
def timeline(events, limit=50):
    """Newest-first slice of the central log."""
    return list(reversed(events[-limit:]))


# --------------------------------------------------------------------------- #
# one call the server + API share                                             #
# --------------------------------------------------------------------------- #
def build_snapshot():
    """Everything the dashboard page needs, in one dict."""
    events = load_events()
    report, report_path = latest_findings_report()
    return {
        "events": events,
        "agent_status": agent_status(events),
        "report": report,
        "report_path": (os.path.basename(report_path) if report_path else None),
        "honeypot": honeypot_stats(events),
        "transcripts": list_transcripts(),
        "responder": responder_runs(events),
        "timeline": timeline(events),
    }



# =========================================================================== #
# PRESENTATION LAYER                                                          #
# =========================================================================== #
REFRESH_SECONDS = 10

# --------------------------------------------------------------------------- #
# small helpers                                                               #
# --------------------------------------------------------------------------- #
def _esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def _now_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S")


def _fmt_hm(ts):
    """'2026-10-11T08:02:03' -> '08:02'. Best effort, never crashes."""
    try:
        return datetime.datetime.fromisoformat(str(ts)).strftime("%H:%M")
    except (ValueError, TypeError):
        return "--:--"


def _humanize(event_type):
    return str(event_type or "").replace("_", " ").strip().title()


# AI-generated HYDRA logo — embedded in this single file.
_LOGO_URI = ("data:image/jpeg;base64," +
             "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")


# --------------------------------------------------------------------------- #
# stylesheet — dark "Next-Gen AI Powered SOC" edition                         #
# --------------------------------------------------------------------------- #
CSS = """
*{box-sizing:border-box}
body{margin:0;padding:0;background:#02070c;color:#d7e8de;
 font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,
 "Helvetica Neue",Arial,sans-serif;font-size:14px;
 background-image:
  radial-gradient(1000px 480px at 70% -8%,rgba(16,185,129,.10),transparent 60%),
  radial-gradient(700px 500px at 8% 110%,rgba(16,185,129,.06),transparent 60%)}
/* ---------- top bar ---------- */
.topbar{display:flex;align-items:center;gap:14px;padding:10px 22px;
 background:rgba(3,10,14,.92);border-bottom:1px solid #0c2b22;
 position:sticky;top:0;z-index:40}
.brand{display:flex;align-items:center;gap:10px}
.brand img{width:38px;height:38px;border-radius:50%;
 box-shadow:0 0 16px rgba(52,211,153,.5)}
.brand .wm{font-size:22px;font-weight:800;letter-spacing:4px;color:#eafff5}
.brand .wm span{color:#34d399}
.topnav{display:flex;gap:22px;margin-left:26px;font-size:13.5px;color:#8fa8a0}
.topnav a{color:#8fa8a0;text-decoration:none}
.topnav a:hover{color:#34d399}
.topnav .sep{color:#1d3a30}
.topbar .sp{flex:1}
.soc{display:flex;align-items:center;gap:8px;font-size:12.5px;font-weight:700;
 color:#34d399}
.soc .dot{width:9px;height:9px;border-radius:50%;background:#34d399;
 box-shadow:0 0 10px #34d399;animation:pulse 1.6s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.clock{font-size:12.5px;color:#7d93a3;font-variant-numeric:tabular-nums;
 font-family:ui-monospace,Menlo,Consolas,monospace}
.gear{color:#5f7a70;font-size:17px}
/* ---------- layout ---------- */
.layout{display:flex;min-height:calc(100vh - 59px)}
.sidebar{width:196px;flex:none;background:#030b10;
 border-right:1px solid #0c2b22;display:flex;flex-direction:column;
 padding:16px 10px;position:sticky;top:59px;height:calc(100vh - 59px)}
.snav{display:flex;flex-direction:column;gap:2px}
.snav a{display:flex;align-items:center;gap:12px;color:#9db8ac;
 text-decoration:none;font-size:13.5px;font-weight:600;padding:11px 12px;
 border-radius:9px;border-left:3px solid transparent}
.snav a:hover{background:rgba(52,211,153,.07);color:#eafff5}
.snav a.on{background:rgba(16,185,129,.14);color:#fff;
 border-left-color:#34d399}
.snav .ic{width:20px;text-align:center;color:#34d399;font-size:15px}
.snav a.on .ic{color:#4ade80}
.stag{margin-top:auto;padding:16px 12px;font-size:12.5px;color:#7d93a3;
 line-height:1.8;border-top:1px solid #0c2b22}
.stag b{color:#34d399;letter-spacing:2px}
main{flex:1;min-width:0;padding:22px 24px;max-width:1460px}
.cols{display:grid;grid-template-columns:minmax(0,1fr) 348px;gap:18px;
 align-items:start}
/* ---------- hero ---------- */
.hero{position:relative;overflow:hidden;border:1px solid #0e3a2c;
 border-radius:16px;padding:38px 36px;margin-bottom:18px;
 background:linear-gradient(120deg,#04120d 30%,#03130e 60%,#02100b);
 min-height:280px;display:flex;align-items:center}
.hero-art{position:absolute;right:-40px;top:50%;transform:translateY(-50%);
 width:430px;height:430px;object-fit:cover;opacity:.85;
 -webkit-mask-image:radial-gradient(circle at 50% 50%,#000 42%,transparent 72%);
 mask-image:radial-gradient(circle at 50% 50%,#000 42%,transparent 72%)}
.hero-text{position:relative;z-index:2;max-width:430px}
.hero-text h1{margin:0;font-size:64px;font-weight:800;letter-spacing:10px;
 background:linear-gradient(180deg,#d9fff0,#34d399 70%,#0d8a4e);
 -webkit-background-clip:text;background-clip:text;color:transparent;
 text-shadow:0 0 44px rgba(52,211,153,.25)}
.hero-sub{font-size:14px;font-weight:800;letter-spacing:5px;color:#eafff5;
 margin:10px 0 12px}
.hero-tag{font-size:13.5px;color:#8fa8a0;line-height:1.75;margin:0 0 16px}
.threat-pill{display:inline-flex;align-items:center;gap:9px;font-size:12px;
 font-weight:800;letter-spacing:1.6px;padding:8px 16px;border-radius:24px;
 border:1px solid;text-transform:uppercase}
.threat-pill i{width:8px;height:8px;border-radius:50%;background:currentColor;
 box-shadow:0 0 8px currentColor}
.tp-high{color:#f87171;border-color:#5b1d24;background:rgba(248,113,113,.08)}
.tp-guarded{color:#fbbf24;border-color:#5b4517;background:rgba(251,191,36,.08)}
.tp-low{color:#34d399;border-color:#14532d;background:rgba(52,211,153,.08)}
.tp-unknown{color:#7d93a3;border-color:#1e2c4a;background:rgba(125,147,163,.08)}
/* ---------- capability cards ---------- */
.caps{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;
 margin-bottom:18px}
.cap{background:rgba(6,20,16,.75);border:1px solid #0e3a2c;border-radius:14px;
 padding:22px 16px;text-align:center;transition:transform .15s}
.cap:hover{transform:translateY(-3px);border-color:#1d5c46}
.cap .ic{width:52px;height:52px;margin:0 auto 12px;border-radius:50%;
 display:flex;align-items:center;justify-content:center;font-size:23px;
 color:#34d399;background:rgba(52,211,153,.09);
 border:1px solid rgba(52,211,153,.3);box-shadow:0 0 18px rgba(52,211,153,.18)}
.cap .t{font-size:13px;font-weight:800;letter-spacing:2.5px;color:#eafff5;
 margin-bottom:8px}
.cap .d{font-size:12px;color:#7d93a3;line-height:1.65}
/* ---------- panels ---------- */
.panel{background:rgba(5,17,13,.82);border:1px solid #0e3a2c;border-radius:14px;
 padding:18px 20px;margin-bottom:18px}
.panel-h{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.panel-h .pt{font-size:12.5px;font-weight:800;letter-spacing:2.2px;color:#eafff5}
.panel-h .sp{flex:1}
.panel-h .more{font-size:11.5px;color:#34d399;text-decoration:none}
/* system overview rows */
.srow{display:flex;align-items:center;gap:12px;padding:11px 2px;
 border-bottom:1px solid #0a241b;font-size:13px}
.srow:last-child{border-bottom:none}
.srow .ic{width:30px;height:30px;border-radius:8px;display:flex;
 align-items:center;justify-content:center;font-size:15px;flex:none;
 background:rgba(52,211,153,.08);border:1px solid rgba(52,211,153,.22)}
.srow .lb{color:#9db8ac}
.srow .vl{margin-left:auto;font-size:16px;font-weight:800;color:#fff;
 font-variant-numeric:tabular-nums}
.srow .vl small{font-size:11px;color:#7d93a3;font-weight:600}
.ok-txt{color:#34d399!important}
/* alerts */
.alert{display:flex;gap:12px;align-items:flex-start;padding:11px 2px;
 border-bottom:1px solid #0a241b}
.alert:last-child{border-bottom:none}
.adot{width:10px;height:10px;border-radius:50%;margin-top:5px;flex:none}
.ad-high{background:#f87171;box-shadow:0 0 8px #f87171}
.ad-medium{background:#fbbf24;box-shadow:0 0 8px #fbbf24}
.ad-low{background:#34d399;box-shadow:0 0 8px #34d399}
.alert .tt{font-size:13px;font-weight:700;color:#e6f2ec}
.alert .src{font-size:11.5px;color:#7d93a3;font-family:ui-monospace,Menlo,monospace}
.alert .tm{margin-left:auto;font-size:11.5px;color:#7d93a3;flex:none;
 font-variant-numeric:tabular-nums}
.fpills{display:flex;gap:6px}
.fpill{font-size:10.5px;font-weight:800;letter-spacing:.6px;color:#7d93a3;
 background:#081712;border:1px solid #134233;border-radius:14px;
 padding:4px 11px;text-decoration:none;text-transform:uppercase}
.fpill:hover{color:#eafff5;border-color:#34d399}
.fpill.on{background:#0d8a4e;border-color:#0d8a4e;color:#fff}
/* agent status */
.astat{display:flex;align-items:center;gap:12px;padding:11px 2px;
 border-bottom:1px solid #0a241b;font-size:13px}
.astat:last-child{border-bottom:none}
.pring{width:11px;height:11px;border-radius:50%;flex:none}
.p-on{background:#34d399;box-shadow:0 0 9px #34d399;animation:pulse 1.6s infinite}
.p-off{background:#3b4a68}
.astat .nm{font-weight:700;color:#e6f2ec}
.astat .ac{margin-left:auto;font-size:12px;color:#7d93a3}
.aquote{margin-top:12px;padding-top:12px;border-top:1px solid #0a241b;
 font-size:11px;letter-spacing:1.4px;color:#5f7a70;text-align:center;
 line-height:1.9}
/* chart + logs */
.duo{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.15fr);gap:18px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;color:#5f7a70;font-size:10.5px;font-weight:800;
 letter-spacing:1.4px;text-transform:uppercase;padding:9px 10px;
 border-bottom:1px solid #0e3a2c}
td{padding:9px 10px;border-bottom:1px solid #0a241b;color:#b9d4c6;
 vertical-align:middle}
tr:last-child td{border-bottom:none}
tbody tr:hover td{background:rgba(52,211,153,.04)}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.st{font-size:10.5px;font-weight:800;letter-spacing:.8px;text-transform:uppercase;
 padding:3px 10px;border-radius:12px;border:1px solid;white-space:nowrap}
.st-detect{color:#f87171;border-color:#5b1d24;background:rgba(248,113,113,.08)}
.st-warn{color:#fbbf24;border-color:#5b4517;background:rgba(251,191,36,.08)}
.st-block{color:#34d399;border-color:#14532d;background:rgba(52,211,153,.08)}
.st-deceive{color:#a78bfa;border-color:#3b2f66;background:rgba(167,139,250,.08)}
.st-info{color:#60a5fa;border-color:#1e3a66;background:rgba(96,165,250,.08)}
.empty{color:#5f7a70;border:1px dashed #134233;border-radius:10px;
 padding:22px;text-align:center;font-size:12.5px;line-height:1.8}
.empty b{color:#9db8ac}
a{color:#34d399}
.footer{margin:26px 0 8px;padding-top:14px;border-top:1px solid #0c2b22;
 display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;
 font-size:11.5px;color:#5f7a70}
.footer b{color:#9db8ac}
@media(max-width:1100px){.cols{grid-template-columns:1fr}.duo{grid-template-columns:1fr}}
@media(max-width:900px){.sidebar{display:none}.caps{grid-template-columns:1fr 1fr}
 .topnav{display:none}.hero-art{opacity:.35}}
"""

# --------------------------------------------------------------------------- #
# splash screen — AI HYDRA logo on first load of the session                  #
# --------------------------------------------------------------------------- #
SPLASH_CSS = """
#splash{position:fixed;inset:0;z-index:9999;display:flex;flex-direction:column;
 align-items:center;justify-content:center;gap:20px;
 background:radial-gradient(800px 520px at 50% 38%,#0a2e1f 0%,#020604 72%);
 transition:opacity .6s ease}
#splash.hide{opacity:0;pointer-events:none}
.splash-img{width:228px;height:228px;object-fit:cover;border-radius:50%;
 box-shadow:0 0 70px rgba(52,211,153,.5),0 0 22px rgba(52,211,153,.35);
 animation:imgin 1.1s ease}
@keyframes imgin{0%{transform:scale(.82);opacity:0}
 100%{transform:scale(1);opacity:1}}
.splash-mark{position:relative;width:132px;height:132px}
.splash-mark .ring{position:absolute;inset:0;border:2px solid #34d399;
 border-radius:50%;opacity:0;animation:ringpulse 2.2s ease-out infinite}
.splash-mark .r2{animation-delay:.7s}
.splash-mark .r3{animation-delay:1.4s}
@keyframes ringpulse{0%{transform:scale(.55);opacity:.95}
 100%{transform:scale(1.45);opacity:0}}
.splash-mark .core{position:absolute;inset:30px;border-radius:50%;
 background:radial-gradient(circle at 35% 30%,#5fe8a8,#0d8a4e);
 display:flex;align-items:center;justify-content:center;
 font-size:42px;font-weight:800;color:#04120d;
 box-shadow:0 0 44px rgba(52,211,153,.55)}
.splash-name{font-size:36px;font-weight:800;letter-spacing:10px;color:#fff;
 margin-left:10px}
.splash-name span{color:#34d399}
.splash-sub{font-size:10.5px;letter-spacing:3.5px;color:#7fb89a}
.splash-bar{width:230px;height:4px;background:#0e2a1c;border-radius:4px;
 overflow:hidden}
.splash-bar i{display:block;height:100%;width:40%;background:#34d399;
 border-radius:4px;animation:sload 1.1s linear infinite}
@keyframes sload{0%{transform:translateX(-110%)}100%{transform:translateX(600%)}}
"""


def _splash_html():
    if _LOGO_URI:
        mark = ("<img class='splash-img' src='" + _LOGO_URI +
                "' alt='HYDRA logo'>")
    else:
        mark = ("<div class='splash-mark'><div class='ring r1'></div>"
                "<div class='ring r2'></div><div class='ring r3'></div>"
                "<div class='core'>H</div></div>")
    return (
        "<div id='splash'>" + mark +
        "<div class='splash-name'>HYDRA<span>&#9670;</span>SOC</div>"
        "<div class='splash-sub'>SELF-REGENERATING AUTONOMOUS DEFENSE</div>"
        "<div class='splash-bar'><i></i></div></div>"
    )


SPLASH_JS = (
    "<script>(function(){try{var s=document.getElementById('splash');"
    "if(!s)return;"
    "if(sessionStorage.getItem('hydra_splash_seen')){s.style.display='none';"
    "return;}"
    "sessionStorage.setItem('hydra_splash_seen','1');"
    "setTimeout(function(){s.classList.add('hide');"
    "setTimeout(function(){s.style.display='none';},700);},1700);"
    "}catch(e){var x=document.getElementById('splash');"
    "if(x)x.style.display='none';}})();</script>"
    "<noscript><style>#splash{display:none!important}</style></noscript>"
)


def _page(title, body, refresh=True):
    meta = ('<meta http-equiv="refresh" content="' +
            str(REFRESH_SECONDS) + '">') if refresh else ""
    return ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            + meta + "<title>" + _esc(title) + "</title>"
            "<style>" + CSS + SPLASH_CSS + CSS2 + "</style></head>"
            "<body>" + _splash_html() + body + SPLASH_JS +
            "</body></html>")


# --------------------------------------------------------------------------- #
# threat level                                                                #
# --------------------------------------------------------------------------- #
def _threat_level(report):
    if not report:
        return ("UNKNOWN", "tp-unknown",
                "no hunter report yet — run the hunter agent")
    by_sev = (report.get("summary") or {}).get("by_severity") or {}
    high = int(by_sev.get("high", 0) or 0)
    med = int(by_sev.get("medium", 0) or 0)
    if high:
        return ("HIGH", "tp-high",
                "%d high-severity finding(s) need attention" % high)
    if med:
        return ("GUARDED", "tp-guarded",
                "%d medium-severity finding(s) under watch" % med)
    return ("LOW", "tp-low", "no active high/medium findings")


# --------------------------------------------------------------------------- #
# event-volume area chart (emerald SVG, no JS)                                #
# --------------------------------------------------------------------------- #
def _volume_chart(events):
    W, H, PAD = 560, 170, 30
    buckets = [0] * 24
    times = []
    for e in events:
        try:
            times.append(datetime.datetime.fromisoformat(
                str(e.get("timestamp"))))
        except (ValueError, TypeError):
            pass
    if times:
        lo, hi = min(times), max(times)
        span = max((hi - lo).total_seconds(), 1)
        for t in times:
            idx = min(int((t - lo).total_seconds() / span * 23), 23)
            buckets[idx] += 1
    peak = max(buckets) if any(buckets) else 1
    iw, ih = W - 2 * PAD, H - 2 * PAD
    pts = []
    for i, b in enumerate(buckets):
        x = PAD + iw * i / 23
        y = PAD + ih - ih * b / peak
        pts.append((x, y))
    line = "M" + " L".join("%d,%d" % (x, y) for x, y in pts)
    area = (line + " L%d,%d L%d,%d Z" %
            (PAD + iw, PAD + ih, PAD, PAD + ih))
    grid = "".join(
        "<line x1='%d' y1='%d' x2='%d' y2='%d' stroke='#0e2f24' "
        "stroke-width='1'/>" % (PAD, PAD + ih * g / 4, PAD + iw,
                                PAD + ih * g / 4)
        for g in range(5))
    return (
        "<svg viewBox='0 0 %d %d' style='width:100%%;height:auto' "
        "role='img' aria-label='event volume'>%s"
        "<path d='%s' fill='rgba(52,211,153,.16)'/>"
        "<path d='%s' fill='none' stroke='#34d399' stroke-width='2.5'/>"
        "</svg>" % (W, H, grid, area, line))


# --------------------------------------------------------------------------- #
# page sections                                                               #
# --------------------------------------------------------------------------- #
def _topbar():
    logo = ("<img src='" + _LOGO_URI + "' alt='HYDRA'>") if _LOGO_URI else ""
    return (
        "<div class='topbar'>"
        "<div class='brand'>" + logo +
        "<div class='wm'>HYDRA</div></div>"
        "<nav class='topnav'>"
        "<a href='#alerts'>Detect</a><span class='sep'>&#183;</span>"
        "<a href='#threats'>Analyze</a><span class='sep'>&#183;</span>"
        "<a href='#agents'>Respond</a><span class='sep'>&#183;</span>"
        "<a href='#overview'>Defend</a></nav>"
        "<div class='sp'></div>"
        "<div class='soc'><span class='dot'></span>SOC Online</div>"
        "<div class='clock'>" + _esc(_now_utc()) + "</div>"
        "<a href='?viva=1' class='viva-link' title='Viva presentation mode'>"
        "&#128250;</a>"
        "<div class='gear'>&#9881;</div>"
        "</div>")


def _sidebar():
    links = (
        ("#overview", "&#8962;", "Dashboard", True),
        ("#alerts", "&#128737;", "Threat Detection", False),
        ("#logs", "&#128196;", "Log Analysis", False),
        ("#agents", "&#9678;", "AI Agent", False),
        ("#agents", "&#9889;", "Response", False),
        ("#threats", "&#9646;", "Reports", False),
        ("#", "&#9881;", "Settings", False),
    )
    nav = "".join(
        "<a href='" + href + "'" + (" class='on'" if on else "") + ">"
        "<span class='ic'>" + ic + "</span>" + label + "</a>"
        for href, ic, label, on in links)
    return (
        "<aside class='sidebar'><nav class='snav'>" + nav + "</nav>"
        "<div class='stag'>One Head Sees.<br>Many Heads Defend.<br>"
        "<b>HYDRA</b></div></aside>")


def _hero(lvl, lvl_class, why):
    art = ("<img class='hero-art' src='" + _LOGO_URI + "' alt=''>"
           ) if _LOGO_URI else ""
    return (
        "<section class='hero' id='overview'><div class='hero-text'>"
        "<h1>HYDRA</h1>"
        "<div class='hero-sub'>NEXT-GEN AI POWERED SOC</div>"
        "<p class='hero-tag'>Autonomous threat detection,<br>"
        "intelligent analysis,<br>and rapid response.</p>"
        "<span class='threat-pill " + lvl_class + "'><i></i>Threat level: " +
        _esc(lvl) + "</span>"
        "</div>" + art + "</section>")


def _capability_cards():
    cards = (
        ("&#9678;", "DETECT",
         "Hunter finds threats in real-time across your network"),
        ("&#11042;", "ANALYZE",
         "AI-powered correlation of events &amp; threat intelligence"),
        ("&#9889;", "RESPOND",
         "Automated &amp; guided incident response"),
        ("&#11039;", "DEFEND",
         "Deception &amp; self-healing, stronger, always on"),
    )
    return ("<div class='caps'>" + "".join(
        "<div class='cap'><div class='ic'>" + ic + "</div>"
        "<div class='t'>" + t + "</div><div class='d'>" + d + "</div></div>"
        for ic, t, d in cards) + "</div>")


def _system_overview(snapshot, lvl, lvl_class):
    n_events = len(snapshot["events"])
    rep = snapshot["report"] or {}
    n_find = int((rep.get("summary") or {}).get("total", 0) or 0)
    blocked = 0
    for run in (snapshot["responder"] or {}).get("runs", []):
        blocked += sum(1 for a in run.get("actions", []) if a.get("ok"))
    rows = (
        ("&#9646;", "Total Events", str(n_events), ""),
        ("&#9888;", "Detected Threats", str(n_find), ""),
        ("&#128737;", "Blocked Attacks", str(blocked), ""),
        ("&#9678;", "Active Agents", "3 / 3",
         " <small class='ok-txt'>Online</small>"),
        ("&#9670;", "Threat Level",
         "<span class='" + lvl_class + " threat-pill' style='font-size:11px;"
         "padding:5px 12px'><i></i>" + _esc(lvl) + "</span>", ""),
    )
    body = "".join(
        "<div class='srow'><span class='ic'>" + ic + "</span>"
        "<span class='lb'>" + lb + "</span>"
        "<span class='vl'>" + vl + extra + "</span></div>"
        for ic, lb, vl, extra in rows)
    return (
        "<section class='panel' id='system'>"
        "<div class='panel-h'><span class='pt'>&#128737; SYSTEM OVERVIEW</span>"
        "</div>" + body + "</section>")


def _finding_time(finding, timeline):
    src = str(finding.get("source") or "")
    if not src:
        return None
    for ev in timeline:
        det = ev.get("details")
        try:
            blob = json.dumps(det) if isinstance(det, dict) else str(det or "")
        except (TypeError, ValueError):
            blob = ""
        if src in blob:
            return ev.get("timestamp")
    return None


def _recent_alerts(report, timeline, sev):
    pills = "".join(
        "<a class='fpill" + (" on" if k == sev else "") +
        "' href='?sev=" + k + "#alerts'>" + label + "</a>"
        for k, label in (("all", "All"), ("high", "High"),
                         ("medium", "Medium"), ("low", "Low")))
    head = ("<div class='panel-h'><span class='pt'>&#9888; RECENT ALERTS</span>"
            "<div class='sp'></div><div class='fpills'>" + pills + "</div>"
            "</div>")
    findings = ((report or {}).get("findings") or [])
    if sev != "all":
        findings = [f for f in findings
                    if str(f.get("severity", "")).lower() == sev]
    if not findings:
        return head + ("<div class='empty'>No %s findings.<br>"
                       "<b>Hunter is watching.</b></div>"
                       % _esc(sev if sev != "all" else ""))
    rows = []
    for f in findings[:8]:
        s = str(f.get("severity", "info")).lower()
        dot = "ad-" + (s if s in ("high", "medium", "low") else "low")
        rows.append(
            "<div class='alert'><span class='adot " + dot + "'></span>"
            "<div><div class='tt'>" + _esc(f.get("title") or f.get("check")) +
            "</div><div class='src'>" + _esc(f.get("source")) + "</div></div>"
            "<span class='tm'>" +
            _esc(_fmt_hm(_finding_time(f, timeline))) + "</span></div>")
    return ("<section class='panel' id='alerts'>" + head + "".join(rows) +
            "</section>")


def _threat_analysis(events):
    return (
        "<section class='panel' id='threats'>"
        "<div class='panel-h'><span class='pt'>THREAT ANALYSIS</span>"
        "<div class='sp'></div><span class='more'>live window &#9662;</span>"
        "</div>" + _volume_chart(events) + "</section>")


def _log_status(ev):
    et = str(ev.get("event_type", ""))
    sev = str(ev.get("severity") or "").lower()
    if any(k in et for k in ("tarpit", "deceiv", "honeypot")):
        return ("Deceived", "st-deceive")
    if any(k in et for k in ("block", "isolate", "restart", "quarantine")):
        return ("Blocked", "st-block")
    if sev in ("high", "critical"):
        return ("Detected", "st-detect")
    if sev == "medium":
        return ("Detected", "st-warn")
    return ("Logged", "st-info")


def _recent_logs(timeline):
    rows = []
    for ev in timeline[:9]:
        label, cls = _log_status(ev)
        det = ev.get("details") or {}
        src = det.get("src_ip") or det.get("source_ip") or ev.get("agent", "")
        rows.append(
            "<tr><td class='mono'>" + _esc(_fmt_hm(ev.get("timestamp"))) +
            "</td><td class='mono'>" + _esc(src) + "</td>"
            "<td>" + _esc(_humanize(ev.get("event_type"))) + "</td>"
            "<td><span class='st " + cls + "'>" + label + "</span></td></tr>")
    body = ("<table><thead><tr><th>Time</th><th>Source</th><th>Event</th>"
            "<th>Status</th></tr></thead><tbody>" + "".join(rows) +
            "</tbody></table>") if rows else \
        "<div class='empty'>No events yet.<br><b>Run the agents.</b></div>"
    return (
        "<section class='panel' id='logs'>"
        "<div class='panel-h'><span class='pt'>RECENT LOGS</span>"
        "<div class='sp'></div></div>" + body + "</section>")


_ACTIVITY = {
    "scan_completed": "Scan complete",
    "honeypot_login_attempt": "Engaging intruder",
    "honeypot_session": "Deceiving session",
    "tarpit_engaged": "Tarpit engaged",
    "responder_plan": "Planning response",
    "responder_run": "Responding",
    "responder_refusal": "Standing by",
}


def _agent_status(agent_status, events):
    names = (("hunter", "Threat Hunter"), ("deceiver", "Deception Agent"),
             ("responder", "Response Agent"))
    rows = []
    for key, name in names:
        st = (agent_status or {}).get(key, {})
        last_seen = st.get("last_seen")
        on = bool(last_seen)
        activity = "Standby"
        if on:
            last_ev = next((e for e in reversed(events)
                            if e.get("agent") == key), None)
            if last_ev is not None:
                activity = _ACTIVITY.get(
                    str(last_ev.get("event_type")),
                    _humanize(last_ev.get("event_type")))
        rows.append(
            "<div class='astat'><span class='pring " +
            ("p-on" if on else "p-off") + "'></span>"
            "<span class='nm'>" + name + "</span>"
            "<span class='ac'>" + _esc(activity) + "</span></div>")
    return (
        "<section class='panel' id='agents'>"
        "<div class='panel-h'><span class='pt'>&#9678; AI AGENT STATUS</span>"
        "<div class='sp'></div><span class='more'>&#10022; Active</span></div>"
        + "".join(rows) +
        "<div class='aquote'>&ldquo;HYDRA &mdash; MULTI-LAYERED<br>"
        "SECURITY, ONE INTELLIGENCE.&rdquo;</div></section>")


def _footer(report_path):
    return (
        "<div class='footer'><span><b>HYDRA</b> &mdash; Self-Regenerating "
        "Autonomous Defense Architecture</span>"
        "<span>report: <b class='mono'>" + _esc(report_path or "none") +
        "</b></span>"
        "<span>isolated lab &middot; read-only dashboard</span></div>")


# --------------------------------------------------------------------------- #
# full pages                                                                  #
# --------------------------------------------------------------------------- #
def render_dashboard(snapshot, query=None):
    query = query or {}
    if str((query.get("viva") or ["0"])[0]) == "1":
        return _viva_page(snapshot)
    sev = str((query.get("sev") or ["all"])[0]).lower()
    if sev not in ("all", "high", "medium", "low"):
        sev = "all"
    lvl, lvl_class, _why = _threat_level(snapshot["report"])
    body = (
        _topbar() +
        "<div class='layout'>" + _sidebar() + "<main>"
        + _hero(lvl, lvl_class, _why)
        + _capability_cards()
        + _killchain(snapshot)
        + "<div class='cols'><div>"
        + "<div class='duo'>"
        + _threat_analysis(snapshot["events"])
        + _threat_radar((snapshot["report"] or {}).get("findings") or [])
        + "</div>"
        + _network_map(snapshot)
        + _recent_logs(snapshot["timeline"])
        + _terminal(snapshot["timeline"])
        + "</div><div>"
        + _system_overview(snapshot, lvl, lvl_class)
        + _recent_alerts(snapshot["report"], snapshot["timeline"], sev)
        + _agent_status(snapshot["agent_status"], snapshot["events"])
        + "</div></div>"
        + _footer(snapshot["report_path"])
        + "</main></div>"
    )
    return _page("HYDRA — Next-Gen AI Powered SOC", body)


def render_transcript(name, session):
    back = "<a href='/'>&larr; back to dashboard</a>"
    if session is None:
        body = (_topbar() + "<div class='layout'>" + _sidebar() +
                "<main><div class='empty'>Transcript not found.<br>" +
                back + "</div></main></div>")
        return _page("Transcript not found", body, refresh=False)
    cmds = "".join(
        "<div class='mono' style='margin:4px 0'><span style='color:#34d399'>"
        "$</span> " + _esc(c.get("command")) +
        "<div style='color:#7d93a3;white-space:pre-wrap'>" +
        _esc(c.get("output")) + "</div></div>"
        for c in session.get("commands", []))
    logins = "".join(
        "<tr><td class='mono'>" + _esc(_fmt_hm(a.get("timestamp"))) +
        "</td><td class='mono'>" + _esc(a.get("username")) +
        "</td><td>" + ("<span class='st st-block'>ok</span>"
                       if a.get("success")
                       else "<span class='st st-detect'>fail</span>") +
        "</td></tr>"
        for a in session.get("login_attempts", []))
    detail = (
        "<section class='panel'><div class='panel-h'>"
        "<span class='pt'>SESSION " + _esc(name) + "</span></div>"
        "<div class='srow'><span class='lb'>attacker</span>"
        "<span class='vl mono' style='font-size:13px'>" +
        _esc(session.get("src_ip")) + "</span></div>"
        "<div class='srow'><span class='lb'>duration</span>"
        "<span class='vl' style='font-size:13px'>" +
        _esc(session.get("duration_s")) + "s</span></div>"
        "<div class='srow'><span class='lb'>tarpitted</span>"
        "<span class='vl' style='font-size:13px'>" +
        ("yes" if session.get("tarpitted") else "no") + "</span></div>"
        "<div style='margin:14px 0 8px' class='pt'>LOGIN ATTEMPTS</div>"
        "<table><thead><tr><th>Time</th><th>Username</th><th>Result</th></tr>"
        "</thead><tbody>" + (logins or
                             "<tr><td colspan='3'>none</td></tr>") +
        "</tbody></table>"
        "<div style='margin:14px 0 8px' class='pt'>COMMANDS</div>"
        + (cmds or "<div class='empty'>no commands issued</div>") +
        "</section>")
    body = (_topbar() + "<div class='layout'>" + _sidebar() +
            "<main><div style='margin-bottom:12px'>" + back + "</div>" +
            detail + _footer(None) + "</main></div>")
    return _page("Transcript " + str(name), body, refresh=False)


# --------------------------------------------------------------------------- #
# feature pack 2 styles: radar, kill-chain, network map, terminal, viva
# --------------------------------------------------------------------------- #
CSS2 = """/* ---------- threat radar ---------- */
.radar-wrap{display:flex;gap:18px;align-items:center;justify-content:center;
 flex-wrap:wrap}
.radar{position:relative;width:250px;height:250px;flex:none}
.radar .ring{position:absolute;border:1px solid #134233;border-radius:50%}
.radar .r1{inset:0}.radar .r2{inset:32px}.radar .r3{inset:64px}.radar .r4{inset:96px}
.radar .cross{position:absolute;background:#134233}
.radar .ch{left:50%;top:0;bottom:0;width:1px}
.radar .cv{top:50%;left:0;right:0;height:1px}
.radar .sweep{position:absolute;inset:0;border-radius:50%;
 background:conic-gradient(from 0deg,rgba(52,211,153,.55),transparent 70deg);
 animation:sweep 4s linear infinite}
@keyframes sweep{to{transform:rotate(360deg)}}
.radar .blip{position:absolute;width:10px;height:10px;border-radius:50%;
 transform:translate(-50%,-50%);animation:blip 2s ease-out infinite}
@keyframes blip{0%{box-shadow:0 0 0 0 rgba(255,255,255,.25)}
 100%{box-shadow:0 0 0 12px rgba(255,255,255,0)}}
.radar-legend{font-size:12px;color:#7d93a3;line-height:2.2}
.radar-legend i{display:inline-block;width:9px;height:9px;border-radius:50%;
 margin-right:8px}
.radar-legend b{color:#e6f2ec}
/* ---------- kill chain ---------- */
.kc{display:flex;align-items:stretch;gap:6px;overflow-x:auto;padding:6px 2px}
.kc-stage{flex:1;min-width:120px;text-align:center;padding:16px 8px;
 border:1px solid #0e3a2c;border-radius:12px;background:rgba(6,20,16,.6)}
.kc-stage .n{font-size:30px;font-weight:800;color:#fff;
 font-variant-numeric:tabular-nums}
.kc-stage .t{font-size:10.5px;font-weight:800;letter-spacing:1.8px;
 color:#34d399;margin-top:8px}
.kc-stage .d{font-size:11px;color:#5f7a70;margin-top:6px;line-height:1.5}
.kc-stage.dim{opacity:.32}
.kc-arrow{align-self:center;color:#1d5c46;font-size:22px;flex:none;padding:0 2px}
/* ---------- network map ---------- */
.netmap{width:100%;height:auto;display:block}
.netmap .node{fill:#06141d;stroke:#1d5c46;stroke-width:1.5}
.netmap .nlabel{fill:#eafff5;font-size:13px;font-weight:800;text-anchor:middle}
.netmap .iplabel{fill:#5f7a70;font-size:10.5px;text-anchor:middle;
 font-family:ui-monospace,Menlo,monospace}
.netmap .flow{stroke:#f87171;stroke-width:2;stroke-dasharray:9 7;fill:none;
 animation:dashmove 1s linear infinite}
.netmap .idle{stroke:#1d3a30;stroke-width:1.5;stroke-dasharray:5 6;fill:none}
.netmap .ok{stroke:#34d399;stroke-width:2;stroke-dasharray:9 7;fill:none;
 animation:dashmove 1.4s linear infinite}
@keyframes dashmove{to{stroke-dashoffset:-32}}
.netmap .tag{fill:#0a0f0d;font-size:9.5px;font-weight:800;text-anchor:middle;
 letter-spacing:1px}
/* ---------- terminal ---------- */
.term{background:#010503;border:1px solid #0e3a2c;border-radius:12px;
 padding:16px 18px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,
 monospace;font-size:12.5px;line-height:1.9;color:#4ade80;
 background-image:repeating-linear-gradient(0deg,transparent,transparent 2px,
 rgba(0,0,0,.28) 3px);overflow-x:auto}
.term .tp{color:#1d7a55}
.term .tw{color:#eafff5}
.term .tr{color:#f87171}
.term .ta{color:#fbbf24}
.term .cursor{display:inline-block;width:9px;height:15px;background:#4ade80;
 vertical-align:-2px;animation:blink 1s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
/* ---------- viva mode ---------- */
.viva-hero{text-align:center;padding:34px 20px 10px}
.viva-hero img{width:170px;height:170px;border-radius:50%;object-fit:cover;
 box-shadow:0 0 60px rgba(52,211,153,.5)}
.viva-hero h1{font-size:64px;letter-spacing:12px;margin:18px 0 6px;
 background:linear-gradient(180deg,#d9fff0,#34d399 70%,#0d8a4e);
 -webkit-background-clip:text;background-clip:text;color:transparent}
.viva-hero .sub{font-size:15px;letter-spacing:6px;color:#eafff5;font-weight:800}
.viva-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;
 margin:26px 0}
.viva-kpi{background:rgba(6,20,16,.75);border:1px solid #0e3a2c;
 border-radius:14px;padding:26px 12px;text-align:center}
.viva-kpi .n{font-size:52px;font-weight:800;color:#fff}
.viva-kpi .k{font-size:12px;letter-spacing:2px;color:#34d399;font-weight:800;
 margin-top:10px}
.viva-back{display:inline-block;margin:6px 0 18px;font-size:13px}
@media(max-width:900px){.viva-kpis{grid-template-columns:1fr 1fr}
 .viva-hero h1{font-size:40px}}
.viva-link{color:#34d399;font-size:15px;text-decoration:none;
 border:1px solid #134233;border-radius:8px;padding:4px 10px}
.viva-link:hover{border-color:#34d399;background:rgba(52,211,153,.08);
 text-decoration:none}
"""

# --------------------------------------------------------------------------- #
# feature pack 2 builders: radar, kill-chain, network map, terminal, viva     #
# --------------------------------------------------------------------------- #


def _count_blocked(snapshot):
    n = 0
    for run in (snapshot["responder"] or {}).get("runs", []):
        n += sum(1 for a in run.get("actions", []) if a.get("ok"))
    return n


def _threat_radar(findings):
    """Radar sweep with a blip per finding (radius = severity). Real data."""
    blips = []
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in (findings or [])[:14]:
        sev = str(f.get("severity", "")).lower()
        if sev == "high":
            band, color = (0.24, 0.40), "#f87171"
        elif sev == "medium":
            band, color = (0.52, 0.66), "#fbbf24"
        else:
            sev = "low"
            band, color = (0.76, 0.90), "#34d399"
        counts[sev] += 1
        key = (str(f.get("source", "")) + str(f.get("check", "")) +
               str(f.get("title", "")))
        h = abs(hash(key))
        ang = (h % 360) * math.pi / 180
        r = band[0] + ((h // 360) % 100) / 100.0 * (band[1] - band[0])
        x = 50 + r * 50 * math.cos(ang)
        y = 50 + r * 50 * math.sin(ang)
        blips.append(
            "<span class='blip' style='left:" + ("%.1f" % x) +
            "%;top:" + ("%.1f" % y) + "%;background:" + color +
            "' title='" + _esc(f.get("title") or f.get("check")) + "'></span>")
    radar = (
        "<div class='radar'><div class='ring r1'></div>"
        "<div class='ring r2'></div><div class='ring r3'></div>"
        "<div class='ring r4'></div>"
        "<div class='cross ch'></div><div class='cross cv'></div>"
        "<div class='sweep'></div>" + "".join(blips) + "</div>")
    legend = (
        "<div class='radar-legend'>"
        "<div><i style='background:#f87171'></i>High — <b>" +
        str(counts["high"]) + "</b> <span style='color:#5f7a70'>(inner)</span></div>"
        "<div><i style='background:#fbbf24'></i>Medium — <b>" +
        str(counts["medium"]) + "</b></div>"
        "<div><i style='background:#34d399'></i>Low — <b>" +
        str(counts["low"]) + "</b> <span style='color:#5f7a70'>(outer)</span></div>"
        "<div style='margin-top:8px;color:#5f7a70;font-size:11.5px'>"
        "closer to center = more severe</div></div>")
    inner = ("<div class='empty'>No findings on radar.<br><b>Hunter is "
             "watching.</b></div>" if not blips else
             "<div class='radar-wrap'>" + radar + legend + "</div>")
    return (
        "<section class='panel'><div class='panel-h'>"
        "<span class='pt'>&#9678; THREAT RADAR</span></div>" + inner +
        "</section>")


def _killchain(snapshot):
    """Attack story in 5 stages, every number from the real snapshot."""
    findings = ((snapshot["report"] or {}).get("findings") or [])

    def is_recon(f):
        blob = (str(f.get("check", "")) + " " +
                str(f.get("title", ""))).lower()
        return any(k in blob for k in ("scan", "probe", "recon"))

    hp = snapshot["honeypot"] or {}
    resp = snapshot["responder"] or {}
    actions = [a for r in resp.get("runs", []) for a in r.get("actions", [])]
    stages = (
        ("RECON", sum(1 for f in findings if is_recon(f)),
         "threats spotted by Hunter"),
        ("INTRUSION", int(hp.get("attempts", 0) or 0),
         "attacker login attempts"),
        ("DECEPTION", int(hp.get("sessions", 0) or 0),
         "sessions trapped & tarpitted"),
        ("RESPONSE", len(actions), "responder actions executed"),
        ("HEALED", sum(1 for a in actions
                       if a.get("ok") and "restart" in str(a.get("action", ""))),
         "containers self-healed"),
    )
    parts = []
    for i, (title, count, desc) in enumerate(stages):
        if i:
            parts.append("<div class='kc-arrow'>&#10148;</div>")
        parts.append(
            "<div class='kc-stage" + ("" if count else " dim") + "'>"
            "<div class='n'>" + str(count) + "</div>"
            "<div class='t'>" + title + "</div>"
            "<div class='d'>" + desc + "</div></div>")
    return (
        "<section class='panel'><div class='panel-h'>"
        "<span class='pt'>&#128279; KILL-CHAIN — ATTACK STORY</span></div>"
        "<div class='kc'>" + "".join(parts) + "</div></section>")


def _network_map(snapshot):
    """The isolated lab: attacker -> honeypot -> victim, live flow."""
    hp = snapshot["honeypot"] or {}
    per_ip = hp.get("per_ip") or []
    attacker_ip = str(per_ip[0][0]) if per_ip else "awaiting contact"
    attempts = int(hp.get("attempts", 0) or 0)
    flow_label = ("ATTACK x" + str(attempts)) if attempts else "LISTENING"

    def node(x, color, name, ip):
        return (
            "<circle cx='" + str(x) + "' cy='118' r='40' class='node' "
            "style='stroke:" + color + "'/>"
            "<text x='" + str(x) + "' y='123' class='nlabel'>" + name +
            "</text>"
            "<text x='" + str(x) + "' y='182' class='iplabel'>" +
            _esc(ip) + "</text>")

    svg = (
        "<svg class='netmap' viewBox='0 0 620 210' role='img' "
        "aria-label='lab network map'>"
        "<line x1='132' y1='118' x2='268' y2='118' class='flow'/>"
        "<line x1='352' y1='118' x2='488' y2='118' class='idle'/>"
        "<text x='200' y='96' class='tag' fill='#f87171'>" +
        _esc(flow_label) + "</text>"
        "<text x='420' y='96' class='tag' fill='#5f7a70'>ISOLATED</text>"
        + node(90, "#f87171", "ATTACKER", attacker_ip)
        + node(310, "#fbbf24", "HONEYPOT", "172.28.0.12")
        + node(530, "#34d399", "VICTIM", "172.28.0.10")
        + "</svg>")
    return (
        "<section class='panel' id='netmap'><div class='panel-h'>"
        "<span class='pt'>&#127760; LAB NETWORK MAP</span>"
        "<div class='sp'></div>"
        "<span class='more'>172.28.0.0/24 isolated</span></div>"
        + svg + "</section>")


def _terminal(timeline):
    """Hacker-terminal style live feed of the newest events."""
    lines = []
    for ev in (timeline or [])[:10]:
        sev = str(ev.get("severity") or "info").lower()
        cls = ("tr" if sev in ("high", "critical")
               else "ta" if sev == "medium" else "tw")
        lines.append(
            "<div><span class='tp'>[" + _esc(_fmt_hm(ev.get("timestamp"))) +
            "]</span> <span class='tw'>" + _esc(ev.get("agent")) +
            "</span> :: <span class='" + cls + "'>" +
            _esc(_humanize(ev.get("event_type"))) + "</span></div>")
    if not lines:
        lines.append("<div><span class='tp'>$</span> waiting for events...</div>")
    return (
        "<section class='panel'><div class='panel-h'>"
        "<span class='pt'>&#128187; LIVE TERMINAL FEED</span></div>"
        "<div class='term'>" + "".join(lines) +
        "<div><span class='tp'>$</span> <span class='cursor'></span></div>"
        "</div></section>")


def _viva_page(snapshot):
    """One-click presentation view for demo day. Big, simple, story-first."""
    rep = snapshot["report"] or {}
    n_find = int((rep.get("summary") or {}).get("total", 0) or 0)
    n_events = len(snapshot["events"])
    attempts = int((snapshot["honeypot"] or {}).get("attempts", 0) or 0)
    blocked = _count_blocked(snapshot)
    logo = ("<img src='" + _LOGO_URI + "' alt='HYDRA'>") if _LOGO_URI else ""
    kpis = (("TOTAL EVENTS", n_events), ("THREATS DETECTED", n_find),
            ("ATTACK ATTEMPTS", attempts), ("ATTACKS BLOCKED", blocked))
    kpi_html = "".join(
        "<div class='viva-kpi'><div class='n'>" + str(v) + "</div>"
        "<div class='k'>" + k + "</div></div>" for k, v in kpis)
    body = (
        "<main style='max-width:1180px;margin:0 auto'>"
        "<a class='viva-back' href='/'>&larr; exit viva mode</a>"
        "<div class='viva-hero'>" + logo + "<h1>HYDRA</h1>"
        "<div class='sub'>NEXT-GEN AI POWERED SOC</div></div>"
        "<div class='viva-kpis'>" + kpi_html + "</div>"
        + _killchain(snapshot)
        + "<div class='duo'>"
        + _threat_radar(rep.get("findings") or [])
        + _agent_status(snapshot["agent_status"], snapshot["events"])
        + "</div>"
        + _footer(snapshot["report_path"])
        + "</main>")
    return _page("HYDRA — Viva Mode", body)



# =========================================================================== #
# WEB SERVER                                                                  #
# =========================================================================== #
class DashboardHandler(BaseHTTPRequestHandler):
    # Keep the console quiet: the dashboard is read-only furniture, not
    # something that needs its own log spam. (We also deliberately avoid
    # importing the stdlib `logging` module — the repo has its own
    # `logging` package and that import would find it instead.)
    def log_message(self, *args):
        pass

    def _send(self, code, body, content_type="text/html; charset=utf-8"):
        encoded = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/summary":
                self._serve_api()
            elif parsed.path == "/transcript":
                self._serve_transcript(parse_qs(parsed.query))
            elif parsed.path in ("/", "/index.html"):
                self._serve_dashboard(parse_qs(parsed.query))
            else:
                self._send(404, "<h1>404</h1><p><a href='/'>dashboard</a></p>")
        except (BrokenPipeError, ConnectionResetError):
            pass  # browser went away mid-refresh — normal, ignore

    def _serve_dashboard(self, query):
        snapshot = build_snapshot()
        self._send(200, render_dashboard(snapshot, query))

    def _serve_transcript(self, query):
        name = (query.get("file") or [None])[0]
        session = load_transcript(name)
        code = 200 if session is not None else 404
        self._send(code, render_transcript(name or "?", session))

    def _serve_api(self):
        snapshot = build_snapshot()
        summary = {
            "agents": snapshot["agent_status"],
            "latest_report": snapshot["report_path"],
            "findings_total": ((snapshot["report"] or {}).get("summary") or {})
                               .get("total", 0),
            "honeypot": {
                "login_attempts": snapshot["honeypot"]["attempts"],
                "unique_attacker_ips": snapshot["honeypot"]["unique_ips"],
                "sessions_trapped": snapshot["honeypot"]["sessions"],
                "tarpit_adaptations":
                    snapshot["honeypot"]["adaptations"],
            },
            "playbook_runs": len(snapshot["responder"]["runs"]),
            "events_in_log": len(snapshot["events"]),
        }
        self._send(200, json.dumps(summary, indent=2),
                   "application/json; charset=utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="HYDRA SOC dashboard — read-only system view.")
    parser.add_argument("--port", type=int, default=8080,
                        help="port to listen on (default 8080)")
    parser.add_argument("--bind", default="127.0.0.1",
                        help="interface to bind (default 127.0.0.1)")
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer((args.bind, args.port), DashboardHandler)
    open_host = "127.0.0.1" if args.bind == "0.0.0.0" else args.bind
    url = "http://{0}:{1}".format(open_host, args.port)
    print("HYDRA SOC dashboard at {0}  (Ctrl+C to stop)".format(url))
    print("Read-only: serves logs/ and findings/, never touches containers.")
    print("Opening your browser ...")
    threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
