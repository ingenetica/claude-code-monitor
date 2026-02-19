#!/usr/bin/env python3
"""
claude-monitor: Visualize running Claude Code instances and their current activity.
Usage:
    claude-monitor          Watch mode (auto-refresh every 2s, default)
    claude-monitor -w 5     Watch mode with custom interval (seconds)
    claude-monitor --once   One-shot display
"""

import json
import os
import subprocess
import sys
import glob
import signal
import time
import shutil
import urllib.request
import urllib.error
from datetime import datetime, timezone


CLAUDE_DIR = os.path.expanduser("~/.claude")
PROJECTS_DIR = os.path.join(CLAUDE_DIR, "projects")

# ANSI
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
WHITE = "\033[97m"
GRAY = "\033[90m"
BLUE = "\033[34m"
RED = "\033[31m"
CLEAR_SCREEN = "\033[2J\033[H"
HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"

# Claude Code "clawd" startup icon (exact from CLI source)
CLAWD = [
    " ▐▛███▜▌ ",
    "▝▜█████▛▘",
    "  ▘▘ ▝▝  ",
]
CLAWD_W = 9  # visible width of the icon

# Icon colors per state
PURPLE = "\033[38;2;124;58;237m"       # Active – Claude purple (#7C3AED)
ORANGE = "\033[38;2;215;119;87m"       # Inactive – clawd_body rgb(215,119,87)
ICON_GREEN = "\033[38;2;74;222;128m"   # Subprocess – green

# Rate limit display
USAGE_WARN_THRESHOLD = 0.50   # yellow
USAGE_DANGER_THRESHOLD = 0.80 # red
USAGE_REFRESH_INTERVAL = 60   # seconds between API calls

BAR_FILLED = "█"
BAR_EMPTY = "░"
BAR_WIDTH = 30

PLAN_DISPLAY_NAMES = {
    "free": "Free",
    "pro": "Pro ($20/mo)",
    "max": "Max 5x ($100/mo)",
    "max_20x": "Max 20x ($200/mo)",
}
TIER_DISPLAY_NAMES = {
    "default_claude_max_5x": "Max 5x",
    "default_claude_max_20x": "Max 20x",
    "default_claude_pro": "Pro",
    "default_claude_free": "Free",
}

# Caches
_usage_cache = {"value": None, "time": 0}
_creds_cache = {"value": None, "time": 0}


def get_terminal_size():
    return shutil.get_terminal_size((80, 24))


def get_claude_processes():
    """Find all running claude CLI processes, including subprocess/SDK instances."""
    try:
        result = subprocess.run(
            ["ps", "axo", "pid,ppid,tty,lstart,etime,command"],
            capture_output=True, text=True,
        )
        processes = []
        for line in result.stdout.strip().split("\n")[1:]:
            if "claude" not in line or "Claude.app" in line or "Helper" in line:
                continue
            if "grep" in line or "claude-monitor" in line:
                continue
            parts = line.split()
            if len(parts) < 9:
                continue
            pid = parts[0]
            ppid = parts[1]
            tty = parts[2]
            lstart_str = " ".join(parts[3:8])
            etime = parts[8]
            cmd = " ".join(parts[9:])
            cmd_stripped = cmd.strip()
            # Match claude invocations: "claude", "/path/to/claude", "node /path/to/claude"
            words = cmd_stripped.split()[:3] if cmd_stripped else []
            is_claude = any(os.path.basename(w) == "claude" for w in words)
            # Match: node running claude-code CLI (SDK/subprocess)
            if not is_claude and "claude-code" in cmd_stripped:
                is_claude = True
            if not is_claude:
                continue
            try:
                start_time = datetime.strptime(lstart_str, "%a %b %d %H:%M:%S %Y")
            except ValueError:
                start_time = None
            # Detect if it's a background/subprocess instance
            is_interactive = tty != "??"
            # Extract flags for subprocess identification
            is_print_mode = "--print" in cmd_stripped or " -p " in cmd_stripped
            # Identify parent app
            parent_app = None
            if not is_interactive:
                parent_app = _identify_parent(ppid)
            processes.append({
                "pid": pid,
                "ppid": ppid,
                "tty": tty,
                "start_time": start_time,
                "etime": etime.strip(),
                "cmd": cmd_stripped,
                "interactive": is_interactive,
                "print_mode": is_print_mode,
                "parent_app": parent_app,
            })
        return processes
    except Exception as e:
        print(f"Error getting processes: {e}", file=sys.stderr)
        return []


def _identify_parent(ppid):
    """Try to identify what app spawned a subprocess claude instance."""
    try:
        result = subprocess.run(
            ["ps", "-p", ppid, "-o", "command="],
            capture_output=True, text=True,
        )
        cmd = result.stdout.strip()
        if "Nexus" in cmd or "nexus" in cmd:
            return "Nexus"
        if "Electron" in cmd or "electron" in cmd:
            return "Electron"
        if "node" in cmd:
            return "Node"
        if cmd:
            return os.path.basename(cmd.split()[0])[:20]
    except Exception:
        pass
    return None


def find_project_dirs():
    project_dirs = []
    projects_base = os.path.join(CLAUDE_DIR, "projects")
    if os.path.isdir(projects_base):
        for entry in os.listdir(projects_base):
            full = os.path.join(projects_base, entry)
            if os.path.isdir(full):
                project_dirs.append(full)
    return project_dirs


def get_active_sessions(project_dirs, num_processes):
    all_files = []
    for pdir in project_dirs:
        for f in glob.glob(os.path.join(pdir, "*.jsonl")):
            mtime = os.path.getmtime(f)
            all_files.append((f, mtime))
    all_files.sort(key=lambda x: x[1], reverse=True)
    return all_files[: max(num_processes + 4, 8)]


def parse_iso_timestamp(ts_str):
    if not ts_str:
        return None
    try:
        ts_str = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_str)
        return dt.replace(tzinfo=None)
    except (ValueError, TypeError):
        return None


def extract_session_info(filepath):
    info = {
        "session_id": os.path.basename(filepath).replace(".jsonl", ""),
        "filepath": filepath,
        "cwd": None,
        "first_prompt": None,
        "first_timestamp": None,
        "last_prompt": None,
        "last_tool_use": None,
        "last_assistant_text": None,
        "message_count": 0,
        "project_path": os.path.basename(os.path.dirname(filepath)),
    }

    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
    except Exception:
        return info

    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        info["cwd"] = obj.get("cwd", info["cwd"])

        if obj.get("type") == "user":
            msg = obj.get("message", {})
            if not isinstance(msg, dict):
                continue
            content = msg.get("content", "")
            text = None
            if isinstance(content, str) and content.strip():
                text = content.strip()
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        t = block.get("text", "").strip()
                        if t:
                            text = t
                            break
            if text:
                if info["first_prompt"] is None:
                    info["first_prompt"] = text
                    info["first_timestamp"] = parse_iso_timestamp(
                        obj.get("timestamp")
                    )
                info["last_prompt"] = text
                info["message_count"] += 1

        elif obj.get("type") == "assistant":
            msg = obj.get("message", {})
            if not isinstance(msg, dict):
                continue
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_use":
                        name = block.get("name", "")
                        inp = block.get("input", {})
                        if not isinstance(inp, dict):
                            inp = {}
                        detail = ""
                        if "command" in inp:
                            detail = inp["command"][:50]
                        elif "file_path" in inp:
                            detail = os.path.basename(inp["file_path"])
                        elif "pattern" in inp:
                            detail = inp["pattern"][:50]
                        elif "prompt" in inp:
                            detail = inp["prompt"][:50]
                        elif "query" in inp:
                            detail = inp["query"][:50]
                        elif "skill" in inp:
                            detail = inp["skill"]
                        info["last_tool_use"] = (
                            f"{name}" + (f" -> {detail}" if detail else "")
                        )
                    elif block.get("type") == "text":
                        t = block.get("text", "").strip()
                        if t:
                            info["last_assistant_text"] = t

    return info


def match_pid_to_session(process, sessions_info):
    if not process["start_time"]:
        return None
    best_match = None
    best_diff = None
    for sinfo in sessions_info:
        if sinfo["first_timestamp"] is None:
            continue
        diff = (sinfo["first_timestamp"] - process["start_time"]).total_seconds()
        if -5 < diff < 300:
            if best_diff is None or abs(diff) < abs(best_diff):
                best_diff = diff
                best_match = sinfo
    return best_match


def get_lock_sessions():
    locks = set()
    tasks_dir = os.path.join(CLAUDE_DIR, "tasks")
    if os.path.isdir(tasks_dir):
        for entry in os.listdir(tasks_dir):
            lock_path = os.path.join(tasks_dir, entry, ".lock")
            if os.path.isfile(lock_path):
                locks.add(entry)
    return locks


def truncate(text, max_len):
    if not text:
        return ""
    text = text.replace("\n", " ").strip()
    if len(text) > max_len:
        return text[: max_len - 1] + "…"
    return text


def format_uptime(etime_str):
    """Convert ps etime to a human-friendly string."""
    e = etime_str.strip()
    # formats: MM:SS, HH:MM:SS, D-HH:MM:SS
    if "-" in e:
        days, rest = e.split("-", 1)
        parts = rest.split(":")
        return f"{days}d {parts[0]}h"
    parts = e.split(":")
    if len(parts) == 3:
        h, m, _ = parts
        return f"{int(h)}h {int(m)}m"
    if len(parts) == 2:
        m, s = parts
        return f"{int(m)}m {int(s)}s"
    return e


def get_status_icon(session, locked_sessions):
    """Return (icon_str, ago_seconds) for a session."""
    is_locked = session and session["session_id"] in locked_sessions
    if is_locked:
        return f"{GREEN}●{RESET}", 0, True
    if session:
        mtime = os.path.getmtime(session["filepath"])
        ago = time.time() - mtime
        if ago < 60:
            return f"{GREEN}●{RESET}", ago, False
        elif ago < 300:
            return f"{YELLOW}◐{RESET}", ago, False
        else:
            return f"{DIM}○{RESET}", ago, False
    return f"{DIM}○{RESET}", 0, False


def format_status_text(ago, is_locked):
    if is_locked:
        return f"{GREEN}Processing…{RESET}"
    if ago < 60:
        return f"{GREEN}Active ({int(ago)}s ago){RESET}"
    elif ago < 300:
        return f"{YELLOW}Idle ({int(ago / 60)}m {int(ago % 60)}s){RESET}"
    else:
        return f"{DIM}Waiting ({int(ago / 60)}m){RESET}"


def build_output(processes, sessions_info, locked_sessions, results, term_width, term_height, usage_data=None):
    """Build the full display string."""
    buf = []
    now_str = datetime.now().strftime("%H:%M:%S")
    max_w = min(term_width, 100)
    n = len(results)
    pad = CLAWD_W + 3  # icon width + gap
    info_w = max_w - pad - 2  # available width for info text

    buf.append("")
    title = f"  {BOLD}{WHITE}Claude Monitor{RESET}  {DIM}{n} instance{'s' if n != 1 else ''}{RESET}  {DIM}{now_str}{RESET}"
    buf.append(title)

    # Plan & usage bars (above instances)
    if usage_data:
        buf.append(f"  {DIM}{'─' * (max_w - 2)}{RESET}")
        plan_lines = build_plan_section(
            usage_data["creds"], usage_data["rate_limits"], max_w
        )
        buf.extend(plan_lines)

    buf.append(f"  {DIM}{'─' * (max_w - 2)}{RESET}")

    if not processes:
        buf.append(f"\n  {DIM}No running Claude Code instances found.{RESET}\n")
        return "\n".join(buf)

    for idx, (proc, session) in enumerate(results, 1):
        pid = proc["pid"]
        tty = proc["tty"]
        uptime = format_uptime(proc["etime"])
        icon, ago, is_locked = get_status_icon(session, locked_sessions)
        status_text = format_status_text(ago, is_locked)

        # Build instance type label and pick icon color
        is_interactive = proc.get("interactive", True)
        parent_app = proc.get("parent_app")
        if not is_interactive:
            # Subprocess: green icon
            src = parent_app or "subprocess"
            type_label = f"{ICON_GREEN}{src}{RESET} {DIM}(--print){RESET}"
            icon_color = ICON_GREEN
        elif ago < 60 or is_locked:
            # Active: purple icon
            type_label = f"{tty}"
            icon_color = PURPLE
        else:
            # Inactive: orange icon
            type_label = f"{tty}"
            icon_color = ORANGE

        # Build 4 right-side info lines to pair with the 4 clawd icon lines
        right = []
        right.append(
            f"{icon} {BOLD}{WHITE}Instance {idx}{RESET}  "
            f"{DIM}PID {pid}  {type_label}  {uptime}{RESET}"
        )
        if session:
            prompt = truncate(session["last_prompt"], info_w - 10)
            tool = truncate(session["last_tool_use"], info_w - 10)
            right.append(f"{CYAN}Prompt:{RESET}  {prompt}" if prompt else "")
            right.append(f"{MAGENTA}Tool:{RESET}    {tool}" if tool else "")
            right.append(f"{BOLD}Status:{RESET}  {status_text}")
        elif not is_interactive:
            cmd_info = truncate(proc.get("cmd", ""), info_w - 10)
            right.append(f"{CYAN}Cmd:{RESET}     {cmd_info}")
            right.append("")
            right.append(f"{BOLD}Status:{RESET}  {ICON_GREEN}Running{RESET}")
        else:
            right.append(f"{DIM}(no session){RESET}")
            right.append("")
            right.append("")

        # Render icon + info side by side
        buf.append("")
        num_lines = max(len(CLAWD), len(right))
        for i in range(num_lines):
            clawd_line = CLAWD[i] if i < len(CLAWD) else " " * CLAWD_W
            info_line = right[i] if i < len(right) else ""
            buf.append(f"  {icon_color}{clawd_line}{RESET}  {info_line}")

    buf.append("")
    buf.append(f"  {DIM}{'─' * (max_w - 2)}{RESET}")
    buf.append(
        f"  {PURPLE}▐▌{RESET} {DIM}Active{RESET}  "
        f"{ORANGE}▐▌{RESET} {DIM}Idle{RESET}  "
        f"{ICON_GREEN}▐▌{RESET} {DIM}Subprocess{RESET}  "
        f"{DIM}  Ctrl+C to exit{RESET}"
    )
    buf.append("")

    return "\n".join(buf)


def get_credentials():
    """Get Claude credentials from macOS Keychain. Cached for 5 min."""
    now = time.time()
    if _creds_cache["value"] is not None and now - _creds_cache["time"] < 300:
        return _creds_cache["value"]

    creds = None
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", "Claude Code-credentials", "-w"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout.strip())
            oauth = data.get("claudeAiOauth", {})
            creds = {
                "access_token": oauth.get("accessToken"),
                "subscription_type": oauth.get("subscriptionType", "pro"),
                "rate_limit_tier": oauth.get("rateLimitTier", ""),
                "org_id": data.get("claudeAiOauth", {}).get("organizationUuid", ""),
            }
    except Exception:
        pass

    if creds is None:
        # Fallback: read from statsig
        plan = "pro"
        statsig_dir = os.path.join(CLAUDE_DIR, "statsig")
        try:
            for f in glob.glob(os.path.join(statsig_dir, "statsig.failed_logs.*")):
                with open(f, "r") as fh:
                    data = json.load(fh)
                entries = data if isinstance(data, list) else [data]
                for entry in entries:
                    st = entry.get("user", {}).get("custom", {}).get("subscriptionType")
                    if st:
                        plan = st
                        break
        except Exception:
            pass
        creds = {"access_token": None, "subscription_type": plan, "rate_limit_tier": "", "org_id": ""}

    _creds_cache["value"] = creds
    _creds_cache["time"] = now
    return creds


def fetch_rate_limits(access_token):
    """Make a minimal API call to get real rate limit utilization headers. Cached 60s."""
    now = time.time()
    if _usage_cache["value"] is not None and now - _usage_cache["time"] < USAGE_REFRESH_INTERVAL:
        return _usage_cache["value"]

    result = {
        "5h_utilization": None, "7d_utilization": None,
        "5h_status": None, "7d_status": None,
        "5h_reset": None, "7d_reset": None,
        "overage_status": None, "fallback_pct": None,
        "representative_claim": None,
        "error": None,
    }

    if not access_token:
        result["error"] = "no token"
        _usage_cache["value"] = result
        _usage_cache["time"] = now
        return result

    headers = None
    try:
        body = json.dumps({
            "model": "claude-3-5-haiku-latest",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "x"}],
        }).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers={
            "Authorization": f"Bearer {access_token}",
            "anthropic-version": "2023-06-01",
            "anthropic-beta": "oauth-2025-04-20",
            "content-type": "application/json",
        })
        resp = urllib.request.urlopen(req, timeout=10)
        headers = resp.headers
    except urllib.error.HTTPError as e:
        headers = e.headers
        if e.code == 429:
            result["error"] = "rate-limited"
        else:
            result["error"] = f"HTTP {e.code}"
    except Exception as ex:
        result["error"] = str(ex)[:40]
        _usage_cache["value"] = result
        _usage_cache["time"] = now
        return result

    if headers is not None:
        def hdr(name):
            return headers.get(f"anthropic-ratelimit-unified-{name}")

        try:
            v = hdr("5h-utilization")
            result["5h_utilization"] = float(v) if v else None
        except (TypeError, ValueError):
            pass
        try:
            v = hdr("7d-utilization")
            result["7d_utilization"] = float(v) if v else None
        except (TypeError, ValueError):
            pass
        result["5h_status"] = hdr("5h-status")
        result["7d_status"] = hdr("7d-status")
        try:
            v = hdr("5h-reset")
            result["5h_reset"] = int(v) if v else None
        except (TypeError, ValueError):
            pass
        try:
            v = hdr("7d-reset")
            result["7d_reset"] = int(v) if v else None
        except (TypeError, ValueError):
            pass
        result["overage_status"] = hdr("overage-status")
        try:
            v = hdr("fallback-percentage")
            result["fallback_pct"] = float(v) if v else None
        except (TypeError, ValueError):
            pass
        result["representative_claim"] = hdr("representative-claim")

    _usage_cache["value"] = result
    _usage_cache["time"] = now
    return result


def format_reset_time(reset_ts):
    """Format a unix timestamp as human-readable relative/absolute time."""
    if not reset_ts:
        return ""
    now = time.time()
    dt = datetime.fromtimestamp(reset_ts)
    diff = reset_ts - now
    if diff <= 0:
        return "now"
    if diff < 3600:
        return f"{int(diff / 60)}m"
    if diff < 86400:
        return f"{int(diff / 3600)}h {int((diff % 3600) / 60)}m"
    return dt.strftime("%a %H:%M")


def build_usage_bar(utilization, bar_w, label, reset_ts=None, status=None):
    """Build a single usage bar line."""
    if utilization is None:
        return f"  {label}  {DIM}(no data){RESET}"

    ratio = min(utilization, 1.0)
    pct = int(ratio * 100)

    if ratio >= USAGE_DANGER_THRESHOLD:
        color = RED
    elif ratio >= USAGE_WARN_THRESHOLD:
        color = YELLOW
    else:
        color = GREEN

    filled = int(ratio * bar_w)
    empty = bar_w - filled
    bar = f"{color}{BAR_FILLED * filled}{RESET}{DIM}{BAR_EMPTY * empty}{RESET}"
    avail = 100 - pct

    parts = f"  {label}  [{bar}] {color}{pct:>3}%{RESET}  {DIM}{avail}% free{RESET}"
    if reset_ts:
        parts += f"  {DIM}Reset: {format_reset_time(reset_ts)}{RESET}"
    if status and status != "allowed":
        parts += f"  {RED}{BOLD}● {status}{RESET}"
    return parts


def build_plan_section(creds, rate_limits, max_w):
    """Build the plan info + usage bars section."""
    lines = []

    # Plan display name
    sub = creds.get("subscription_type", "pro")
    plan_name = PLAN_DISPLAY_NAMES.get(sub, sub.title())
    tier = creds.get("rate_limit_tier", "")
    tier_name = TIER_DISPLAY_NAMES.get(tier, "")

    # Status indicator
    status_5h = rate_limits.get("5h_status")
    status_7d = rate_limits.get("7d_status")
    overage = rate_limits.get("overage_status")
    if status_5h == "allowed" and status_7d == "allowed":
        status_icon = f"{GREEN}●{RESET}"
        status_text = f"{GREEN}Allowed{RESET}"
    elif status_5h == "rate-limited" or status_7d == "rate-limited":
        status_icon = f"{RED}●{RESET}"
        status_text = f"{RED}Rate Limited{RESET}"
    else:
        status_icon = f"{YELLOW}●{RESET}"
        status_text = f"{YELLOW}Unknown{RESET}"

    # Header
    header = f" Plan: {plan_name} "
    if tier_name and tier_name not in plan_name:
        header += f"({tier_name}) "
    dashes = max_w - 4 - len(header) - 12  # leave room for status
    if dashes < 0:
        dashes = 0
    lines.append(f"  {DIM}──{RESET}{BOLD}{WHITE}{header}{RESET}{DIM}{'─' * dashes}{RESET}  {status_icon} {status_text}")

    # Usage bars
    bar_w = min(BAR_WIDTH, max_w - 40)
    lines.append(build_usage_bar(
        rate_limits.get("5h_utilization"), bar_w, f"{CYAN}5h Window{RESET}",
        rate_limits.get("5h_reset"), status_5h,
    ))
    lines.append(build_usage_bar(
        rate_limits.get("7d_utilization"), bar_w, f"{BLUE}7d Window{RESET}",
        rate_limits.get("7d_reset"), status_7d,
    ))

    # Warning lines
    representative = rate_limits.get("representative_claim")
    u5 = rate_limits.get("5h_utilization") or 0
    u7 = rate_limits.get("7d_utilization") or 0
    peak = max(u5, u7)
    if peak >= USAGE_DANGER_THRESHOLD:
        window = "5h" if u5 >= u7 else "7d"
        lines.append(f"  {RED}{BOLD}⚠ Approaching {window} rate limit – responses may be slower or use fallback models{RESET}")
    elif overage == "rejected":
        lines.append(f"  {DIM}Overage: disabled (org policy){RESET}")

    # Error from API
    err = rate_limits.get("error")
    if err and rate_limits.get("5h_utilization") is None:
        lines.append(f"  {DIM}API: {err}{RESET}")

    return lines


def collect_data():
    """Gather all data and return (processes, sessions_info, locked_sessions, results, token_data)."""
    processes = get_claude_processes()
    project_dirs = find_project_dirs()
    active_files = get_active_sessions(project_dirs, len(processes))
    locked_sessions = get_lock_sessions()

    sessions_info = []
    for filepath, mtime in active_files:
        sinfo = extract_session_info(filepath)
        sinfo["mtime"] = mtime
        sessions_info.append(sinfo)

    matched = set()
    results = []
    for proc in processes:
        session = match_pid_to_session(
            proc, [s for s in sessions_info if s["session_id"] not in matched]
        )
        if session:
            matched.add(session["session_id"])
        results.append((proc, session))

    unmatched_sessions = [
        s for s in sessions_info if s["session_id"] not in matched
    ]
    for i, (proc, session) in enumerate(results):
        if session is None and unmatched_sessions:
            results[i] = (proc, unmatched_sessions.pop(0))
            matched.add(results[i][1]["session_id"])

    # Rate limit data from API
    creds = get_credentials()
    rate_limits = fetch_rate_limits(creds.get("access_token"))
    usage_data = {"creds": creds, "rate_limits": rate_limits}

    return processes, sessions_info, locked_sessions, results, usage_data


def run_once():
    processes, sessions_info, locked_sessions, results, usage_data = collect_data()
    ts = get_terminal_size()
    output = build_output(processes, sessions_info, locked_sessions, results, ts.columns, ts.lines, usage_data)
    print(output)


def run_watch(interval):
    def on_exit(sig, frame):
        sys.stdout.write(SHOW_CURSOR)
        sys.stdout.flush()
        print(f"\n{DIM}Stopped.{RESET}")
        sys.exit(0)

    signal.signal(signal.SIGINT, on_exit)
    signal.signal(signal.SIGTERM, on_exit)

    sys.stdout.write(HIDE_CURSOR)
    sys.stdout.flush()

    try:
        while True:
            processes, sessions_info, locked_sessions, results, usage_data = collect_data()
            ts = get_terminal_size()
            output = build_output(
                processes, sessions_info, locked_sessions, results, ts.columns, ts.lines, usage_data
            )
            sys.stdout.write(CLEAR_SCREEN + output)
            sys.stdout.flush()
            time.sleep(interval)
    finally:
        sys.stdout.write(SHOW_CURSOR)
        sys.stdout.flush()


def main():
    watch = True
    interval = 2.0

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ("-w", "--watch"):
            watch = True
            if i + 1 < len(args):
                try:
                    interval = float(args[i + 1])
                    i += 1
                except ValueError:
                    pass
        elif args[i] in ("--once",):
            watch = False
        elif args[i] in ("-h", "--help"):
            print(__doc__.strip())
            sys.exit(0)
        i += 1

    if watch:
        run_watch(interval)
    else:
        run_once()


if __name__ == "__main__":
    main()
