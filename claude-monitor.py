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
import re
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
LIGHT_BLUE = "\033[38;2;96;165;250m"  # Subagent – light blue

# Tree drawing characters
TREE_BRANCH = "├─"
TREE_LAST   = "└─"
TREE_PIPE   = "│ "
TREE_SPACE  = "  "
SUBAGENT_ICON = "◆"
ORCH_ICON = "⟐"
SUB_INDENT = " " * 13  # aligns with info column after clawd icon

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
_ppid_cache = {"value": None, "time": 0}
_prev_session_mtimes = {}   # session_id -> mtime from previous refresh cycle
_session_owner_cache = {}   # session_id -> pid (learned from mtime tracking)
_OWNER_CACHE_FILE = os.path.join(CLAUDE_DIR, ".monitor-owner-cache.json")


def _load_owner_cache():
    """Load owner cache from disk. Only keeps entries for running processes."""
    global _session_owner_cache
    try:
        with open(_OWNER_CACHE_FILE, "r") as f:
            _session_owner_cache = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        _session_owner_cache = {}


def _save_owner_cache():
    """Persist owner cache to disk."""
    try:
        with open(_OWNER_CACHE_FILE, "w") as f:
            json.dump(_session_owner_cache, f)
    except Exception:
        pass


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
            # Match: claude-agent-sdk spawned processes
            if not is_claude and "claude-agent" in cmd_stripped:
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


def _get_all_ppids():
    """Get PID->PPID mapping for all system processes. Cached per refresh cycle."""
    now = time.time()
    if _ppid_cache["value"] is not None and now - _ppid_cache["time"] < 2:
        return _ppid_cache["value"]
    try:
        res = subprocess.run(
            ["ps", "axo", "pid,ppid"], capture_output=True, text=True, timeout=5,
        )
        ppid_map = {}
        for line in res.stdout.strip().split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 2:
                ppid_map[parts[0]] = parts[1]
        _ppid_cache["value"] = ppid_map
        _ppid_cache["time"] = now
        return ppid_map
    except Exception:
        return _ppid_cache.get("value") or {}


def build_process_tree(processes):
    """Build parent->children map from claude processes.

    Walks the PPID chain (up to 4 levels) to find claude ancestors,
    handling intermediate shell/node processes between orchestrator and subagent.
    Returns (roots, children_map, sdk_groups).
    """
    pid_set = {p["pid"] for p in processes}
    all_ppids = _get_all_ppids()
    children_map = {}  # parent_pid -> [child_procs]
    roots = []

    def find_claude_ancestor(pid):
        """Walk up PPID chain to find nearest claude ancestor."""
        current = all_ppids.get(pid)
        for _ in range(4):
            if not current or current in ("0", "1"):
                break
            if current in pid_set and current != pid:
                return current
            current = all_ppids.get(current)
        return None

    for proc in processes:
        ancestor = find_claude_ancestor(proc["pid"])
        if ancestor:
            proc["is_subagent"] = True
            proc["parent_claude_pid"] = ancestor
            children_map.setdefault(ancestor, []).append(proc)
        else:
            proc["is_subagent"] = False
            proc["parent_claude_pid"] = None
            roots.append(proc)

    # Detect SDK orchestrator groups: multiple non-interactive roots with same PPID
    sdk_groups = {}
    ppid_to_roots = {}
    for proc in roots:
        ppid_to_roots.setdefault(proc["ppid"], []).append(proc)
    for ppid, group in ppid_to_roots.items():
        if len(group) > 1 and all(not p.get("interactive") for p in group):
            orch_name = _identify_parent(ppid) or "Agent SDK"
            sdk_groups[ppid] = {"name": orch_name, "agents": group}

    return roots, children_map, sdk_groups


def render_subagent_tree(subagents, pid_to_session, children_map, locked_sessions, info_w):
    """Render indented subagent tree with branch characters."""
    lines = []
    total = len(subagents)

    for i, child in enumerate(subagents):
        is_last = (i == total - 1)
        branch = TREE_LAST if is_last else TREE_BRANCH
        pipe = TREE_SPACE if is_last else TREE_PIPE
        pid = child["pid"]
        uptime = format_uptime(child["etime"])
        session = pid_to_session.get(pid)
        icon, ago, is_locked = get_status_icon(session, locked_sessions)
        status = format_status_text(ago, is_locked)

        # Subagent header line
        lines.append(
            f"{SUB_INDENT}{GRAY}{branch}{RESET} "
            f"{LIGHT_BLUE}{SUBAGENT_ICON}{RESET} "
            f"{DIM}PID {pid}{RESET}  {uptime}  {icon} {status}"
        )

        # Session info (prompt + tool)
        if session:
            prompt = truncate(session.get("last_prompt"), info_w - 20)
            tool = truncate(session.get("last_tool_use"), info_w - 20)
            if prompt:
                lines.append(
                    f"{SUB_INDENT}{GRAY}{pipe}{RESET}   "
                    f"{CYAN}Prompt:{RESET} {prompt}"
                )
            if tool:
                lines.append(
                    f"{SUB_INDENT}{GRAY}{pipe}{RESET}   "
                    f"{MAGENTA}Tool:{RESET}   {tool}"
                )
        else:
            cmd_info = truncate(child.get("cmd", ""), info_w - 20)
            if child.get("print_mode"):
                lines.append(
                    f"{SUB_INDENT}{GRAY}{pipe}{RESET}   "
                    f"{DIM}--print mode{RESET}"
                )
            elif cmd_info:
                lines.append(
                    f"{SUB_INDENT}{GRAY}{pipe}{RESET}   "
                    f"{DIM}{cmd_info}{RESET}"
                )

        # Recursive: render sub-subagents (nested depth)
        nested = children_map.get(pid, [])
        if nested:
            nested_lines = render_subagent_tree(
                nested, pid_to_session, children_map, locked_sessions, info_w
            )
            # Indent nested lines further under the current branch pipe
            for nline in nested_lines:
                lines.append(
                    f"{SUB_INDENT}{GRAY}{pipe}{RESET} {nline.lstrip()}"
                )

    return lines


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
    """Match a process to its session by timestamp proximity (5 min window)."""
    if process["start_time"]:
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
        if best_match:
            return best_match

    # Check owner cache from mtime tracking (learned from previous cycles)
    pid = process["pid"]
    for sinfo in sessions_info:
        if _session_owner_cache.get(sinfo["session_id"]) == pid:
            return sinfo

    return None


def _has_caffeinate_child(pid):
    """Check if a claude process has a caffeinate child (= actively processing)."""
    try:
        result = subprocess.run(
            ["pgrep", "-P", str(pid)],
            capture_output=True, text=True, timeout=2,
        )
        for cpid in result.stdout.strip().split("\n"):
            if not cpid:
                continue
            cmd = subprocess.run(
                ["ps", "-p", cpid, "-o", "command="],
                capture_output=True, text=True, timeout=2,
            ).stdout.strip()
            if "caffeinate" in cmd:
                return True
    except Exception:
        pass
    return False


def _update_session_tracking(sessions_info, active_pids):
    """Track session mtime changes between refresh cycles.

    Sessions whose mtime changed since last cycle are actively being written to.
    Sessions whose mtime is frozen are likely orphaned (their process died).
    Returns (changed_sids, stale_sids).
    """
    global _prev_session_mtimes, _session_owner_cache

    changed = set()
    stale = set()

    for sinfo in sessions_info:
        sid = sinfo["session_id"]
        current_mt = sinfo.get("mtime", 0)
        prev_mt = _prev_session_mtimes.get(sid, 0)

        if prev_mt > 0:
            if current_mt > prev_mt:
                changed.add(sid)
            else:
                stale.add(sid)

        _prev_session_mtimes[sid] = current_mt

    # Clean owner cache: remove dead processes
    _session_owner_cache = {
        sid: pid for sid, pid in _session_owner_cache.items()
        if pid in active_pids
    }

    return changed, stale


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


def build_output(processes, sessions_info, locked_sessions, results, term_width, term_height, usage_data=None, tree_data=None):
    """Build the full display string with hierarchical subagent tree."""
    buf = []
    now_str = datetime.now().strftime("%H:%M:%S")
    max_w = min(term_width, 100)
    pad = CLAWD_W + 3  # icon width + gap
    info_w = max_w - pad - 2  # available width for info text

    # Build pid -> session lookup
    pid_to_session = {}
    for proc, session in results:
        pid_to_session[proc["pid"]] = session

    # Get tree structure
    if tree_data:
        roots, children_map, sdk_groups = tree_data
    else:
        roots = [proc for proc, _ in results]
        children_map = {}
        sdk_groups = {}

    # Count subagents
    total_subs = sum(len(v) for v in children_map.values())
    n_roots = len(roots)
    n_total = len(results)

    buf.append("")
    # Title with subagent count
    title_parts = f"  {BOLD}{WHITE}Claude Monitor{RESET}  {DIM}{n_roots} instance{'s' if n_roots != 1 else ''}"
    if total_subs > 0:
        title_parts += f"  {LIGHT_BLUE}{SUBAGENT_ICON} {total_subs} subagent{'s' if total_subs != 1 else ''}{RESET}"
    title_parts += f"{RESET}  {DIM}{now_str}{RESET}"
    buf.append(title_parts)

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

    # Track which SDK groups have been rendered
    rendered_sdk_groups = set()
    instance_idx = 0

    for proc in roots:
        instance_idx += 1
        session = pid_to_session.get(proc["pid"])
        pid = proc["pid"]
        tty = proc["tty"]
        uptime = format_uptime(proc["etime"])
        icon, ago, is_locked = get_status_icon(session, locked_sessions)
        status_text = format_status_text(ago, is_locked)
        subs = children_map.get(pid, [])
        has_subs = len(subs) > 0

        # SDK orchestrator group header
        if proc["ppid"] in sdk_groups and proc["ppid"] not in rendered_sdk_groups:
            group = sdk_groups[proc["ppid"]]
            rendered_sdk_groups.add(proc["ppid"])
            n_agents = len(group["agents"])
            buf.append("")
            buf.append(
                f"  {YELLOW}{BOLD}{ORCH_ICON} {group['name']} Orchestrator{RESET}  "
                f"{DIM}({n_agents} agents){RESET}"
            )

        # Build instance type label and pick icon color
        is_interactive = proc.get("interactive", True)
        parent_app = proc.get("parent_app")
        if not is_interactive:
            src = parent_app or "subprocess"
            type_label = f"{ICON_GREEN}{src}{RESET} {DIM}(--print){RESET}"
            icon_color = ICON_GREEN
        elif ago < 60 or is_locked:
            type_label = f"{tty}"
            icon_color = PURPLE
        else:
            type_label = f"{tty}"
            icon_color = ORANGE

        # Build right-side info lines
        right = []
        instance_label = f"Instance {instance_idx}"
        if has_subs:
            instance_label += f"  {LIGHT_BLUE}{SUBAGENT_ICON}{len(subs)}{RESET}"
        right.append(
            f"{icon} {BOLD}{WHITE}{instance_label}{RESET}  "
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

        # Render subagent tree under this instance
        if has_subs:
            sub_lines = render_subagent_tree(
                subs, pid_to_session, children_map, locked_sessions, info_w
            )
            buf.extend(sub_lines)

    buf.append("")
    buf.append(f"  {DIM}{'─' * (max_w - 2)}{RESET}")
    buf.append(
        f"  {PURPLE}▐▌{RESET} {DIM}Active{RESET}  "
        f"{ORANGE}▐▌{RESET} {DIM}Idle{RESET}  "
        f"{ICON_GREEN}▐▌{RESET} {DIM}Subprocess{RESET}  "
        f"{LIGHT_BLUE}{SUBAGENT_ICON}{RESET} {DIM}Subagent{RESET}  "
        f"{YELLOW}{ORCH_ICON}{RESET} {DIM}SDK Orchestrator{RESET}  "
        f"{DIM}Ctrl+C to exit{RESET}"
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
            "model": "claude-3-haiku-20240307",
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
    """Format a unix timestamp as human-readable relative/absolute time with date."""
    if not reset_ts:
        return ""
    now = time.time()
    dt = datetime.fromtimestamp(reset_ts)
    diff = reset_ts - now
    if diff <= 0:
        return "now"
    date_str = dt.strftime("%d/%m %H:%M")
    if diff < 3600:
        return f"{int(diff / 60)}m ({date_str})"
    if diff < 86400:
        return f"{int(diff / 3600)}h {int((diff % 3600) / 60)}m ({date_str})"
    return date_str


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
    """Gather all data and return (processes, sessions_info, locked_sessions, results, token_data, tree_data)."""
    processes = get_claude_processes()
    project_dirs = find_project_dirs()
    active_files = get_active_sessions(project_dirs, len(processes))
    locked_sessions = get_lock_sessions()

    sessions_info = []
    for filepath, mtime in active_files:
        sinfo = extract_session_info(filepath)
        sinfo["mtime"] = mtime
        sessions_info.append(sinfo)

    # Track mtime changes to detect orphaned sessions
    active_pids = {p["pid"] for p in processes}
    changed_sids, stale_sids = _update_session_tracking(sessions_info, active_pids)

    matched = set()
    results = []

    # Pass 1: timestamp + owner cache matching
    for proc in processes:
        session = match_pid_to_session(
            proc, [s for s in sessions_info if s["session_id"] not in matched]
        )
        if session:
            matched.add(session["session_id"])
            _session_owner_cache[session["session_id"]] = proc["pid"]
        results.append((proc, session))

    # Pass 2: associate changed sessions with actively processing processes.
    # A process with a caffeinate child is actively processing a request.
    # If that process is unmatched and there's a changed session, pair them.
    unmatched_indices = [
        i for i, (proc, session) in enumerate(results)
        if session is None and proc.get("interactive")
    ]
    unmatched_session_list = [
        s for s in sessions_info if s["session_id"] not in matched
    ]

    if unmatched_indices:
        # Find which processes are actively processing (have caffeinate child)
        active_proc_indices = [
            idx for idx in unmatched_indices
            if _has_caffeinate_child(results[idx][0]["pid"])
        ]
        # Find candidate sessions: changed mtime, or very recently modified (< 5s)
        now = time.time()
        candidate_sids = changed_sids | {
            s["session_id"] for s in unmatched_session_list
            if now - s.get("mtime", 0) < 5
        }
        for idx in list(active_proc_indices):
            proc = results[idx][0]
            for s in list(unmatched_session_list):
                if s["session_id"] in candidate_sids:
                    results[idx] = (proc, s)
                    matched.add(s["session_id"])
                    _session_owner_cache[s["session_id"]] = proc["pid"]
                    unmatched_indices.remove(idx)
                    unmatched_session_list.remove(s)
                    break

    # Pass 3: remaining unmatched — pair by mtime, deprioritizing stale sessions.
    def _session_sort_key(s):
        sid = s["session_id"]
        if sid in stale_sids:
            return (0, s.get("mtime", 0))  # stale = likely orphaned
        return (1, s.get("mtime", 0))      # unknown or changed

    remaining_sessions = sorted(
        [s for s in unmatched_session_list if s["session_id"] not in matched],
        key=_session_sort_key,
        reverse=True,
    )

    # Sort unmatched processes: most recently started first
    def _proc_recency(idx):
        proc = results[idx][0]
        if proc.get("start_time"):
            return time.mktime(proc["start_time"].timetuple())
        return 0

    unmatched_indices.sort(key=_proc_recency, reverse=True)

    for idx in unmatched_indices:
        if not remaining_sessions:
            break
        session = remaining_sessions.pop(0)
        results[idx] = (results[idx][0], session)
        matched.add(session["session_id"])
        # Do NOT cache fallback pairings — low confidence, may be wrong

    # Persist learned associations
    _save_owner_cache()

    # Build process tree for subagent detection
    tree_data = build_process_tree(processes)

    # Rate limit data from API
    creds = get_credentials()
    rate_limits = fetch_rate_limits(creds.get("access_token"))
    usage_data = {"creds": creds, "rate_limits": rate_limits}

    return processes, sessions_info, locked_sessions, results, usage_data, tree_data


def run_once():
    processes, sessions_info, locked_sessions, results, usage_data, tree_data = collect_data()
    ts = get_terminal_size()
    output = build_output(processes, sessions_info, locked_sessions, results, ts.columns, ts.lines, usage_data, tree_data)
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
            processes, sessions_info, locked_sessions, results, usage_data, tree_data = collect_data()
            ts = get_terminal_size()
            output = build_output(
                processes, sessions_info, locked_sessions, results, ts.columns, ts.lines, usage_data, tree_data
            )
            sys.stdout.write(CLEAR_SCREEN + output)
            sys.stdout.flush()
            time.sleep(interval)
    finally:
        sys.stdout.write(SHOW_CURSOR)
        sys.stdout.flush()


def main():
    _load_owner_cache()
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
