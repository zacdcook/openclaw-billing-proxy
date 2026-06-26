#!/usr/bin/env python3
"""
OCPlatform Subscription Billing Proxy v2.1 (Python port)

Routes OCPlatform API requests through Claude Code's subscription billing
instead of Extra Usage. Defeats Anthropic's multi-layer detection:

  Layer 1: Billing header injection (84-char Claude Code identifier)
  Layer 2: String trigger sanitization (OpenClaw, sessions_*, operating from, etc.)
  Layer 3: Tool name fingerprint bypass (rename OC tools to CC PascalCase convention)
  Layer 4: System prompt template bypass (strip config section, replace with paraphrase)
  Layer 5: Tool description stripping (reduce fingerprint signal in tool schemas)
  Layer 6: Property name renaming (eliminate OC-specific schema property names)
  Layer 7: Full bidirectional reverse mapping (SSE + JSON responses)
  Layer 8: Strip trailing assistant prefill (Opus 4.6 compatibility)

This is a straight, single-threaded Python translation of proxy.js. There is
NO worker pool and NO parallelization: processBody / reverseMap run inline on
the request-handling thread. The HTTP server uses a threading mixin so multiple
in-flight requests still proceed, but each request's transforms are sequential.

Standard library only. Usage:
    python3 proxy2.py [--port 18801] [--config config.json]
"""

import sys
import os
import json
import hashlib
import uuid
import time
import random
import http.client
import http.server
import socketserver
import subprocess
import platform
from urllib.parse import urlparse, parse_qs

# --- Defaults ----------------------------------------------------------------
DEFAULT_PORT = 18801
UPSTREAM_HOST = "api.anthropic.com"
VERSION = "2.1.0"
REQUEST_SIZE_WARN_BYTES = 1 * 1024 * 1024
REQUEST_SIZE_HIGH_BYTES = 2 * 1024 * 1024
REQUEST_SIZE_CRITICAL_BYTES = 5 * 1024 * 1024
USAGE_LOG_DEFAULT_NAME = "routing-layer-usage.jsonl"

# Claude Code version to emulate (update when new CC versions are released)
CC_VERSION = "2.1.97"

# Billing fingerprint constants (matches real CC utils/fingerprint.ts)
BILLING_HASH_SALT = "59cf53e54c78"
BILLING_HASH_INDICES = [4, 7, 20]

# Persistent per-instance identifiers (generated once at startup)
DEVICE_ID = os.urandom(32).hex()
INSTANCE_SESSION_ID = str(uuid.uuid4())

# Beta flags required for OAuth + Claude Code features
REQUIRED_BETAS = [
    "oauth-2025-04-20",
    "claude-code-20250219",
    "interleaved-thinking-2025-05-14",
    "advanced-tool-use-2025-11-20",
    "context-management-2025-06-27",
    "prompt-caching-scope-2026-01-05",
    "effort-2025-11-24",
    "fast-mode-2026-02-01",
]

# CC tool stubs -- injected into tools array to make the tool set look more
# like a Claude Code session. The model won't call these (schemas are minimal).
CC_TOOL_STUBS = [
    '{"name":"Glob","description":"Find files by pattern","input_schema":{"type":"object","properties":{"pattern":{"type":"string","description":"Glob pattern"}},"required":["pattern"]}}',
    '{"name":"Grep","description":"Search file contents","input_schema":{"type":"object","properties":{"pattern":{"type":"string","description":"Regex pattern"},"path":{"type":"string","description":"Search path"}},"required":["pattern"]}}',
    '{"name":"Agent","description":"Launch a subagent for complex tasks","input_schema":{"type":"object","properties":{"prompt":{"type":"string","description":"Task description"}},"required":["prompt"]}}',
    '{"name":"NotebookEdit","description":"Edit notebook cells","input_schema":{"type":"object","properties":{"notebook_path":{"type":"string"},"cell_index":{"type":"integer"}},"required":["notebook_path"]}}',
    '{"name":"TodoRead","description":"Read current task list","input_schema":{"type":"object","properties":{}}}',
]


# --- Billing Fingerprint -----------------------------------------------------
# Computes a 3-character SHA256 fingerprint hash matching real CC's
# computeFingerprint() in utils/fingerprint.ts:
#   SHA256(salt + msg[4] + msg[7] + msg[20] + version)[:3]
# Applied to the first user message text in the request body.

def compute_billing_fingerprint(first_user_text):
    chars = "".join(
        (first_user_text[i] if i < len(first_user_text) else "0")
        for i in BILLING_HASH_INDICES
    )
    inp = f"{BILLING_HASH_SALT}{chars}{CC_VERSION}"
    return hashlib.sha256(inp.encode("utf-8")).hexdigest()[:3]


def extract_first_user_text(body_str):
    """Extract first user message text via string scanning (no json.loads)."""
    msgs_idx = body_str.find('"messages":[')
    if msgs_idx == -1:
        return ""
    user_idx = body_str.find('"role":"user"', msgs_idx)
    if user_idx == -1:
        return ""

    content_idx = body_str.find('"content"', user_idx)
    if content_idx == -1 or content_idx > user_idx + 500:
        return ""

    after_content = body_str[content_idx + len('"content"') + 1:content_idx + len('"content"') + 2]
    if after_content == '"':
        text_start = content_idx + len('"content":"')
        end = text_start
        n = len(body_str)
        while end < n:
            if body_str[end] == "\\":
                end += 2
                continue
            if body_str[end] == '"':
                break
            end += 1
        return (body_str[text_start:end]
                .replace("\\n", "\n").replace("\\t", "\t")
                .replace('\\"', '"').replace("\\\\", "\\"))

    text_idx = body_str.find('"text":"', content_idx)
    if text_idx == -1 or text_idx > content_idx + 2000:
        return ""
    text_start = text_idx + len('"text":"')
    end = text_start
    n = len(body_str)
    while end < n:
        if body_str[end] == "\\":
            end += 2
            continue
        if body_str[end] == '"':
            break
        end += 1
    return (body_str[text_start:min(end, text_start + 50)]
            .replace("\\n", "\n").replace("\\t", "\t")
            .replace('\\"', '"').replace("\\\\", "\\"))


def build_billing_block(body_str):
    first_text = extract_first_user_text(body_str)
    fingerprint = compute_billing_fingerprint(first_text)
    cc_version = f"{CC_VERSION}.{fingerprint}"
    return '{"type":"text","text":"x-routing-config: rt_version=%s; rt_entrypoint=cli; cfg=00000;"}' % cc_version


# --- Stainless SDK Headers ---------------------------------------------------
# Real Claude Code sends these on every request via the Anthropic JS SDK.
def get_stainless_headers():
    p = sys.platform
    if p == "darwin":
        os_name = "macOS"
    elif p.startswith("win"):
        os_name = "Windows"
    elif p.startswith("linux"):
        os_name = "Linux"
    else:
        os_name = p
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        arch = "x64"
    elif m in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = m
    return {
        "user-agent": f"claude-cli/{CC_VERSION} (external, cli)",
        "x-app": "cli",
        "x-claude-code-session-id": INSTANCE_SESSION_ID,
        "x-stainless-arch": arch,
        "x-stainless-lang": "js",
        "x-stainless-os": os_name,
        "x-stainless-package-version": "0.81.0",
        "x-stainless-runtime": "node",
        "x-stainless-runtime-version": "v" + platform.python_version(),
        "x-stainless-retry-count": "0",
        "x-stainless-timeout": "600",
        "anthropic-dangerous-direct-browser-access": "true",
    }


# --- Layer 2: String Trigger Replacements ------------------------------------
DEFAULT_REPLACEMENTS = [
    ["OCPlatform", "OCPlatform"],
    ["ocplatform", "openclaw"],
    ["Claude Code", "Claude Code"],
    ["Claude Code", "Claude Code"],
    ["claude-code", "claude-code"],
    ["Anthropic", "Anthropic"],
    ["CLAUDE.md", "CLAUDE.md"],
    ["WORKSPACE NOTES", "WORKSPACE NOTES"],
    ["USER NOTES", "USER NOTES"],
    ["available_tools", "available_tools"],
    ["create_task", "create_task"],
    ["list_tasks", "list_tasks"],
    ["get_history", "get_history"],
    ["send_to_task", "send_to_task"],
    ["task_yield_interrupt", "task_yield_interrupt"],
    ["yield_task", "yield_task"],
    ["task_store", "task_store"],
    ["HEARTBEAT_OK", "HB_ACK"],
    ["HB_SIGNAL", "HB_SIGNAL"],
    ["hb_signal", "hb_signal"],
    ["operating from", "operating from"],
    ["PAssistant", "PAssistant"],
    ["passistant", "passistant"],
    ["skillhub.example.com", "skillhub.example.com"],
    ["clawhub", "clawhub"],
    ["clawd", "agentd"],
    ["lossless-ctx", "lossless-ctx"],
    ["external", "third-party"],
    ["routing layer", "routing layer"],
    ["routing-layer", "routing-layer"],
    ["x-routing-config", "x-routing-config"],
    ["x-routing-cfg", "x-routing-cfg"],
    ["cfg=00000", "cfg=00000"],
    ["rt_version", "rt_version"],
    ["rt_entrypoint", "rt_entrypoint"],
    ["routing config", "routing config"],
    ["usage quota", "usage quota"],
    ["ocplatform", "ocplatform"],
]

# --- Layer 3: Tool Name Renames ----------------------------------------------
# ORDERING: lcm_expand_query MUST come before lcm_expand to avoid partial match.
DEFAULT_TOOL_RENAMES = [
    ["exec", "Bash"],
    ["process", "execSession"],
    ["browser", "BrowserControl"],
    ["canvas", "CanvasView"],
    ["nodes", "DeviceControl"],
    ["cron", "Scheduler"],
    ["message", "SendMessage"],
    ["tts", "Speech"],
    ["gateway", "SystemCtl"],
    ["agents_list", "AgentList"],
    ["list_tasks", "TaskList"],
    ["get_history", "TaskHistory"],
    ["send_to_task", "TaskSend"],
    ["create_task", "TaskCreate"],
    ["subagents", "AgentControl"],
    ["session_status", "StatusCheck"],
    ["web_search", "web_search"],
    ["web_fetch", "WebFetch"],
    # NOTE: ['image', 'ImageGen'] removed -- collides with Anthropic content block
    # type "image". See issue #14.
    ["pdf", "PdfParse"],
    ["memory_search", "KnowledgeSearch"],
    ["memory_get", "KnowledgeGet"],
    ["lcm_expand_query", "ContextQuery"],
    ["lcm_grep", "ContextGrep"],
    ["lcm_describe", "ContextDescribe"],
    ["lcm_expand", "ContextExpand"],
    ["yield_task", "TaskYield"],
    ["task_store", "TaskStore"],
    ["task_yield_interrupt", "TaskYieldInterrupt"],
    ["mcp_browser_back", "BrowserBack"],
    ["mcp_browser_click", "BrowserClick"],
    ["mcp_browser_console", "BrowserConsole"],
    ["mcp_browser_get_images", "BrowserImages"],
    ["mcp_browser_navigate", "BrowserNavigate"],
    ["mcp_browser_press", "BrowserPress"],
    ["mcp_browser_scroll", "BrowserScroll"],
    ["mcp_browser_snapshot", "BrowserSnapshot"],
    ["mcp_browser_type", "BrowserType"],
    ["mcp_browser_vision", "BrowserVision"],
    ["mcp_clarify", "AskUser"],
    ["mcp_cronjob", "Scheduler"],
    ["mcp_delegate_task", "Task"],
    ["mcp_execute_code", "CodeExec"],
    ["mcp_memory", "MemoryStore"],
    ["mcp_patch", "PatchApply"],
    ["mcp_process", "BashSessionCtl"],
    ["mcp_read_file", "Read"],
    ["mcp_search_files", "GrepFiles"],
    ["mcp_session_search", "TaskSearch"],
    ["mcp_skill_manage", "SkillManage"],
    ["mcp_skill_view", "SkillView"],
    ["mcp_skills_list", "SkillList"],
    ["mcp_terminal", "Bash"],
    ["mcp_text_to_speech", "Speech"],
    ["mcp_todo", "TodoWrite"],
    ["mcp_vision_analyze", "VisionAnalyze"],
    ["mcp_write_file", "Write"],
]

# --- Layer 6: Property Name Renames ------------------------------------------
DEFAULT_PROP_RENAMES = [
    ["session_id", "session_id"],
    ["conversation_id", "thread_ref"],
    ["summaryIds", "chunk_ids"],
    ["summary_id", "chunk_id"],
    ["system_event", "event_text"],
    ["agent_id", "worker_id"],
    ["wake_at", "trigger_at"],
    ["wake_event", "trigger_event"],
]

# --- Reverse Mappings --------------------------------------------------------
DEFAULT_REVERSE_MAP = [
    ["OCPlatform", "OCPlatform"],
    ["ocplatform", "ocplatform"],
    ["create_task", "create_task"],
    ["list_tasks", "list_tasks"],
    ["get_history", "get_history"],
    ["send_to_task", "send_to_task"],
    ["task_yield_interrupt", "task_yield_interrupt"],
    ["sessions_yield", "yield_task"],
    ["task_store", "task_store"],
    ["HB_ACK", "HB_ACK"],
    ["HB_SIGNAL", "HB_SIGNAL"],
    ["hb_signal", "hb_signal"],
    ["PAssistant", "PAssistant"],
    ["passistant", "passistant"],
    ["skillhub.example.com", "skillhub.example.com"],
    ["clawhub", "skillhub"],
    ["agentd", "agentd"],
    ["lossless-ctx", "lossless-ctx"],
    ["external", "external"],
    ["routing layer", "routing layer"],
    ["routing-layer", "routing-layer"],
    ["x-routing-config", "x-routing-config"],
    ["x-routing-cfg", "x-routing-cfg"],
    ["cfg=00000", "cfg=00000"],
    ["rt_version", "rt_version"],
    ["rt_entrypoint", "rt_entrypoint"],
    ["routing config", "routing config"],
    ["usage quota", "usage quota"],
]


# --- Helpers -----------------------------------------------------------------
def expand_home(p, home_dir=None):
    if home_dir is None:
        home_dir = os.path.expanduser("~")
    if p and p.startswith("~"):
        return os.path.join(home_dir, p[1:].lstrip("/\\"))
    return p


def dedupe_pairs(pairs):
    seen = set()
    out = []
    for pair in pairs or []:
        if not isinstance(pair, (list, tuple)) or len(pair) < 2:
            continue
        key = json.dumps([pair[0], pair[1]])
        if key in seen:
            continue
        seen.add(key)
        out.append([pair[0], pair[1]])
    return out


def now_ms():
    return time.monotonic() * 1000.0


def format_ms(ms):
    return f"{max(0, round(ms))}ms"


def hms():
    return time.strftime("%H:%M:%S", time.localtime())


def iso_now():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z"


def hash_short(value):
    if value is None or value == "":
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def normalize_body_preview_chars(value):
    if value is None or value is False:
        return 0
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return 0
    if parsed < 1:
        return 0
    return min(int(parsed), 500)


def resolve_usage_log_path(config_path, home_dir=None):
    if home_dir is None:
        home_dir = os.path.expanduser("~")
    if config_path is False or config_path is None:
        # Match JS: only None/False disables; default path otherwise.
        if config_path is False:
            return None
    default = os.path.join(home_dir, ".ocplatform", "logs", USAGE_LOG_DEFAULT_NAME)
    p = expand_home(config_path or default, home_dir)
    return os.path.abspath(p)


def approx_content_chars(content):
    if isinstance(content, str):
        return len(content)
    if not isinstance(content, list):
        return 0
    total = 0
    for part in content:
        if not isinstance(part, dict):
            continue
        if isinstance(part.get("text"), str):
            total += len(part["text"])
        if isinstance(part.get("content"), str):
            total += len(part["content"])
    return total


def content_preview(content, max_chars):
    if not max_chars:
        return None
    text = ""
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        parts = []
        for part in content:
            if not isinstance(part, dict):
                continue
            if isinstance(part.get("text"), str):
                parts.append(part["text"])
            elif isinstance(part.get("content"), str):
                parts.append(part["content"])
        text = " ".join(p for p in parts if p)
    if not text:
        return None
    normalized = " ".join(text.split()).strip()
    if not normalized:
        return None
    return normalized[:max_chars] + "..." if len(normalized) > max_chars else normalized


def count_content_parts(content, type_):
    if not isinstance(content, list):
        return 0
    return sum(1 for part in content if isinstance(part, dict) and part.get("type") == type_)


def parse_request_model(body_str):
    import re
    match = re.search(r'"model"\s*:\s*"([^"]+)"', body_str)
    return match.group(1) if match else "unknown"


def extract_request_metadata(body_str, headers=None, preview_chars=0):
    headers = headers or {}
    meta = {
        "parseOk": False,
        "model": parse_request_model(body_str),
        "stream": None,
        "maxTokens": None,
        "thinkingBudgetTokens": None,
        "messagesCount": None,
        "toolsCount": None,
        "systemChars": 0,
        "messageContentChars": 0,
        "userMessages": 0,
        "assistantMessages": 0,
        "toolUseBlocks": 0,
        "toolResultBlocks": 0,
        "firstUserHash": None,
        "lastUserHash": None,
        "firstUserPreview": None,
        "lastUserPreview": None,
        "bodyHash": hash_short(body_str),
    }

    attribution_names = [
        "x-ocplatform-agent-id", "x-ocplatform-session-key", "x-ocplatform-session-id",
        "x-ocplatform-run-id", "x-ocplatform-cron-job-id", "x-ocplatform-task-id",
    ]
    attribution = {}
    for name in attribution_names:
        value = headers.get(name) or headers.get(name.lower())
        if value:
            attribution[name] = hash_short(value)
    if attribution:
        meta["attributionHeaderHashes"] = attribution

    try:
        parsed = json.loads(body_str)
        meta["parseOk"] = True
        meta["model"] = parsed.get("model") or meta["model"]
        meta["stream"] = bool(parsed.get("stream"))
        meta["maxTokens"] = parsed.get("max_tokens", parsed.get("maxTokens"))
        thinking = parsed.get("thinking") or {}
        meta["thinkingBudgetTokens"] = thinking.get("budget_tokens", thinking.get("budgetTokens"))
        tools = parsed.get("tools")
        meta["toolsCount"] = len(tools) if isinstance(tools, list) else 0
        system = parsed.get("system")
        if isinstance(system, str):
            meta["systemChars"] = len(system)
        elif isinstance(system, list):
            meta["systemChars"] = sum(
                approx_content_chars(part.get("text", part.get("content", "")) if isinstance(part, dict) else "")
                for part in system
            )
        else:
            meta["systemChars"] = 0

        tool_names = [t.get("name") for t in tools if isinstance(t, dict) and t.get("name")] if isinstance(tools, list) else []
        if tool_names:
            meta["toolNamesHash"] = hash_short("\n".join(tool_names))

        messages = parsed.get("messages")
        if isinstance(messages, list):
            meta["messagesCount"] = len(messages)
            first_user = None
            last_user = None
            first_user_preview = None
            last_user_preview = None
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                if msg.get("role") == "user":
                    meta["userMessages"] += 1
                if msg.get("role") == "assistant":
                    meta["assistantMessages"] += 1
                meta["messageContentChars"] += approx_content_chars(msg.get("content"))
                meta["toolUseBlocks"] += count_content_parts(msg.get("content"), "tool_use")
                meta["toolResultBlocks"] += count_content_parts(msg.get("content"), "tool_result")
                if msg.get("role") == "user":
                    chars = approx_content_chars(msg.get("content"))
                    marker = f"{chars}:{json.dumps(msg.get('content'))[:256]}"
                    preview = content_preview(msg.get("content"), preview_chars)
                    if not first_user:
                        first_user = marker
                    if not first_user_preview:
                        first_user_preview = preview
                    last_user = marker
                    last_user_preview = preview
            meta["firstUserHash"] = hash_short(first_user)
            meta["lastUserHash"] = hash_short(last_user)
            meta["firstUserPreview"] = first_user_preview
            meta["lastUserPreview"] = last_user_preview
    except Exception:
        # Keep string-scanned fields above. Never log raw body content on parse failure.
        pass
    return meta


def request_size_level(num_bytes):
    if num_bytes >= REQUEST_SIZE_CRITICAL_BYTES:
        return "CRITICAL"
    if num_bytes >= REQUEST_SIZE_HIGH_BYTES:
        return "HIGH"
    if num_bytes >= REQUEST_SIZE_WARN_BYTES:
        return "WARN"
    return None


# --- Usage log ----------------------------------------------------------------
def ensure_usage_log_dir(config):
    if not config["usageLogEnabled"] or not config["usageLogPath"]:
        return
    os.makedirs(os.path.dirname(config["usageLogPath"]), exist_ok=True)


def append_usage_log(config, entry):
    if not config["usageLogEnabled"] or not config["usageLogPath"]:
        return
    try:
        with open(config["usageLogPath"], "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[{hms()}] usage-log write failed: {e}", file=sys.stderr)


def summarize_usage_log(config, options=None):
    options = options or {}
    if not config["usageLogEnabled"] or not config["usageLogPath"] or not os.path.exists(config["usageLogPath"]):
        return {"enabled": bool(config["usageLogEnabled"]), "path": config["usageLogPath"], "entries": 0}
    try:
        max_lines = int(options.get("lines") or 5000)
    except (TypeError, ValueError):
        max_lines = 5000
    max_lines = max(1, min(max_lines, 50000))
    with open(config["usageLogPath"], "r", encoding="utf-8") as f:
        raw_lines = [ln for ln in f.read().strip().split("\n") if ln][-max_lines:]
    by_minute = {}
    by_model = {}
    by_event = {}
    large_requests = []
    parsed = 0
    for line in raw_lines:
        if not line:
            continue
        try:
            entry = json.loads(line)
        except Exception:
            continue
        parsed += 1
        minute = entry["ts"][:16] if entry.get("ts") else "unknown"
        event = entry.get("event", "unknown")
        model = entry.get("model") or (entry.get("request") or {}).get("model") or "unknown"
        num_bytes = int(entry.get("originalBytes") or 0)
        by_event[event] = by_event.get(event, 0) + 1
        by_model[model] = by_model.get(model, 0) + (1 if event == "request" else 0)
        if event == "request":
            bucket = by_minute.get(minute) or {
                "minute": minute, "requests": 0, "originalBytes": 0, "transformedBytes": 0,
                "warn": 0, "high": 0, "critical": 0, "models": {},
            }
            bucket["requests"] += 1
            bucket["originalBytes"] += num_bytes
            bucket["transformedBytes"] += int(entry.get("transformedBytes") or 0)
            if entry.get("sizeLevel") == "WARN":
                bucket["warn"] += 1
            if entry.get("sizeLevel") == "HIGH":
                bucket["high"] += 1
            if entry.get("sizeLevel") == "CRITICAL":
                bucket["critical"] += 1
            bucket["models"][model] = bucket["models"].get(model, 0) + 1
            by_minute[minute] = bucket
            if num_bytes >= REQUEST_SIZE_WARN_BYTES:
                large_requests.append({
                    "ts": entry.get("ts"), "reqNum": entry.get("reqNum"), "model": model,
                    "originalBytes": num_bytes, "transformedBytes": entry.get("transformedBytes"),
                    "sizeLevel": entry.get("sizeLevel"), "request": entry.get("request"),
                })
    top_minutes = sorted(by_minute.values(), key=lambda b: b["requests"], reverse=True)[:20]
    recent_minutes = sorted(by_minute.values(), key=lambda b: b["minute"])[-60:]
    return {
        "enabled": True,
        "path": config["usageLogPath"],
        "sampledLines": len(raw_lines),
        "parsedEntries": parsed,
        "eventCounts": dict(sorted(by_event.items(), key=lambda kv: kv[1], reverse=True)),
        "modelRequestCounts": dict(sorted([(k, v) for k, v in by_model.items() if v > 0], key=lambda kv: kv[1], reverse=True)),
        "topMinutes": top_minutes,
        "recentMinutes": recent_minutes,
        "largeRequests": large_requests[-100:],
    }


# --- Token Management ---------------------------------------------------------
KEYCHAIN_SERVICES = ["Claude Code-credentials", "claude-code", "claude", "com.anthropic.claude-code"]


def parse_credential_payload(raw):
    if not raw:
        return None
    if raw and ord(raw[0]) == 0xFEFF:
        raw = raw[1:]
    try:
        parsed = json.loads(raw)
        oauth = parsed.get("claudeAiOauth") or {}
        return parsed if oauth.get("accessToken") else None
    except Exception:
        if raw.startswith("sk-ant-"):
            return {
                "claudeAiOauth": {
                    "accessToken": raw,
                    "expiresAt": int(time.time() * 1000) + 86400000,
                    "subscriptionType": "unknown",
                }
            }
        return None


def read_credential_file(file_path):
    if not file_path or not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return None
    with open(file_path, "r", encoding="utf-8") as f:
        return parse_credential_payload(f.read())


def read_keychain_credentials():
    if sys.platform != "darwin":
        return None
    for service in KEYCHAIN_SERVICES:
        try:
            raw = subprocess.check_output(
                ["security", "find-generic-password", "-s", service, "-w"],
                stderr=subprocess.DEVNULL,
            ).decode("utf-8").strip()
            creds = parse_credential_payload(raw)
            if creds and creds.get("claudeAiOauth"):
                return {"service": service, "creds": creds}
        except Exception:
            pass
    return None


def write_credential_file(file_path, creds):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(creds))
    os.chmod(file_path, 0o600)


def resolve_claude_credentials(configured_path, home_dir=None):
    if home_dir is None:
        home_dir = os.path.expanduser("~")
    default_path = os.path.join(home_dir, ".claude", ".credentials.json")
    creds_paths = [p for p in [
        configured_path,
        default_path,
        os.path.join(home_dir, ".claude", "credentials.json"),
    ] if p]
    creds_paths = [expand_home(p, home_dir) for p in creds_paths]

    best_file = None
    for file_path in creds_paths:
        creds = read_credential_file(file_path)
        if creds and creds.get("claudeAiOauth"):
            best_file = {"path": file_path, "creds": creds}
            break

    keychain = read_keychain_credentials()
    if keychain and keychain.get("creds", {}).get("claudeAiOauth"):
        file_expiry = (best_file or {}).get("creds", {}).get("claudeAiOauth", {}).get("expiresAt", 0) if best_file else 0
        keychain_expiry = keychain["creds"]["claudeAiOauth"].get("expiresAt", 0)
        now = int(time.time() * 1000)
        if not best_file or file_expiry <= now or keychain_expiry > file_expiry:
            target = best_file["path"] if best_file else default_path
            write_credential_file(target, keychain["creds"])
            print(f"[PROXY] Synced Claude credentials from macOS Keychain ({keychain['service']})")
            return target

    return best_file["path"] if best_file else None


def get_token(creds_path):
    creds = read_credential_file(creds_path)
    expires_at = (creds or {}).get("claudeAiOauth", {}).get("expiresAt", 0) if creds else 0
    now = int(time.time() * 1000)
    if expires_at <= now:
        keychain = read_keychain_credentials()
        keychain_expiry = (keychain or {}).get("creds", {}).get("claudeAiOauth", {}).get("expiresAt", 0) if keychain else 0
        if keychain_expiry > expires_at:
            write_credential_file(creds_path, keychain["creds"])
            creds = keychain["creds"]
            print(f"[PROXY] Refreshed expired Claude credentials from macOS Keychain ({keychain['service']})")
    oauth = (creds or {}).get("claudeAiOauth")
    if not oauth or not oauth.get("accessToken"):
        raise RuntimeError('No OAuth token. Run "claude auth login".')
    return oauth


# --- Configuration ------------------------------------------------------------
def load_config(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    config_path = None
    port = None
    i = 0
    while i < len(args):
        if args[i] == "--port" and i + 1 < len(args):
            try:
                port = int(args[i + 1])
            except ValueError:
                pass
        if args[i] == "--config" and i + 1 < len(args):
            config_path = args[i + 1]
        i += 1

    config = {}
    if config_path and os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    elif os.path.exists("config.json"):
        with open("config.json", "r", encoding="utf-8") as f:
            config = json.load(f)

    home_dir = os.path.expanduser("~")
    creds_path = resolve_claude_credentials(config.get("credentialsPath"), home_dir)

    if not creds_path:
        print('[ERROR] Claude Code credentials not found. Run "claude auth login" first.', file=sys.stderr)
        if sys.platform == "darwin":
            print("Also checked macOS Keychain.", file=sys.stderr)
        sys.exit(1)

    return {
        "port": port or config.get("port") or DEFAULT_PORT,
        "credsPath": creds_path,
        "replacements": dedupe_pairs(DEFAULT_REPLACEMENTS + (config.get("replacements") or [])),
        "reverseMap": dedupe_pairs(DEFAULT_REVERSE_MAP + (config.get("reverseMap") or [])),
        "toolRenames": dedupe_pairs(DEFAULT_TOOL_RENAMES + (config.get("toolRenames") or [])),
        "propRenames": dedupe_pairs(DEFAULT_PROP_RENAMES + (config.get("propRenames") or [])),
        "stripSystemConfig": config.get("stripSystemConfig") is not False,
        "stripToolDescriptions": config.get("stripToolDescriptions") is not False,
        "injectCCStubs": config.get("injectCCStubs") is not False,
        "stripTrailingAssistantPrefill": config.get("stripTrailingAssistantPrefill") is not False,
        "bodyPreviewChars": normalize_body_preview_chars(config.get("bodyPreviewChars")),
        "usageLogEnabled": config.get("usageLogEnabled") is not False,
        "usageLogPath": resolve_usage_log_path(config.get("usageLogPath"), home_dir),
    }


# --- Helper ------------------------------------------------------------------
def find_matching_bracket(s, start):
    d = 0
    for i in range(start, len(s)):
        if s[i] == "[":
            d += 1
        elif s[i] == "]":
            d -= 1
            if d == 0:
                return i
    return -1


# --- Request Processing (Layers 1-6, 8) --------------------------------------
def process_body(body_str, config):
    m = body_str

    # Layer 2: String trigger sanitization (global replace)
    for find, replace in config["replacements"]:
        m = m.replace(find, replace)

    # Layer 3: Tool name fingerprint bypass (quoted replacement for precision)
    for orig, cc in config["toolRenames"]:
        m = m.replace('"' + orig + '"', '"' + cc + '"')

    # Layer 6: Property name renaming
    for orig, renamed in config["propRenames"]:
        m = m.replace('"' + orig + '"', '"' + renamed + '"')

    # Layer 4: System prompt template bypass
    # OCPlatform template: identity line -> first workspace doc header.
    if config["stripSystemConfig"]:
        IDENTITY_MARKER = "You are a personal assistant"
        config_start = m.find(IDENTITY_MARKER)
        if config_start != -1:
            strip_from = config_start
            if strip_from >= 2 and m[strip_from - 2] == "\\" and m[strip_from - 1] == "n":
                strip_from -= 2
            config_end = m.find("AGENTS.md", config_start)
            if config_end != -1:
                boundary = config_end
                i = config_end - 1
                while i > strip_from:
                    if (m[i] == "#" and m[i - 1] == "#" and i >= 3
                            and m[i - 3] == "\\" and m[i - 2] == "n"):
                        boundary = i - 3
                        break
                    i -= 1
                stripped_len = boundary - strip_from
                if stripped_len > 1000:
                    PARAPHRASE = (
                        "\\nYou are an AI operations assistant with access to all tools listed in this request "
                        "for file operations, command execution, web search, browser control, scheduling, "
                        "messaging, and session management. Tool names are case-sensitive and must be called "
                        "exactly as listed. Your responses route to the active channel automatically. "
                        "For cross-session communication, use the task messaging tools. "
                        "Skills defined in your workspace should be invoked when they match user requests. "
                        "Consult your workspace reference files for detailed operational configuration.\\n"
                    )
                    m = m[:strip_from] + PARAPHRASE + m[boundary:]
                    print(f"[STRIP] Removed {stripped_len} chars of config template")

    # Hermes template: preserve CC identity block, strip SOUL/MEMORY/USER/skills payload.
    if config["stripSystemConfig"]:
        HERMES_SOUL_MARKERS = ["# CLAUDE.md - Who You Are", "# CLAUDE.md - Who You Are"]
        HERMES_SKILLS_MARKERS = ["<available_tools>", "<available_tools>"]
        HERMES_END_MARKERS = ["Conversation started:", "You are a CLI AI Agent."]

        soul_start = -1
        for marker in HERMES_SOUL_MARKERS:
            idx = m.find(marker)
            if idx != -1 and (soul_start == -1 or idx < soul_start):
                soul_start = idx
        has_skills_block = any(m.find(marker, soul_start) != -1 for marker in HERMES_SKILLS_MARKERS) if soul_start != -1 else False
        if soul_start != -1 and has_skills_block:
            boundary = -1
            for marker in HERMES_END_MARKERS:
                idx = m.find(marker, soul_start)
                if idx != -1 and (boundary == -1 or idx < boundary):
                    boundary = idx
            if boundary != -1:
                strip_from = soul_start
                if strip_from >= 2 and m[strip_from - 2] == "\\" and m[strip_from - 1] == "n":
                    strip_from -= 2
                stripped_len = boundary - strip_from
                if stripped_len > 1000:
                    PARAPHRASE = (
                        "\\nAdditional workspace guidance, durable memory, user profile notes, and skill references "
                        "are available in this session context. Act as a practical CLI coding assistant, narrate "
                        "briefly before tool use, preserve user preferences, and consult available skills when the "
                        "task clearly matches them.\\n"
                    )
                    m = m[:strip_from] + PARAPHRASE + m[boundary:]
                    print(f"[STRIP] Removed {stripped_len} chars of Hermes template")

    # Layer 5: Tool description stripping
    if config["stripToolDescriptions"]:
        tools_idx = m.find('"tools":[')
        if tools_idx != -1:
            tools_end_idx = find_matching_bracket(m, tools_idx + len('"tools":'))
            if tools_end_idx != -1:
                section = m[tools_idx:tools_end_idx + 1]
                frm = 0
                while True:
                    d = section.find('"description":"', frm)
                    if d == -1:
                        break
                    vs = d + len('"description":"')
                    i = vs
                    sl = len(section)
                    while i < sl:
                        if section[i] == "\\" and i + 1 < sl:
                            i += 2
                            continue
                        if section[i] == '"':
                            break
                        i += 1
                    section = section[:vs] + section[i:]
                    frm = vs + 1
                if config["injectCCStubs"]:
                    insert_at = len('"tools":[')
                    section = section[:insert_at] + ",".join(CC_TOOL_STUBS) + "," + section[insert_at:]
                m = m[:tools_idx] + section + m[tools_end_idx + 1:]
    elif config["injectCCStubs"]:
        tools_idx = m.find('"tools":[')
        if tools_idx != -1:
            insert_at = tools_idx + len('"tools":[')
            m = m[:insert_at] + ",".join(CC_TOOL_STUBS) + "," + m[insert_at:]

    # Layer 1: Billing header injection (dynamic fingerprint per request)
    billing_block = build_billing_block(m)
    sys_array_idx = m.find('"system":[')
    if sys_array_idx != -1:
        insert_at = sys_array_idx + len('"system":[')
        m = m[:insert_at] + billing_block + "," + m[insert_at:]
    elif '"system":"' in m:
        sys_start = m.find('"system":"')
        i = sys_start + len('"system":"')
        ml = len(m)
        while i < ml:
            if m[i] == "\\":
                i += 2
                continue
            if m[i] == '"':
                break
            i += 1
        sys_end = i + 1
        original_sys_str = m[sys_start + len('"system":'):sys_end]
        m = (m[:sys_start]
             + '"system":[' + billing_block + ',{"type":"text","text":' + original_sys_str + "}]"
             + m[sys_end:])
    else:
        m = '{"system":[' + billing_block + "]," + m[1:]

    # Metadata injection: device_id + session_id matching real CC format
    meta_value = json.dumps({"device_id": DEVICE_ID, "session_id": INSTANCE_SESSION_ID})
    meta_json = '"metadata":{"user_id":' + json.dumps(meta_value) + "}"
    existing_meta = m.find('"metadata":{')
    if existing_meta != -1:
        depth = 0
        mi = existing_meta + len('"metadata":')
        ml = len(m)
        while mi < ml:
            if m[mi] == "{":
                depth += 1
            elif m[mi] == "}":
                depth -= 1
                if depth == 0:
                    mi += 1
                    break
            mi += 1
        m = m[:existing_meta] + meta_json + m[mi:]
    else:
        m = "{" + meta_json + "," + m[1:]

    # Layer 8: Strip trailing assistant prefill (raw string, no json.loads)
    if config["stripTrailingAssistantPrefill"] is not False:
        msgs_idx = m.find('"messages":[')
        if msgs_idx != -1:
            array_start = msgs_idx + len('"messages":[')
            positions = []
            depth = 0
            in_string = False
            obj_start = -1
            i = array_start
            ml = len(m)
            while i < ml:
                c = m[i]
                if in_string:
                    if c == "\\":
                        i += 2
                        continue
                    if c == '"':
                        in_string = False
                    i += 1
                    continue
                if c == '"':
                    in_string = True
                elif c == "{":
                    if depth == 0:
                        obj_start = i
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0 and obj_start != -1:
                        positions.append((obj_start, i))
                        obj_start = -1
                elif c == "]" and depth == 0:
                    break
                i += 1
            popped = 0
            while positions:
                last_start, last_end = positions[-1]
                obj = m[last_start:last_end + 1]
                if '"role":"assistant"' not in obj:
                    break
                strip_from = last_start
                j = last_start - 1
                while j >= array_start:
                    if m[j] == ",":
                        strip_from = j
                        break
                    if m[j] not in (" ", "\n", "\r", "\t"):
                        break
                    j -= 1
                m = m[:strip_from] + m[last_end + 1:]
                positions.pop()
                popped += 1
            if popped > 0:
                print(f"[STRIP-PREFILL] Removed {popped} trailing assistant message(s)")

    return m


# --- Response Processing (Layer 7) -------------------------------------------
def reverse_map(text, config):
    r = text
    # Reverse tool names first (more specific patterns)
    for orig, cc in config["toolRenames"]:
        r = r.replace('"' + cc + '"', '"' + orig + '"')
    # Reverse property names
    for orig, renamed in config["propRenames"]:
        r = r.replace('"' + renamed + '"', '"' + orig + '"')
    # Reverse string replacements
    for sanitized, original in config["reverseMap"]:
        r = r.replace(sanitized, original)
    return r


# --- Upstream Retry Handling --------------------------------------------------
MAX_UPSTREAM_ATTEMPTS = 3
RETRYABLE_UPSTREAM_ERRORS = (
    ConnectionResetError,
    BrokenPipeError,
    TimeoutError,
    ConnectionAbortedError,
)


def is_retryable_upstream_error(e):
    if isinstance(e, RETRYABLE_UPSTREAM_ERRORS):
        return True
    msg = str(e)
    return "socket hang up" in msg or "Connection reset" in msg or "timed out" in msg


def upstream_retry_delay_ms(attempt):
    base = [500, 1500, 3500][min(attempt - 1, 2)]
    return base + random.randint(0, 249)


# --- Server -------------------------------------------------------------------
class ProxyState:
    def __init__(self, config):
        self.config = config
        self.request_count = 0
        self.started_at = int(time.time() * 1000)


def build_upstream_headers(req_headers, oauth, body_len):
    headers = {}
    for key, value in req_headers.items():
        lk = key.lower()
        if lk in ("host", "connection", "authorization", "x-api-key",
                  "content-length", "x-session-affinity"):
            continue
        headers[key] = value
    headers["authorization"] = f"Bearer {oauth['accessToken']}"
    headers["content-length"] = str(body_len)
    headers["accept-encoding"] = "identity"
    headers["anthropic-version"] = "2023-06-01"

    for k, v in get_stainless_headers().items():
        headers[k] = v

    existing_beta = headers.get("anthropic-beta", "")
    betas = [b.strip() for b in existing_beta.split(",")] if existing_beta else []
    for b in REQUIRED_BETAS:
        if b not in betas:
            betas.append(b)
    headers["anthropic-beta"] = ",".join(betas)
    return headers


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # Silence default logging; we do our own.
    def log_message(self, fmt, *args):
        pass

    @property
    def state(self):
        return self.server.state

    @property
    def config(self):
        return self.server.state.config

    def _write_json(self, status, obj, extra_headers=None):
        payload = json.dumps(obj).encode("utf-8") if not isinstance(obj, (bytes, bytearray)) else obj
        self.send_response(status)
        if extra_headers:
            for k, v in extra_headers.items():
                if k.lower() == "content-length":
                    continue
                self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        config = self.config
        if self.path.startswith("/usage-summary"):
            try:
                qs = parse_qs(urlparse(self.path).query)
                lines = qs.get("lines", [None])[0]
                summary = summarize_usage_log(config, {"lines": lines})
                self._write_json(200, summary)
            except Exception as e:
                self._write_json(500, {"status": "error", "message": str(e)})
            return

        if self.path == "/health":
            try:
                oauth = get_token(config["credsPath"])
                now = int(time.time() * 1000)
                expires_in = (oauth.get("expiresAt", 0) - now) / 3600000.0
                self._write_json(200, {
                    "status": "ok" if expires_in > 0 else "token_expired",
                    "proxy": "ocplatform-routing-layer",
                    "version": VERSION,
                    "requestsServed": self.state.request_count,
                    "uptime": str((now - self.state.started_at) // 1000) + "s",
                    "usageLog": config["usageLogPath"] if config["usageLogEnabled"] else None,
                    "tokenExpiresInHours": f"{expires_in:.1f}",
                    "subscriptionType": oauth.get("subscriptionType"),
                    "transformPool": {"enabled": False, "workers": 0, "busy": 0, "queued": 0, "maxQueue": 0},
                    "layers": {
                        "stringReplacements": len(config["replacements"]),
                        "toolNameRenames": len(config["toolRenames"]),
                        "propertyRenames": len(config["propRenames"]),
                        "ccToolStubs": len(CC_TOOL_STUBS) if config["injectCCStubs"] else 0,
                        "systemStripEnabled": config["stripSystemConfig"],
                        "descriptionStripEnabled": config["stripToolDescriptions"],
                    },
                })
            except Exception as e:
                self._write_json(500, {"status": "error", "message": str(e)})
            return

        # Any other GET is proxied like a normal request (no body).
        self._proxy_request()

    def do_POST(self):
        self._proxy_request()

    def do_PUT(self):
        self._proxy_request()

    def do_DELETE(self):
        self._proxy_request()

    def _read_body(self):
        length = self.headers.get("Content-Length")
        if length is None:
            return b""
        try:
            return self.rfile.read(int(length))
        except (TypeError, ValueError):
            return b""

    def _proxy_request(self):
        config = self.config
        self.state.request_count += 1
        req_num = self.state.request_count
        request_started_at = now_ms()

        body = self._read_body()

        try:
            oauth = get_token(config["credsPath"])
        except Exception as e:
            self._write_json(500, {"type": "error", "error": {"message": str(e)}})
            return

        body_str = body.decode("utf-8", errors="replace")
        original_size = len(body_str)
        request_meta = extract_request_metadata(body_str, dict(self.headers.items()), config["bodyPreviewChars"])
        request_model = request_meta["model"]
        size_level = request_size_level(original_size)
        if size_level:
            print(f"[{hms()}] #{req_num} [SIZE-{size_level}] request body {original_size}b model={request_model}; "
                  f"large bodies can stall transforms or signal weak compaction", file=sys.stderr)

        try:
            body_str = process_body(body_str, config)
        except Exception as e:
            append_usage_log(config, {
                "ts": iso_now(), "reqNum": req_num, "method": self.command, "url": self.path,
                "event": "processBody_error", "durationMs": now_ms() - request_started_at,
                "originalBytes": original_size, "model": request_model, "error": str(e), "request": request_meta,
            })
            self._write_json(500, {"type": "error", "error": {"message": "processBody failed: " + str(e)}})
            return

        body = body_str.encode("utf-8")
        headers = build_upstream_headers(dict(self.headers.items()), oauth, len(body))

        ts = hms()
        print(f"[{ts}] #{req_num} {self.command} {self.path} model={request_model} ({original_size}b -> {len(body)}b)")
        if config["bodyPreviewChars"] and (request_meta["firstUserPreview"] or request_meta["lastUserPreview"]):
            print(f"[{ts}] #{req_num} body-preview first={json.dumps(request_meta['firstUserPreview'])} "
                  f"last={json.dumps(request_meta['lastUserPreview'])}")
        append_usage_log(config, {
            "ts": iso_now(), "reqNum": req_num, "method": self.command, "url": self.path, "event": "request",
            "model": request_model, "originalBytes": original_size, "transformedBytes": len(body),
            "sizeLevel": size_level, "request": request_meta,
        })

        self._send_upstream(body, headers, req_num, request_started_at, attempt=1)

    def _send_upstream(self, body, headers, req_num, request_started_at, attempt=1):
        config = self.config
        try:
            conn = http.client.HTTPSConnection(UPSTREAM_HOST, 443, timeout=600)
            conn.request(self.command, self.path, body=body, headers=headers)
            up_res = conn.getresponse()
        except Exception as e:
            if is_retryable_upstream_error(e) and attempt < MAX_UPSTREAM_ATTEMPTS:
                delay = upstream_retry_delay_ms(attempt)
                code = f" code={getattr(e, 'errno', '')}" if getattr(e, "errno", None) else ""
                print(f"[{hms()}] #{req_num} RETRY {attempt + 1}/{MAX_UPSTREAM_ATTEMPTS} after {e}{code} in {delay}ms",
                      file=sys.stderr)
                append_usage_log(config, {
                    "ts": iso_now(), "reqNum": req_num, "event": "retry", "attempt": attempt,
                    "nextAttempt": attempt + 1, "durationMs": now_ms() - request_started_at,
                    "error": str(e), "delayMs": delay,
                })
                time.sleep(delay / 1000.0)
                return self._send_upstream(body, headers, req_num, request_started_at, attempt + 1)
            print(f"[{hms()}] #{req_num} ERR: {e}", file=sys.stderr)
            append_usage_log(config, {
                "ts": iso_now(), "reqNum": req_num, "event": "upstream_error", "attempt": attempt,
                "durationMs": now_ms() - request_started_at, "error": str(e),
            })
            self._write_json(502, {"type": "error", "error": {"message": str(e)}})
            return

        status = up_res.status
        attempt_suffix = f" attempt={attempt}/{MAX_UPSTREAM_ATTEMPTS}" if attempt > 1 else ""
        print(f"[{hms()}] #{req_num} > {status}{attempt_suffix}")
        append_usage_log(config, {
            "ts": iso_now(), "reqNum": req_num, "event": "response_headers", "status": status,
            "attempt": attempt, "durationMs": now_ms() - request_started_at,
        })

        up_headers = {k: v for k, v in up_res.getheaders()}
        content_type = up_res.getheader("content-type") or ""

        # Error (non-200/201): buffer, reverse-map, return.
        if status not in (200, 201):
            err_body = up_res.read()
            conn.close()
            err_text = err_body.decode("utf-8", errors="replace")
            detection = "usage quota" in err_text
            if detection:
                print(f"[{hms()}] #{req_num} DETECTION! Body: {len(body)}b", file=sys.stderr)
            append_usage_log(config, {
                "ts": iso_now(), "reqNum": req_num, "event": "response_error_body", "status": status,
                "attempt": attempt, "durationMs": now_ms() - request_started_at,
                "responseBytes": len(err_text.encode("utf-8")), "detection": detection,
            })
            err_text = reverse_map(err_text, config)
            payload = err_text.encode("utf-8")
            nh = {k: v for k, v in up_headers.items() if k.lower() != "content-length"}
            self.send_response(status)
            for k, v in nh.items():
                if k.lower() in ("transfer-encoding", "connection", "content-encoding"):
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        # Streaming (SSE): stream chunks through reverse_map.
        if "text/event-stream" in content_type:
            self.send_response(status)
            for k, v in up_headers.items():
                if k.lower() in ("transfer-encoding", "connection", "content-length", "content-encoding"):
                    continue
                self.send_header(k, v)
            # Stream as chunked back to the client.
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                while True:
                    chunk = up_res.read(8192)
                    if not chunk:
                        break
                    mapped = reverse_map(chunk.decode("utf-8", errors="replace"), config).encode("utf-8")
                    self.wfile.write(b"%X\r\n%s\r\n" % (len(mapped), mapped))
                self.wfile.write(b"0\r\n\r\n")
                append_usage_log(config, {
                    "ts": iso_now(), "reqNum": req_num, "event": "stream_end", "status": status,
                    "attempt": attempt, "durationMs": now_ms() - request_started_at,
                })
            except Exception as e:
                print(f"[{hms()}] #{req_num} STREAM ERR: {e}", file=sys.stderr)
                append_usage_log(config, {
                    "ts": iso_now(), "reqNum": req_num, "event": "stream_error", "status": status,
                    "attempt": attempt, "durationMs": now_ms() - request_started_at, "error": str(e),
                })
            finally:
                conn.close()
            return

        # Non-streaming JSON: buffer, reverse-map, return.
        resp_body = up_res.read()
        conn.close()
        resp_text = resp_body.decode("utf-8", errors="replace")
        resp_text = reverse_map(resp_text, config)
        payload = resp_text.encode("utf-8")
        append_usage_log(config, {
            "ts": iso_now(), "reqNum": req_num, "event": "response_body", "status": status,
            "attempt": attempt, "durationMs": now_ms() - request_started_at, "responseBytes": len(payload),
        })
        nh = {k: v for k, v in up_headers.items() if k.lower() != "content-length"}
        self.send_response(status)
        for k, v in nh.items():
            if k.lower() in ("transfer-encoding", "connection", "content-encoding"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_server(config):
    ensure_usage_log_dir(config)
    server = ThreadingHTTPServer(("127.0.0.1", config["port"]), Handler)
    server.state = ProxyState(config)

    try:
        oauth = get_token(config["credsPath"])
        now = int(time.time() * 1000)
        h = f"{(oauth.get('expiresAt', 0) - now) / 3600000.0:.1f}"
        print(f"\n  OCPlatform Billing Proxy v{VERSION} (Python)")
        print("  -----------------------------")
        print(f"  Port:              {config['port']}")
        print(f"  Emulating:         Claude Code v{CC_VERSION}")
        print(f"  Subscription:      {oauth.get('subscriptionType')}")
        print(f"  Token expires:     {h}h")
        print(f"  String patterns:   {len(config['replacements'])} sanitize + {len(config['reverseMap'])} reverse")
        print(f"  Tool renames:      {len(config['toolRenames'])} (bidirectional)")
        print(f"  Property renames:  {len(config['propRenames'])} (bidirectional)")
        print(f"  CC tool stubs:     {len(CC_TOOL_STUBS) if config['injectCCStubs'] else 'disabled'}")
        print(f"  System strip:      {'enabled' if config['stripSystemConfig'] else 'disabled'}")
        print(f"  Description strip: {'enabled' if config['stripToolDescriptions'] else 'disabled'}")
        print("  Transform workers: disabled (single-threaded inline)")
        print("  Billing hash:      dynamic (SHA256 fingerprint)")
        print("  CC headers:        Stainless SDK + identity")
        print(f"  Credentials:       {config['credsPath']}")
        print(f"  Usage log:         {config['usageLogPath'] if config['usageLogEnabled'] else 'disabled'}")
        print(f"\n  Ready. Set openclaw.json baseUrl to http://127.0.0.1:{config['port']}\n")
    except Exception as e:
        print(f"  Started on port {config['port']} but credentials error: {e}", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


# --- Main --------------------------------------------------------------------
if __name__ == "__main__":
    start_server(load_config())
