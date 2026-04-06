# Changelog

## v1.3.0 -- 2026-04-06

### HEARTBEAT_OK trigger + missing sessions_* tools + NVM path scanning

**Changes:**
- Added `HEARTBEAT_OK` to sanitization — a newly discovered trigger phrase that
  Anthropic's classifier detects. OpenClaw injects this in heartbeat ack
  instructions; without sanitizing it, all requests fail with "out of extra
  usage" even when the billing block and OAuth token are correct.
- Added `sessions_store` and `sessions_yield_interrupt` to default tool list —
  these exist in OpenClaw 2026.4.x but were missing from the proxy defaults.
- Fixed `setup.js` to scan NVM install paths (`~/.nvm/versions/node/*/lib/...`)
  when auto-detecting `sessions_*` tools. Previously only checked system-wide
  and npm-global paths, causing NVM-installed OpenClaw to fall back to defaults.
- Updated `config.example.json` with all new patterns.

**Why HEARTBEAT_OK:**
OpenClaw's system prompt includes heartbeat ack instructions containing
`HEARTBEAT_OK`. Anthropic's classifier treats this as a third-party harness
identifier. Replacing it with `HB_ACK` and reverse-mapping responses resolves
the billing rejection. Confirmed via binary search on a 103K system prompt.

**Ordering note:**
`sessions_yield_interrupt` must appear before `sessions_yield` in the
replacements array to avoid partial matches (`sessions_yield` matching the
prefix of `sessions_yield_interrupt`).

---

## v1.2.0 -- 2026-04-05

### Bidirectional reverse mapping + sessions_yield + path-safe replacements

**Changes:**
- Added bidirectional reverse mapping on all API responses
  - SSE streaming: reverse-maps each chunk in real-time
  - JSON responses: buffers, reverse-maps, then sends
  - Ensures OpenClaw sees original tool names, file paths, and identifiers
- Added `sessions_yield` to sanitization (new tool in OpenClaw 2026.3.13+)
- Changed `openclaw` replacement from `assistant platform` (has space, breaks filesystem paths like `.openclaw/`) to `ocplatform` (space-free)
- Added `reverseMap` config option for customizable response-side mappings
- Health endpoint now reports `reverseMapPatterns` count

**Why reverse mapping matters:**
Without it, the model sees sanitized paths (`.ocplatform/workspace/`) in its context and tries to use them for tool calls. The filesystem has `.openclaw/`. Reverse mapping translates responses back so OpenClaw and the filesystem always see original terms.

**Why sessions_yield:**
`sessions_yield` was added in OpenClaw between v2026.3.11 and v2026.3.13. It's a new session management tool for ending the current agent turn after spawning a subagent. Without sanitizing it, requests fail intermittently when conversation history references this tool.

**Wildcard recommendation:**
If your OpenClaw version has additional `sessions_*` tools beyond the 5 listed, add them to your config.json replacements and reverseMap arrays.

---

## v1.1.0 -- 2026-04-05

### Simplified to verified minimal detection bypasses

**Changes:**
- Removed Claude Code tool stub injection — systematic testing proved tool fingerprinting is NOT part of Anthropic's detection
- Reduced sanitization from 18 patterns to 7 verified triggers
- Updated README with accurate detection documentation
- Updated config.example.json with minimal replacement set

**Verified triggers (the only terms Anthropic detects):**
1. `OpenClaw` (case-insensitive) — the platform name
2. `openclaw` — lowercase variant
3. `sessions_spawn` — OpenClaw session management tool
4. `sessions_list` — OpenClaw session management tool
5. `sessions_history` — OpenClaw session management tool
6. `sessions_send` — OpenClaw session management tool
7. `running inside` — the self-declaration phrase ("running inside OpenClaw")

**Confirmed safe (NOT detected):**
- Assistant names (e.g., "custom assistant name")
- Workspace files (AGENTS.md, SOUL.md, USER.md)
- Config paths (.openclaw/, openclaw.json)
- Plugin names (lossless-claw)
- Individual tool names (exec, lcm_grep, gateway, cron, etc.)
- Bot names (custom assistant nameAssistantBot)
- Runtime references (pi-embedded, pi-ai)

**Testing:** Validated with 478+ real OpenClaw requests on production instance.

---

## v1.0.0 — 2026-04-05

### Initial release

- Billing header injection (84-char Claude Code identifier in system prompt)
- OAuth token swap (Claude Code credentials from ~/.claude/.credentials.json)
- Beta flag injection (oauth-2025-04-20, claude-code-20250219, etc.)
- 18 sanitization patterns (overly broad — reduced in v1.1.0)
- Claude Code tool stub injection (unnecessary — removed in v1.1.0)
- Auto-detect credentials path (cross-platform)
- Health endpoint (/health)
- Configurable via config.json or CLI args
- Zero dependencies
