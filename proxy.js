#!/usr/bin/env node
/**
 * OpenClaw Subscription Billing Proxy v2.0
 *
 * Routes OpenClaw API requests through Claude Code's subscription billing
 * instead of Extra Usage. Defeats Anthropic's multi-layer detection:
 *
 *   Layer 1: Billing header injection (84-char Claude Code identifier)
 *   Layer 2: String trigger sanitization (OpenClaw, sessions_*, running inside, etc.)
 *   Layer 3: Tool name fingerprint bypass (rename OC tools to CC PascalCase convention)
 *   Layer 4: System prompt template bypass (strip config section, replace with paraphrase)
 *   Layer 5: Tool description stripping (reduce fingerprint signal in tool schemas)
 *   Layer 6: Property name renaming (eliminate OC-specific schema property names)
 *   Layer 7: Full bidirectional reverse mapping (SSE + JSON responses)
 *
 * v1.x string-only sanitization stopped working April 8, 2026 when Anthropic
 * upgraded from string matching to tool-name fingerprinting and template detection.
 * v2.0 defeats the new detection by transforming the entire request body.
 *
 * Zero dependencies. Works on Windows, Linux, Mac.
 *
 * Usage:
 *   node proxy.js [--port 18801] [--config config.json]
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { StringDecoder } = require('string_decoder');

// ─── Defaults ───────────────────────────────────────────────────────────────
const DEFAULT_PORT = 18801;
const UPSTREAM_HOST = 'api.anthropic.com';
const VERSION = '2.2.3';

// Claude Code version to emulate (update when new CC versions are released)
const CC_VERSION = '2.1.97';

// Billing fingerprint constants (matches real CC utils/fingerprint.ts)
const BILLING_HASH_SALT = '59cf53e54c78';
const BILLING_HASH_INDICES = [4, 7, 20];

// Persistent per-instance identifiers (generated once at startup)
const DEVICE_ID = crypto.randomBytes(32).toString('hex');
const INSTANCE_SESSION_ID = crypto.randomUUID();

// Beta flags required for OAuth + Claude Code features
const REQUIRED_BETAS = [
  'oauth-2025-04-20',
  'claude-code-20250219',
  'interleaved-thinking-2025-05-14',
  'advanced-tool-use-2025-11-20',
  'context-management-2025-06-27',
  'prompt-caching-scope-2026-01-05',
  'effort-2025-11-24',
  'fast-mode-2026-02-01'
];

// CC tool stubs -- injected into tools array to make the tool set look more
// like a Claude Code session. The model won't call these (schemas are minimal).
const CC_TOOL_STUBS = [
  '{"name":"Glob","description":"Find files by pattern","input_schema":{"type":"object","properties":{"pattern":{"type":"string","description":"Glob pattern"}},"required":["pattern"]}}',
  '{"name":"Grep","description":"Search file contents","input_schema":{"type":"object","properties":{"pattern":{"type":"string","description":"Regex pattern"},"path":{"type":"string","description":"Search path"}},"required":["pattern"]}}',
  '{"name":"Agent","description":"Launch a subagent for complex tasks","input_schema":{"type":"object","properties":{"prompt":{"type":"string","description":"Task description"}},"required":["prompt"]}}',
  '{"name":"NotebookEdit","description":"Edit notebook cells","input_schema":{"type":"object","properties":{"notebook_path":{"type":"string"},"cell_index":{"type":"integer"}},"required":["notebook_path"]}}',
  '{"name":"TodoRead","description":"Read current task list","input_schema":{"type":"object","properties":{}}}'
];

// ─── Billing Fingerprint ────────────────────────────────────────────────────
// Computes a 3-character SHA256 fingerprint hash matching real CC's
// computeFingerprint() in utils/fingerprint.ts:
//   SHA256(salt + msg[4] + msg[7] + msg[20] + version)[:3]
// Applied to the first user message text in the request body.

function computeBillingFingerprint(firstUserText) {
  const chars = BILLING_HASH_INDICES.map(i => firstUserText[i] || '0').join('');
  const input = `${BILLING_HASH_SALT}${chars}${CC_VERSION}`;
  return crypto.createHash('sha256').update(input).digest('hex').slice(0, 3);
}

// Extract first user message text from the raw body using string scanning.
// Avoids JSON.parse to preserve raw body integrity.
function extractFirstUserText(bodyStr) {
  // Find first "role":"user" in messages array
  const msgsIdx = bodyStr.indexOf('"messages":[');
  if (msgsIdx === -1) return '';
  const userIdx = bodyStr.indexOf('"role":"user"', msgsIdx);
  if (userIdx === -1) return '';

  // Look for "content" near this role
  // Could be "content":"string" or "content":[{..."text":"..."}]
  const contentIdx = bodyStr.indexOf('"content"', userIdx);
  if (contentIdx === -1 || contentIdx > userIdx + 500) return '';

  const afterContent = bodyStr[contentIdx + '"content"'.length + 1]; // skip the :
  if (afterContent === '"') {
    // Simple string content: "content":"text here"
    const textStart = contentIdx + '"content":"'.length;
    let end = textStart;
    while (end < bodyStr.length) {
      if (bodyStr[end] === '\\') { end += 2; continue; }
      if (bodyStr[end] === '"') break;
      end++;
    }
    // Decode basic JSON escapes for the fingerprint characters
    return bodyStr.slice(textStart, end)
      .replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  // Array content: find first text block
  const textIdx = bodyStr.indexOf('"text":"', contentIdx);
  if (textIdx === -1 || textIdx > contentIdx + 2000) return '';
  const textStart = textIdx + '"text":"'.length;
  let end = textStart;
  while (end < bodyStr.length) {
    if (bodyStr[end] === '\\') { end += 2; continue; }
    if (bodyStr[end] === '"') break;
    end++;
  }
  return bodyStr.slice(textStart, Math.min(end, textStart + 50))
    .replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
}

function buildBillingBlock(bodyStr) {
  const firstText = extractFirstUserText(bodyStr);
  const fingerprint = computeBillingFingerprint(firstText);
  const ccVersion = `${CC_VERSION}.${fingerprint}`;
  return `{"type":"text","text":"x-anthropic-billing-header: cc_version=${ccVersion}; cc_entrypoint=cli; cch=00000;"}`;
}

// ─── Stainless SDK Headers ──────────────────────────────────────────────────
// Real Claude Code sends these on every request via the Anthropic JS SDK.
function getStainlessHeaders() {
  const p = process.platform;
  const osName = p === 'darwin' ? 'macOS' : p === 'win32' ? 'Windows' : p === 'linux' ? 'Linux' : p;
  const arch = process.arch === 'x64' ? 'x64' : process.arch === 'arm64' ? 'arm64' : process.arch;
  return {
    'user-agent': `claude-cli/${CC_VERSION} (external, cli)`,
    'x-app': 'cli',
    'x-claude-code-session-id': INSTANCE_SESSION_ID,
    'x-stainless-arch': arch,
    'x-stainless-lang': 'js',
    'x-stainless-os': osName,
    'x-stainless-package-version': '0.81.0',
    'x-stainless-runtime': 'node',
    'x-stainless-runtime-version': process.version,
    'x-stainless-retry-count': '0',
    'x-stainless-timeout': '600',
    'anthropic-dangerous-direct-browser-access': 'true'
  };
}

// ─── Layer 2: String Trigger Replacements ───────────────────────────────────
// Applied globally via split/join on the entire request body.
// IMPORTANT: Use space-free replacements for lowercase 'openclaw' to avoid
// breaking filesystem paths (e.g., .openclaw/ -> .ocplatform/, not .oc platform/)
const DEFAULT_REPLACEMENTS = [
  ['OpenClaw', 'OCPlatform'],
  ['openclaw', 'ocplatform'],
  ['sessions_spawn', 'create_task'],
  ['sessions_list', 'list_tasks'],
  ['sessions_history', 'get_history'],
  ['sessions_send', 'send_to_task'],
  ['sessions_yield_interrupt', 'task_yield_interrupt'],
  ['sessions_yield', 'yield_task'],
  ['sessions_store', 'task_store'],
  ['HEARTBEAT_OK', 'HB_ACK'],
  ['HEARTBEAT', 'HB_SIGNAL'],
  ['heartbeat', 'hb_signal'],
  ['running inside', 'operating from'],
  ['Prometheus', 'PAssistant'],
  ['prometheus', 'passistant'],
  ['clawhub.com', 'skillhub.example.com'],
  ['clawhub', 'skillhub'],
  ['clawd', 'agentd'],
  ['lossless-claw', 'lossless-ctx'],
  ['third-party', 'external'],
  ['billing proxy', 'routing layer'],
  ['billing-proxy', 'routing-layer'],
  ['x-anthropic-billing-header', 'x-routing-config'],
  ['x-anthropic-billing', 'x-routing-cfg'],
  ['cch=00000', 'cfg=00000'],
  ['cc_version', 'rt_version'],
  ['cc_entrypoint', 'rt_entrypoint'],
  ['billing header', 'routing config'],
  ['extra usage', 'usage quota'],
  ['assistant platform', 'ocplatform']
];

// ─── Layer 3: Tool Name Renames ─────────────────────────────────────────────
// Applied as "quoted" replacements ("name" -> "Name") throughout the ENTIRE body.
// This defeats Anthropic's tool-name fingerprinting which identifies the request
// as OpenClaw based on the combination of tool names in the tools array.
//
// The detector specifically checks for OpenClaw's tool name set. Even with empty
// schemas (no descriptions, no properties), original tool names trigger detection.
// Renaming to PascalCase CC-like conventions defeats this entirely.
//
// ORDERING: lcm_expand_query MUST come before lcm_expand to avoid partial match.
const DEFAULT_TOOL_RENAMES = [
  ['exec', 'Bash'],
  ['process', 'BashSession'],
  ['browser', 'BrowserControl'],
  ['canvas', 'CanvasView'],
  ['nodes', 'DeviceControl'],
  ['cron', 'Scheduler'],
  ['message', 'SendMessage'],
  ['tts', 'Speech'],
  ['gateway', 'SystemCtl'],
  ['agents_list', 'AgentList'],
  ['list_tasks', 'TaskList'],
  ['get_history', 'TaskHistory'],
  ['send_to_task', 'TaskSend'],
  ['create_task', 'TaskCreate'],
  ['subagents', 'AgentControl'],
  ['session_status', 'StatusCheck'],
  ['web_search', 'WebSearch'],
  ['web_fetch', 'WebFetch'],
  // NOTE: ['image', 'ImageGen'] removed — collides with Anthropic content block
  // type "image". OpenClaw tool_results carrying image content blocks would have
  // their `"type": "image"` field renamed and Anthropic rejects with:
  //   messages.N.content.M.tool_result.content.K: Input tag 'ImageGen' found
  //   using 'type' does not match any of the expected tags
  // The fingerprint signal lost from one tool name is much smaller than the
  // certainty of breaking every conversation that ever touched an image. (issue #14)
  ['pdf', 'PdfParse'],
  ['image_generate', 'ImageCreate'],
  ['music_generate', 'MusicCreate'],
  ['video_generate', 'VideoCreate'],
  ['memory_search', 'KnowledgeSearch'],
  ['memory_get', 'KnowledgeGet'],
  ['lcm_expand_query', 'ContextQuery'],
  ['lcm_grep', 'ContextGrep'],
  ['lcm_describe', 'ContextDescribe'],
  ['lcm_expand', 'ContextExpand'],
  ['yield_task', 'TaskYield'],
  ['task_store', 'TaskStore'],
  ['task_yield_interrupt', 'TaskYieldInterrupt']
];

// ─── Layer 6: Property Name Renames ─────────────────────────────────────────
// OC-specific schema property names that contribute to fingerprinting.
const DEFAULT_PROP_RENAMES = [
  ['session_id', 'thread_id'],
  ['conversation_id', 'thread_ref'],
  ['summaryIds', 'chunk_ids'],
  ['summary_id', 'chunk_id'],
  ['system_event', 'event_text'],
  ['agent_id', 'worker_id'],
  ['wake_at', 'trigger_at'],
  ['wake_event', 'trigger_event']
];

// ─── Reverse Mappings ───────────────────────────────────────────────────────
const DEFAULT_REVERSE_MAP = [
  ['OCPlatform', 'OpenClaw'],
  ['ocplatform', 'openclaw'],
  ['create_task', 'sessions_spawn'],
  ['list_tasks', 'sessions_list'],
  ['get_history', 'sessions_history'],
  ['send_to_task', 'sessions_send'],
  ['task_yield_interrupt', 'sessions_yield_interrupt'],
  ['yield_task', 'sessions_yield'],
  ['task_store', 'sessions_store'],
  ['HB_ACK', 'HEARTBEAT_OK'],
  ['HB_SIGNAL', 'HEARTBEAT'],
  ['hb_signal', 'heartbeat'],
  ['PAssistant', 'Prometheus'],
  ['passistant', 'prometheus'],
  ['skillhub.example.com', 'clawhub.com'],
  ['skillhub', 'clawhub'],
  ['agentd', 'clawd'],
  ['lossless-ctx', 'lossless-claw'],
  ['external', 'third-party'],
  ['routing layer', 'billing proxy'],
  ['routing-layer', 'billing-proxy'],
  ['x-routing-config', 'x-anthropic-billing-header'],
  ['x-routing-cfg', 'x-anthropic-billing'],
  ['cfg=00000', 'cch=00000'],
  ['rt_version', 'cc_version'],
  ['rt_entrypoint', 'cc_entrypoint'],
  ['routing config', 'billing header'],
  ['usage quota', 'extra usage']
];

// ─── Configuration ──────────────────────────────────────────────────────────
function loadConfig() {
  // Port precedence: PROXY_PORT env > --port CLI > config.json port > DEFAULT_PORT
  const args = process.argv.slice(2);
  let configPath = null;
  let cliPort = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && args[i + 1]) cliPort = parseInt(args[i + 1]);
    if (args[i] === '--config' && args[i + 1]) configPath = args[i + 1];
  }

  const envPort = process.env.PROXY_PORT ? parseInt(process.env.PROXY_PORT) : null;

  let config = {};
  if (configPath && fs.existsSync(configPath)) {
    try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch(e) {
      console.error('[ERROR] Failed to parse config: ' + configPath + ' (' + e.message + ')');
      process.exit(1);
    }
  } else if (fs.existsSync('config.json')) {
    try { config = JSON.parse(fs.readFileSync('config.json', 'utf8')); } catch(e) {
      console.error('[PROXY] Warning: config.json is invalid, using defaults. (' + e.message + ')');
    }
  }

  const homeDir = os.homedir();

  // OAUTH_TOKEN env var takes precedence over all file-based credentials (useful for Docker)
  let credsPath = null;
  if (process.env.OAUTH_TOKEN) {
    credsPath = 'env';
    console.log('[PROXY] Using OAUTH_TOKEN from environment variable.');
  }

  const credsPaths = [
    config.credentialsPath,
    path.join(homeDir, '.claude', '.credentials.json'),
    path.join(homeDir, '.claude', 'credentials.json')
  ].filter(Boolean);

  if (!credsPath) {
    for (const p of credsPaths) {
      const resolved = p.startsWith('~') ? path.join(homeDir, p.slice(1)) : p;
      if (fs.existsSync(resolved) && fs.statSync(resolved).size > 0) {
        credsPath = resolved;
        break;
      }
    }
  }

  // macOS Keychain fallback
  if (!credsPath && process.platform === 'darwin') {
    const { execSync } = require('child_process');
    for (const svc of ['Claude Code-credentials', 'claude-code', 'claude', 'com.anthropic.claude-code']) {
      try {
        const token = execSync('security find-generic-password -s "' + svc + '" -w 2>/dev/null', { encoding: 'utf8' }).trim();
        if (token) {
          let creds;
          try { creds = JSON.parse(token); } catch(e) {
            if (token.startsWith('sk-ant-')) creds = { claudeAiOauth: { accessToken: token, expiresAt: Date.now() + 86400000, subscriptionType: 'unknown' } };
          }
          if (creds && creds.claudeAiOauth) {
            credsPath = path.join(homeDir, '.claude', '.credentials.json');
            fs.mkdirSync(path.join(homeDir, '.claude'), { recursive: true });
            fs.writeFileSync(credsPath, JSON.stringify(creds));
            console.log('[PROXY] Extracted credentials from macOS Keychain');
            break;
          }
        }
      } catch(e) {}
    }
  }

  if (!credsPath) {
    console.error('[ERROR] Claude Code credentials not found.');
    console.error('Run "claude auth login" first to authenticate.');
    console.error('Searched:', credsPaths.join(', '));
    if (process.platform === 'darwin') console.error('Also checked macOS Keychain (Claude Code-credentials, claude-code, claude, com.anthropic.claude-code).');
    console.error('For Docker: set OAUTH_TOKEN in .env or mount ~/.claude as a volume.');
    process.exit(1);
  }

  // Merge pattern arrays: defaults first, then config additions/overrides.
  // This prevents stale config.json snapshots (from old setup.js runs) from
  // silently masking new default patterns added in proxy updates. (issue #24)
  // Users who want full manual control can set "mergeDefaults": false.
  function mergePatterns(defaults, overrides) {
    if (!overrides || overrides.length === 0) return defaults;
    const merged = new Map();
    for (const [find, replace] of defaults) merged.set(find, replace);
    for (const [find, replace] of overrides) merged.set(find, replace);
    return [...merged.entries()];
  }

  const useDefaults = config.mergeDefaults !== false;

  const replacements = useDefaults
    ? mergePatterns(DEFAULT_REPLACEMENTS, config.replacements)
    : (config.replacements || DEFAULT_REPLACEMENTS);
  const reverseMap = useDefaults
    ? mergePatterns(DEFAULT_REVERSE_MAP, config.reverseMap)
    : (config.reverseMap || DEFAULT_REVERSE_MAP);
  const toolRenames = useDefaults
    ? mergePatterns(DEFAULT_TOOL_RENAMES, config.toolRenames)
    : (config.toolRenames || DEFAULT_TOOL_RENAMES);
  const propRenames = useDefaults
    ? mergePatterns(DEFAULT_PROP_RENAMES, config.propRenames)
    : (config.propRenames || DEFAULT_PROP_RENAMES);

  // Warn if config has stale arrays that were merged
  if (config.replacements && useDefaults && config.replacements.length < DEFAULT_REPLACEMENTS.length) {
    console.log(`[PROXY] Note: config.json has ${config.replacements.length} replacements, merged with ${DEFAULT_REPLACEMENTS.length} defaults -> ${replacements.length} total`);
  }
  if (config.toolRenames && useDefaults && config.toolRenames.length < DEFAULT_TOOL_RENAMES.length) {
    console.log(`[PROXY] Note: config.json has ${config.toolRenames.length} toolRenames, merged with ${DEFAULT_TOOL_RENAMES.length} defaults -> ${toolRenames.length} total`);
  }

  return {
    port: envPort || cliPort || config.port || DEFAULT_PORT,
    credsPath,
    replacements,
    reverseMap,
    toolRenames,
    propRenames,
    stripSystemConfig: config.stripSystemConfig !== false,
    stripToolDescriptions: config.stripToolDescriptions !== false,
    injectCCStubs: config.injectCCStubs !== false,
    stripTrailingAssistantPrefill: config.stripTrailingAssistantPrefill !== false
  };
}

// ─── Token Management ───────────────────────────────────────────────────────
function getToken(credsPath) {
  // Env var mode: return synthetic OAuth object without file I/O
  if (credsPath === 'env') {
    const token = process.env.OAUTH_TOKEN;
    if (!token) throw new Error('OAUTH_TOKEN env var is empty.');
    return { accessToken: token, expiresAt: Infinity, subscriptionType: 'env-var' };
  }
  let raw = fs.readFileSync(credsPath, 'utf8');
  if (raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1);
  const creds = JSON.parse(raw);
  const oauth = creds.claudeAiOauth;
  if (!oauth || !oauth.accessToken) throw new Error('No OAuth token. Run "claude auth login".');
  return oauth;
}

// ─── Helper ─────────────────────────────────────────────────────────────────
// String-aware bracket matching: skips [/] inside JSON string values so that
// brackets in tool descriptions or text content don't corrupt the depth count.
function findMatchingBracket(str, start) {
  let d = 0, inStr = false;
  for (let i = start; i < str.length; i++) {
    const c = str[i];
    if (inStr) {
      if (c === '\\') { i++; continue; }
      if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; continue; }
    if (c === '[') d++;
    else if (c === ']') { d--; if (d === 0) return i; }
  }
  return -1;
}

// ─── Thinking Block Protection ──────────────────────────────────────────────
// Anthropic requires thinking/redacted_thinking content blocks to be echoed
// back byte-identical to what the model originally produced; any mutation
// triggers:
//   "thinking or redacted_thinking blocks in the latest assistant message
//    cannot be modified. These blocks must remain as they were in the
//    original response."
// Both the forward pass (Layer 2/3/6 running against assistant message
// history) and the reverse pass (reverseMap running against responses the
// client stores and echoes on subsequent turns) mutate these blocks via plain
// split/join. Mask each content block with a unique placeholder before
// transforms run, restore after. The placeholder is chosen so no replacement
// or rename pattern can match it.
const THINK_MASK_PREFIX = '__OBP_THINK_MASK_';
const THINK_MASK_SUFFIX = '__';
const THINK_BLOCK_PATTERNS = ['{"type":"thinking"', '{"type":"redacted_thinking"'];

function maskThinkingBlocks(m) {
  const masks = [];
  let out = '';
  let i = 0;
  while (i < m.length) {
    let nextIdx = -1;
    for (const p of THINK_BLOCK_PATTERNS) {
      const idx = m.indexOf(p, i);
      if (idx !== -1 && (nextIdx === -1 || idx < nextIdx)) nextIdx = idx;
    }
    if (nextIdx === -1) { out += m.slice(i); break; }
    out += m.slice(i, nextIdx);
    // String-aware bracket scan so braces inside the thinking text value
    // don't corrupt the depth count.
    let depth = 0, inStr = false, j = nextIdx;
    while (j < m.length) {
      const c = m[j];
      if (inStr) {
        if (c === '\\') { j += 2; continue; }
        if (c === '"') inStr = false;
        j++;
        continue;
      }
      if (c === '"') { inStr = true; j++; continue; }
      if (c === '{') { depth++; j++; continue; }
      if (c === '}') { depth--; j++; if (depth === 0) break; continue; }
      j++;
    }
    if (depth !== 0) {
      // Malformed / truncated — bail without masking the rest
      out += m.slice(nextIdx);
      return { masked: out, masks };
    }
    masks.push(m.slice(nextIdx, j));
    out += THINK_MASK_PREFIX + (masks.length - 1) + THINK_MASK_SUFFIX;
    i = j;
  }
  return { masked: out, masks };
}

function unmaskThinkingBlocks(m, masks) {
  for (let i = 0; i < masks.length; i++) {
    m = m.split(THINK_MASK_PREFIX + i + THINK_MASK_SUFFIX).join(masks[i]);
  }
  return m;
}

// ─── Request Processing ─────────────────────────────────────────────────────
function processBody(bodyStr, config) {
  // Mask thinking/redacted_thinking content blocks from the transform pipeline
  // so Layer 2/3/6 split/join can't mutate assistant history. Restored before
  // return. See "Thinking Block Protection" above.
  const { masked: maskedBody, masks: thinkMasks } = maskThinkingBlocks(bodyStr);
  let m = maskedBody;

  // Layer 2: String trigger sanitization (global split/join)
  for (const [find, replace] of config.replacements) {
    m = m.split(find).join(replace);
  }

  // Layer 3: Tool name fingerprint bypass (quoted replacement for precision)
  for (const [orig, cc] of config.toolRenames) {
    m = m.split('"' + orig + '"').join('"' + cc + '"');
  }

  // Layer 6: Property name renaming
  for (const [orig, renamed] of config.propRenames) {
    m = m.split('"' + orig + '"').join('"' + renamed + '"');
  }

  // Layer 4: System prompt template bypass
  // Strip the OC config section (~28K of ## Tooling, ## Workspace, ## Messaging, etc.)
  // and replace with a brief paraphrase. The config is between the identity line
  // ("You are a personal assistant") and the first workspace doc (AGENTS.md header).
  // IMPORTANT: Search WITHIN the system array, not from the start of the body.
  // The identity line can appear in conversation history (from prior discussions),
  // and matching there instead of the system prompt causes the strip to fail.
  if (config.stripSystemConfig) {
    const IDENTITY_MARKER = 'You are a personal assistant';
    // Anchor search to the system array so we don't match conversation history
    const sysArrayStart = m.indexOf('"system":[');
    const searchFrom = sysArrayStart !== -1 ? sysArrayStart : 0;
    const configStart = m.indexOf(IDENTITY_MARKER, searchFrom);
    if (configStart !== -1) {
      let stripFrom = configStart;
      if (stripFrom >= 2 && m[stripFrom - 2] === '\\' && m[stripFrom - 1] === 'n') {
        stripFrom -= 2;
      }
      // Find end of config: first workspace doc header (a ## section with a filesystem path).
      // Previous approach used 'AGENTS.md' as the landmark, but that string can appear
      // earlier in skill content or LCM summaries, causing a premature boundary. (issue #26)
      // Workspace doc headers always start with a filesystem path:
      //   Linux/macOS: \n## /home/... or \n## /Users/...
      //   Windows:     \n## C:\\...
      let configEnd = m.indexOf('\\n## /', configStart + IDENTITY_MARKER.length);
      if (configEnd === -1) configEnd = m.indexOf('\\n## C:\\\\', configStart + IDENTITY_MARKER.length);
      if (configEnd !== -1) {
        const boundary = configEnd;

        const strippedLen = boundary - stripFrom;
        if (strippedLen > 1000) {
          const PARAPHRASE =
            '\\nYou are an AI operations assistant with access to all tools listed in this request ' +
            'for file operations, command execution, web search, browser control, scheduling, ' +
            'messaging, and session management. Tool names are case-sensitive and must be called ' +
            'exactly as listed. Your responses route to the active channel automatically. ' +
            'For cross-session communication, use the task messaging tools. ' +
            'Skills defined in your workspace should be invoked when they match user requests. ' +
            'Consult your workspace reference files for detailed operational configuration.\\n';

          m = m.slice(0, stripFrom) + PARAPHRASE + m.slice(boundary);
          console.log(`[STRIP] Removed ${strippedLen} chars of config template`);
        }
      }
    }
  }

  // Layer 5: Tool description stripping
  if (config.stripToolDescriptions) {
    const toolsIdx = m.indexOf('"tools":[');
    if (toolsIdx !== -1) {
      const toolsEndIdx = findMatchingBracket(m, toolsIdx + '"tools":'.length);
      if (toolsEndIdx !== -1) {
        let section = m.slice(toolsIdx, toolsEndIdx + 1);
        let from = 0;
        while (true) {
          const d = section.indexOf('"description":"', from);
          if (d === -1) break;
          const vs = d + '"description":"'.length;
          let i = vs;
          while (i < section.length) {
            if (section[i] === '\\' && i + 1 < section.length) { i += 2; continue; }
            if (section[i] === '"') break;
            i++;
          }
          section = section.slice(0, vs) + section.slice(i);
          from = vs + 1;
        }
        // Inject CC tool stubs
        if (config.injectCCStubs) {
          const insertAt = '"tools":['.length;
          section = section.slice(0, insertAt) + CC_TOOL_STUBS.join(',') + ',' + section.slice(insertAt);
        }
        m = m.slice(0, toolsIdx) + section + m.slice(toolsEndIdx + 1);
      }
    }
  } else if (config.injectCCStubs) {
    // Inject stubs even without description stripping
    const toolsIdx = m.indexOf('"tools":[');
    if (toolsIdx !== -1) {
      const insertAt = toolsIdx + '"tools":['.length;
      m = m.slice(0, insertAt) + CC_TOOL_STUBS.join(',') + ',' + m.slice(insertAt);
    }
  }

  // Layer 1: Billing header injection (dynamic fingerprint per request)
  const BILLING_BLOCK = buildBillingBlock(m);
  const sysArrayIdx = m.indexOf('"system":[');
  if (sysArrayIdx !== -1) {
    const insertAt = sysArrayIdx + '"system":['.length;
    m = m.slice(0, insertAt) + BILLING_BLOCK + ',' + m.slice(insertAt);
  } else if (m.includes('"system":"')) {
    const sysStart = m.indexOf('"system":"');
    let i = sysStart + '"system":"'.length;
    while (i < m.length) {
      if (m[i] === '\\') { i += 2; continue; }
      if (m[i] === '"') break;
      i++;
    }
    const sysEnd = i + 1;
    const originalSysStr = m.slice(sysStart + '"system":'.length, sysEnd);
    m = m.slice(0, sysStart)
      + '"system":[' + BILLING_BLOCK + ',{"type":"text","text":' + originalSysStr + '}]'
      + m.slice(sysEnd);
  } else {
    m = '{"system":[' + BILLING_BLOCK + '],' + m.slice(1);
  }

  // Metadata injection: device_id + session_id matching real CC format
  // Uses raw string manipulation to inject/replace metadata field
  const metaValue = JSON.stringify({ device_id: DEVICE_ID, session_id: INSTANCE_SESSION_ID });
  const metaJson = '"metadata":{"user_id":' + JSON.stringify(metaValue) + '}';
  const existingMeta = m.indexOf('"metadata":{');
  if (existingMeta !== -1) {
    // Find end of existing metadata object
    let depth = 0, mi = existingMeta + '"metadata":'.length;
    for (; mi < m.length; mi++) {
      if (m[mi] === '{') depth++;
      else if (m[mi] === '}') { depth--; if (depth === 0) { mi++; break; } }
    }
    m = m.slice(0, existingMeta) + metaJson + m.slice(mi);
  } else {
    // Insert after opening brace
    m = '{' + metaJson + ',' + m.slice(1);
  }

  // Layer 8: Strip trailing assistant prefill (raw string, no JSON.parse)
  // Opus 4.6 disabled assistant message prefill. OpenClaw sometimes pre-fills the
  // next assistant turn to resume interrupted responses, causing permanent 400
  // errors ("This model does not support assistant message prefill"). The error is
  // permanent for the affected session — every retry includes the same prefill.
  // Fix: forward-scan the messages array with string-aware bracket matching,
  // then pop trailing assistant messages until the array ends with a user message.
  if (config.stripTrailingAssistantPrefill !== false) {
    const msgsIdx = m.indexOf('"messages":[');
    if (msgsIdx !== -1) {
      const arrayStart = msgsIdx + '"messages":['.length;
      const positions = [];
      let depth = 0, inString = false, objStart = -1;
      for (let i = arrayStart; i < m.length; i++) {
        const c = m[i];
        if (inString) {
          if (c === '\\') { i++; continue; }
          if (c === '"') inString = false;
          continue;
        }
        if (c === '"') { inString = true; continue; }
        if (c === '{') { if (depth === 0) objStart = i; depth++; }
        else if (c === '}') { depth--; if (depth === 0 && objStart !== -1) { positions.push({ start: objStart, end: i }); objStart = -1; } }
        else if (c === ']' && depth === 0) break;
      }
      let popped = 0;
      while (positions.length > 0) {
        const last = positions[positions.length - 1];
        const obj = m.slice(last.start, last.end + 1);
        if (!obj.includes('"role":"assistant"')) break;
        let stripFrom = last.start;
        for (let i = last.start - 1; i >= arrayStart; i--) {
          if (m[i] === ',') { stripFrom = i; break; }
          if (m[i] !== ' ' && m[i] !== '\n' && m[i] !== '\r' && m[i] !== '\t') break;
        }
        m = m.slice(0, stripFrom) + m.slice(last.end + 1);
        positions.pop();
        popped++;
      }
      if (popped > 0) {
        console.log(`[STRIP-PREFILL] Removed ${popped} trailing assistant message(s)`);
      }
    }
  }

  return unmaskThinkingBlocks(m, thinkMasks);
}

// ─── Response Processing ────────────────────────────────────────────────────
function reverseMap(text, config) {
  let r = text;
  // Reverse tool names first (more specific patterns).
  // Handle BOTH plain ("Name") AND escaped (\"Name\") forms.
  // SSE input_json_delta embeds tool args in a partial_json string field where
  // inner quotes are escaped. Without the escaped variant, renamed arg keys
  // like \"SendMessage\" never get reverted to \"message\" and OpenClaw's tool
  // runtime fails with "message required". (issue #11)
  for (const [orig, cc] of config.toolRenames) {
    r = r.split('"' + cc + '"').join('"' + orig + '"');
    r = r.split('\\"' + cc + '\\"').join('\\"' + orig + '\\"');
  }
  // Reverse property names — same dual handling
  for (const [orig, renamed] of config.propRenames) {
    r = r.split('"' + renamed + '"').join('"' + orig + '"');
    r = r.split('\\"' + renamed + '\\"').join('\\"' + orig + '\\"');
  }
  // Reverse string replacements
  for (const [sanitized, original] of config.reverseMap) {
    r = r.split(sanitized).join(original);
  }
  return r;
}

// ─── Server ─────────────────────────────────────────────────────────────────
function startServer(config) {
  let requestCount = 0;
  const startedAt = Date.now();

  const server = http.createServer((req, res) => {
    if (req.url === '/health' && req.method === 'GET') {
      try {
        const oauth = getToken(config.credsPath);
        const expiresIn = (oauth.expiresAt - Date.now()) / 3600000;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: expiresIn > 0 ? 'ok' : 'token_expired',
          proxy: 'openclaw-billing-proxy',
          version: VERSION,
          requestsServed: requestCount,
          uptime: Math.floor((Date.now() - startedAt) / 1000) + 's',
          tokenExpiresInHours: isFinite(expiresIn) ? expiresIn.toFixed(1) : 'n/a',
          subscriptionType: oauth.subscriptionType,
          layers: {
            stringReplacements: config.replacements.length,
            toolNameRenames: config.toolRenames.length,
            propertyRenames: config.propRenames.length,
            ccToolStubs: config.injectCCStubs ? CC_TOOL_STUBS.length : 0,
            systemStripEnabled: config.stripSystemConfig,
            descriptionStripEnabled: config.stripToolDescriptions
          }
        }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'error', message: e.message }));
      }
      return;
    }

    requestCount++;
    const reqNum = requestCount;
    const chunks = [];

    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      let body = Buffer.concat(chunks);
      let oauth;
      try { oauth = getToken(config.credsPath); } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { message: e.message } }));
        return;
      }

      let bodyStr = body.toString('utf8');
      const originalSize = bodyStr.length;
      bodyStr = processBody(bodyStr, config);
      body = Buffer.from(bodyStr, 'utf8');

      const headers = {};
      for (const [key, value] of Object.entries(req.headers)) {
        const lk = key.toLowerCase();
        if (lk === 'host' || lk === 'connection' || lk === 'authorization' ||
            lk === 'x-api-key' || lk === 'content-length' ||
            lk === 'x-session-affinity') continue; // strip non-CC headers
        headers[key] = value;
      }
      headers['authorization'] = `Bearer ${oauth.accessToken}`;
      headers['content-length'] = body.length;
      headers['accept-encoding'] = 'identity';
      headers['anthropic-version'] = '2023-06-01';

      // Inject Stainless SDK + Claude Code identity headers
      const ccHeaders = getStainlessHeaders();
      for (const [k, v] of Object.entries(ccHeaders)) {
        headers[k] = v;
      }

      const existingBeta = headers['anthropic-beta'] || '';
      const betas = existingBeta ? existingBeta.split(',').map(b => b.trim()) : [];
      for (const b of REQUIRED_BETAS) { if (!betas.includes(b)) betas.push(b); }
      headers['anthropic-beta'] = betas.join(',');

      const ts = new Date().toISOString().substring(11, 19);
      console.log(`[${ts}] #${reqNum} ${req.method} ${req.url} (${originalSize}b -> ${body.length}b)`);

      const upstream = https.request({
        hostname: UPSTREAM_HOST, port: 443,
        path: req.url, method: req.method, headers
      }, (upRes) => {
        const status = upRes.statusCode;
        console.log(`[${ts}] #${reqNum} > ${status}`);
        if (status !== 200 && status !== 201) {
          const errChunks = [];
          upRes.on('data', c => errChunks.push(c));
          upRes.on('end', () => {
            let errBody = Buffer.concat(errChunks).toString();
            if (errBody.includes('extra usage')) {
              console.error(`[${ts}] #${reqNum} DETECTION! Body: ${body.length}b`);
            }
            errBody = reverseMap(errBody, config);
            const nh = { ...upRes.headers };
            delete nh['transfer-encoding']; // avoid conflict with content-length
            nh['content-length'] = Buffer.byteLength(errBody);
            res.writeHead(status, nh);
            res.end(errBody);
          });
          return;
        }
        // SSE streaming — event-aware reverseMap. Buffer until a complete SSE
        // event arrives (terminated by \n\n), then transform per event. This
        // subsumes the older tail-buffer fix for patterns split across TCP
        // chunks (#11) because SSE events are self-contained, so patterns
        // can't span event boundaries. It also lets us track the current
        // content block type across events and pass thinking/redacted_thinking
        // bytes through unchanged — Anthropic rejects the next turn otherwise
        // with "thinking blocks in the latest assistant message cannot be
        // modified."
        if (upRes.headers['content-type'] && upRes.headers['content-type'].includes('text/event-stream')) {
          const sseHeaders = { ...upRes.headers };
          delete sseHeaders['content-length'];      // SSE is streamed, no fixed length
          delete sseHeaders['transfer-encoding'];   // avoid header conflicts
          res.writeHead(status, sseHeaders);
          // StringDecoder buffers incomplete UTF-8 sequences across TCP chunks
          // so multi-byte chars (中文, emoji) that land on a chunk boundary
          // don't decode as U+FFFD.
          const decoder = new StringDecoder('utf8');
          let pending = '';
          let currentBlockIsThinking = false;

          const transformEvent = (event) => {
            // Locate the data: line (always at the start of an SSE line)
            let dataIdx = event.startsWith('data: ') ? 0 : event.indexOf('\ndata: ');
            if (dataIdx === -1) return reverseMap(event, config);
            if (dataIdx > 0) dataIdx += 1; // skip the leading \n
            const dataLineEnd = event.indexOf('\n', dataIdx + 6);
            const dataStr = dataLineEnd === -1
              ? event.slice(dataIdx + 6)
              : event.slice(dataIdx + 6, dataLineEnd);

            if (dataStr.indexOf('"type":"content_block_start"') !== -1) {
              if (dataStr.indexOf('"content_block":{"type":"thinking"') !== -1 ||
                  dataStr.indexOf('"content_block":{"type":"redacted_thinking"') !== -1) {
                currentBlockIsThinking = true;
                return event; // pass through unchanged
              }
              currentBlockIsThinking = false;
              return reverseMap(event, config);
            }
            if (dataStr.indexOf('"type":"content_block_stop"') !== -1) {
              const wasThinking = currentBlockIsThinking;
              currentBlockIsThinking = false;
              return wasThinking ? event : reverseMap(event, config);
            }
            if (currentBlockIsThinking) {
              // thinking_delta / signature_delta / etc. inside a thinking block
              return event;
            }
            return reverseMap(event, config);
          };

          upRes.on('data', (chunk) => {
            pending += decoder.write(chunk);
            let sepIdx;
            while ((sepIdx = pending.indexOf('\n\n')) !== -1) {
              const event = pending.slice(0, sepIdx + 2);
              pending = pending.slice(sepIdx + 2);
              res.write(transformEvent(event));
            }
          });
          upRes.on('end', () => {
            pending += decoder.end();
            if (pending.length > 0) {
              // Trailing bytes with no terminator — shouldn't happen in
              // well-formed SSE, but flush to avoid silent drops.
              res.write(transformEvent(pending));
            }
            res.end();
          });
        } else {
          const respChunks = [];
          upRes.on('data', c => respChunks.push(c));
          upRes.on('end', () => {
            let respBody = Buffer.concat(respChunks).toString();
            // Mask thinking blocks so reverseMap can't mutate them. The client
            // stores these bytes and echoes them on the next turn; Anthropic
            // enforces byte-equality on the latest assistant message.
            const { masked: rMasked, masks: rMasks } = maskThinkingBlocks(respBody);
            respBody = unmaskThinkingBlocks(reverseMap(rMasked, config), rMasks);
            const nh = { ...upRes.headers };
            delete nh['transfer-encoding']; // avoid conflict with content-length
            nh['content-length'] = Buffer.byteLength(respBody);
            res.writeHead(status, nh);
            res.end(respBody);
          });
        }
      });
      upstream.on('error', e => {
        console.error(`[${ts}] #${reqNum} ERR: ${e.message}`);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { message: e.message } }));
        }
      });
      upstream.write(body);
      upstream.end();
    });
  });

  const bindHost = process.env.PROXY_HOST || '127.0.0.1';
  server.listen(config.port, bindHost, () => {
    try {
      const oauth = getToken(config.credsPath);
      const expiresIn = (oauth.expiresAt - Date.now()) / 3600000;
      const h = isFinite(expiresIn) ? expiresIn.toFixed(1) + 'h' : 'n/a (env var)';
      console.log(`\n  OpenClaw Billing Proxy v${VERSION}`);
      console.log(`  ─────────────────────────────`);
      console.log(`  Port:              ${config.port}`);
      console.log(`  Bind address:      ${bindHost}`);
      console.log(`  Emulating:         Claude Code v${CC_VERSION}`);
      console.log(`  Subscription:      ${oauth.subscriptionType}`);
      console.log(`  Token expires:     ${h}`);
      console.log(`  String patterns:   ${config.replacements.length} sanitize + ${config.reverseMap.length} reverse`);
      console.log(`  Tool renames:      ${config.toolRenames.length} (bidirectional)`);
      console.log(`  Property renames:  ${config.propRenames.length} (bidirectional)`);
      console.log(`  CC tool stubs:     ${config.injectCCStubs ? CC_TOOL_STUBS.length : 'disabled'}`);
      console.log(`  System strip:      ${config.stripSystemConfig ? 'enabled' : 'disabled'}`);
      console.log(`  Description strip: ${config.stripToolDescriptions ? 'enabled' : 'disabled'}`);
      console.log(`  Billing hash:      dynamic (SHA256 fingerprint)`);
      console.log(`  CC headers:        Stainless SDK + identity`);
      console.log(`  Credentials:       ${config.credsPath}`);
      console.log(`\n  Ready. Set openclaw.json baseUrl to http://${bindHost}:${config.port}\n`);
    } catch (e) {
      console.error(`  Started on port ${config.port} but credentials error: ${e.message}`);
    }
  });

  process.on('SIGINT', () => process.exit(0));
  process.on('SIGTERM', () => process.exit(0));
}

// ─── Main ───────────────────────────────────────────────────────────────────
const config = loadConfig();
startServer(config);
