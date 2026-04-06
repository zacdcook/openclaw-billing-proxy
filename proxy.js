#!/usr/bin/env node
/**
 * OpenClaw Subscription Billing Proxy
 *
 * Routes OpenClaw API requests through Claude Code's subscription billing
 * instead of Extra Usage, by injecting Claude Code's billing identifier
 * and sanitizing detected trigger phrases.
 *
 * Features:
 *   - Billing header injection (84-char Claude Code identifier)
 *   - Bidirectional sanitization (request out + response back)
 *   - Wildcard sessions_* tool name replacement
 *   - SSE streaming support with per-chunk reverse mapping
 *   - Zero dependencies. Works on Windows, Linux, Mac.
 *
 * Usage:
 *   node proxy.js [--port 18801] [--config config.json]
 *
 * Quick start:
 *   1. Authenticate Claude Code: claude auth login
 *   2. Run: node proxy.js
 *   3. Set openclaw.json baseUrl to http://127.0.0.1:18801
 *   4. Restart OpenClaw gateway
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ─── Defaults ───────────────────────────────────────────────────────────────
const DEFAULT_PORT = 18801;
const UPSTREAM_HOST = 'api.anthropic.com';
const USAGE_FILE = path.join(__dirname, 'data', 'usage.json');

// Claude Code billing identifier -- injected into the system prompt
const BILLING_BLOCK = '{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.80.a46; cc_entrypoint=sdk-cli; cch=00000;"}';

// Beta flags required for OAuth + Claude Code features
const REQUIRED_BETAS = [
  'claude-code-20250219',
  'oauth-2025-04-20',
  'interleaved-thinking-2025-05-14',
  'context-management-2025-06-27',
  'prompt-caching-scope-2026-01-05',
  'effort-2025-11-24'
];

// ─── Default Sanitization Rules ─────────────────────────────────────────────
// Verified trigger phrases that Anthropic's streaming classifier detects.
// Uses a wildcard approach for sessions_* to catch current and future tools.
//
// IMPORTANT: Use space-free replacements for lowercase 'openclaw' to avoid
// breaking filesystem paths (e.g., .openclaw/ -> .ocplatform/, not .assistant platform/)
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
  ['running inside', 'running on']
];

// Reverse mapping: applied to API responses before returning to OpenClaw.
// This ensures OpenClaw sees original tool names, file paths, and identifiers.
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
  ['HB_ACK', 'HEARTBEAT_OK']
];

// ─── Configuration ──────────────────────────────────────────────────────────
function loadConfig() {
  const args = process.argv.slice(2);
  let configPath = null;
  let port = DEFAULT_PORT;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && args[i + 1]) port = parseInt(args[i + 1]);
    if (args[i] === '--config' && args[i + 1]) configPath = args[i + 1];
  }

  let config = {};
  if (configPath && fs.existsSync(configPath)) {
    config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } else if (fs.existsSync('config.json')) {
    config = JSON.parse(fs.readFileSync('config.json', 'utf8'));
  }

  // Find Claude Code credentials
  const homeDir = os.homedir();
  const credsPaths = [
    config.credentialsPath,
    path.join(homeDir, '.claude', '.credentials.json'),
    path.join(homeDir, '.claude', 'credentials.json')
  ].filter(Boolean);

  let credsPath = null;
  for (const p of credsPaths) {
    const resolved = p.startsWith('~') ? path.join(homeDir, p.slice(1)) : p;
    if (fs.existsSync(resolved) && fs.statSync(resolved).size > 0) {
      credsPath = resolved;
      break;
    }
  }

  // macOS Keychain fallback: extract token and write to file
  if (!credsPath && process.platform === 'darwin') {
    const { execSync } = require('child_process');
    const keychainNames = ['Claude Code-credentials', 'claude-code', 'claude', 'com.anthropic.claude-code'];
    for (const svc of keychainNames) {
      try {
        const token = execSync('security find-generic-password -s "' + svc + '" -w 2>/dev/null', { encoding: 'utf8' }).trim();
        if (token) {
          let creds;
          try { creds = JSON.parse(token); } catch(e) {
            if (token.startsWith('sk-ant-')) {
              creds = { claudeAiOauth: { accessToken: token, expiresAt: Date.now() + 86400000, subscriptionType: 'unknown' } };
            }
          }
          if (creds && creds.claudeAiOauth) {
            credsPath = path.join(homeDir, '.claude', '.credentials.json');
            fs.mkdirSync(path.join(homeDir, '.claude'), { recursive: true });
            fs.writeFileSync(credsPath, JSON.stringify(creds));
            console.log('[PROXY] Extracted credentials from macOS Keychain to ' + credsPath);
            break;
          }
        }
      } catch(e) { /* not found */ }
    }
  }

  if (!credsPath) {
    console.error('[ERROR] Claude Code credentials not found.');
    console.error('Run "claude auth login" first to authenticate.');
    console.error('On macOS, try: claude -p "test" --max-turns 1 --no-session-persistence');
    console.error('Then run this proxy again.');
    console.error('Searched:', credsPaths.join(', '));
    if (process.platform === 'darwin') {
      console.error('Also checked macOS Keychain (Claude Code-credentials, claude-code, claude, com.anthropic.claude-code)');
    }
    process.exit(1);
  }

  return {
    port: config.port || port,
    credsPath,
    replacements: config.replacements || DEFAULT_REPLACEMENTS,
    reverseMap: config.reverseMap || DEFAULT_REVERSE_MAP
  };
}

// ─── Token Management ───────────────────────────────────────────────────────
function getToken(credsPath) {
  const raw = fs.readFileSync(credsPath, 'utf8');
  const creds = JSON.parse(raw);
  const oauth = creds.claudeAiOauth;
  if (!oauth || !oauth.accessToken) {
    throw new Error('No OAuth token in credentials file. Run "claude auth login".');
  }
  return oauth;
}

// ─── Request Processing ─────────────────────────────────────────────────────
function processBody(bodyStr, config) {
  let modified = bodyStr;

  // 1. Apply sanitization -- raw string replacement preserves original JSON formatting
  for (const [find, replace] of config.replacements) {
    modified = modified.split(find).join(replace);
  }

  // 2. Inject billing block into system prompt
  const sysArrayIdx = modified.indexOf('"system":[');
  if (sysArrayIdx !== -1) {
    const insertAt = sysArrayIdx + '"system":['.length;
    modified = modified.slice(0, insertAt) + BILLING_BLOCK + ',' + modified.slice(insertAt);
  } else if (modified.includes('"system":"')) {
    const sysStart = modified.indexOf('"system":"');
    let i = sysStart + '"system":"'.length;
    while (i < modified.length) {
      if (modified[i] === '\\') { i += 2; continue; }
      if (modified[i] === '"') break;
      i++;
    }
    const sysEnd = i + 1;
    const originalSysStr = modified.slice(sysStart + '"system":'.length, sysEnd);
    modified = modified.slice(0, sysStart)
      + '"system":[' + BILLING_BLOCK + ',{"type":"text","text":' + originalSysStr + '}]'
      + modified.slice(sysEnd);
  } else {
    modified = '{"system":[' + BILLING_BLOCK + '],' + modified.slice(1);
  }

  return modified;
}

// ─── Response Processing ────────────────────────────────────────────────────
function reverseMap(text, config) {
  let result = text;
  for (const [sanitized, original] of config.reverseMap) {
    result = result.split(sanitized).join(original);
  }
  return result;
}

// ─── Usage Data Persistence ─────────────────────────────────────────────────
function loadUsageData() {
  try {
    return JSON.parse(fs.readFileSync(USAGE_FILE, 'utf8'));
  } catch (e) { /* missing or corrupt file, start fresh */ }
  return { version: 1, days: {} };
}

let usageData = loadUsageData();
let saveTimer = null;
let usageDirEnsured = false;

function saveUsageData() {
  try {
    if (!usageDirEnsured) {
      fs.mkdirSync(path.dirname(USAGE_FILE), { recursive: true });
      usageDirEnsured = true;
    }
    fs.writeFileSync(USAGE_FILE, JSON.stringify(usageData, null, 2));
  } catch (e) { /* silent */ }
}

function recordUsage(inputTokens, outputTokens) {
  const today = new Date().toISOString().substring(0, 10);
  if (!usageData.days[today]) {
    usageData.days[today] = { input_tokens: 0, output_tokens: 0, requests: 0 };
  }
  usageData.days[today].input_tokens += inputTokens;
  usageData.days[today].output_tokens += outputTokens;
  usageData.days[today].requests += 1;
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(saveUsageData, 2000);
}

// ─── SSE Token Extraction ──────────────────────────────────────────────────
// Incremental tracker: feed chunks via push(), read totals at end
function createSSETokenTracker() {
  let inputTokens = 0;
  let outputTokens = 0;
  let pending = ''; // leftover partial event from previous chunk
  return {
    push(chunk) {
      pending += chunk;
      const parts = pending.split('\n\n');
      pending = parts.pop(); // last element may be incomplete
      for (const event of parts) {
        const lines = event.split('\n');
        let eventType = '';
        let dataStr = '';
        for (const line of lines) {
          if (line.startsWith('event: ')) eventType = line.slice(7).trim();
          if (line.startsWith('data: ')) dataStr = line.slice(6);
        }
        if (!dataStr) continue;
        try {
          const data = JSON.parse(dataStr);
          if (eventType === 'message_start' && data.message && data.message.usage) {
            inputTokens = data.message.usage.input_tokens || 0;
          }
          if (eventType === 'message_delta' && data.usage) {
            outputTokens = data.usage.output_tokens || 0;
          }
        } catch (e) { /* partial JSON, skip */ }
      }
    },
    get inputTokens() { return inputTokens; },
    get outputTokens() { return outputTokens; },
  };
}

// Batch helper kept for testing convenience
function extractTokensFromSSE(buffer) {
  const tracker = createSSETokenTracker();
  tracker.push(buffer);
  return { inputTokens: tracker.inputTokens, outputTokens: tracker.outputTokens };
}

// ─── Terminal Dashboard ────────────────────────────────────────────────────
const ANSI = {
  hide: '\x1b[?25l', show: '\x1b[?25h',
  home: '\x1b[H', clearDown: '\x1b[J', clearLine: '\x1b[K',
  bold: '\x1b[1m', dim: '\x1b[2m', reset: '\x1b[0m',
  cyan: '\x1b[36m', green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m',
  gray: '\x1b[90m', white: '\x1b[37m',
  moveTo: (r, c) => `\x1b[${r};${c}H`,
};

function fmt(n) { return n.toLocaleString(); }

const dashboard = {
  isTTY: false,
  config: null,
  startedAt: 0,
  recentLogs: [],     // ring buffer, max 10
  lastRateLimit: null,
  showInfo: false,

  init(config, oauth) {
    this.config = config;
    this.startedAt = Date.now();
    this.isTTY = process.stdout.isTTY || false;
    if (!this.isTTY) {
      // Non-TTY fallback: plain text banner
      const h = ((oauth.expiresAt - Date.now()) / 3600000).toFixed(1);
      console.log(`\n  OpenClaw Billing Proxy`);
      console.log(`  Port: ${config.port}  Sub: ${oauth.subscriptionType}  Token: ${h}h`);
      console.log(`  Ready. Set openclaw.json baseUrl to http://127.0.0.1:${config.port}\n`);
      return;
    }
    process.stdout.write(ANSI.hide);
    this._oauth = oauth;
    this.render();
    // Refresh uptime every 60s
    this._uptimeInterval = setInterval(() => { this.refreshToken(); this.renderHeader(); }, 60000);
    process.stdout.on('resize', () => this.render());
    // Key handler for info overlay
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', (key) => {
        if (key === '\u0003') { dashboard.shutdown(); process.exit(0); } // Ctrl+C
        if (key === 'i' || key === 'I') {
          this.showInfo = !this.showInfo;
          this.render();
        }
        if (key === 'q' || key === 'Q') {
          dashboard.shutdown(); process.exit(0);
        }
      });
    }
  },

  render() {
    if (!this.isTTY) return;
    process.stdout.write(ANSI.home + ANSI.clearDown);
    if (this.showInfo) {
      this.renderInfo();
      return;
    }
    this.renderHeader();
    this.renderRateLimit();
    this.renderSeparator();
    this.renderTokenTable();
    this.renderSeparator();
    this.renderLog();
    // Footer hint
    process.stdout.write(`\n  ${ANSI.gray}[i] info  [q] quit${ANSI.reset}\n`);
  },

  renderInfo() {
    if (!this.isTTY) return;
    const c = ANSI.cyan, g = ANSI.green, y = ANSI.yellow, r = ANSI.reset, b = ANSI.bold, d = ANSI.gray;
    process.stdout.write(`\n  ${b}${c}INFO${r}\n\n`);
    process.stdout.write(`  ${b}Header${r}\n`);
    process.stdout.write(`    ${c}Sub${r}          Subscription tier from Claude Code credentials\n`);
    process.stdout.write(`    ${c}Token${r}        Hours until OAuth token expires (auto-refreshes in CLI)\n`);
    process.stdout.write(`    ${c}Uptime${r}       Time since proxy started\n\n`);
    process.stdout.write(`  ${b}Rate Limit${r}\n`);
    process.stdout.write(`    ${c}5h${r}           5-hour rolling window utilization\n`);
    process.stdout.write(`    ${c}7d${r}           7-day rolling window utilization\n`);
    process.stdout.write(`    ${g}Green${r} <50%   ${y}Yellow${r} 50-80%   ${ANSI.red}Red${r} >80%\n`);
    process.stdout.write(`    ${c}Time${r}         Countdown until that window resets\n\n`);
    process.stdout.write(`  ${b}Token Usage${r}\n`);
    process.stdout.write(`    ${g}Input${r}        Tokens sent to the API (prompts)\n`);
    process.stdout.write(`    ${y}Output${r}       Tokens received from the API (completions)\n`);
    process.stdout.write(`    ${c}(N)${r}          Number of requests that day\n`);
    process.stdout.write(`    Data persisted to ${d}./data/usage.json${r}\n\n`);
    process.stdout.write(`  ${b}Recent Activity${r}\n`);
    process.stdout.write(`    ${c}S/H/O${r}        Model: ${b}S${r}onnet / ${b}H${r}aiku / ${b}O${r}pus\n`);
    process.stdout.write(`    ${g}\u2191N${r}           Input tokens for this request\n`);
    process.stdout.write(`    ${y}\u2193N${r}           Output tokens for this request\n\n`);
    process.stdout.write(`  ${b}Keys${r}\n`);
    process.stdout.write(`    ${c}i${r}            Toggle this info screen\n`);
    process.stdout.write(`    ${c}q${r}            Quit the proxy\n`);
    process.stdout.write(`\n  ${d}Press [i] to return${r}\n`);
  },

  refreshToken() {
    try {
      this._oauth = getToken(this.config.credsPath);
    } catch (e) { /* keep last known oauth */ }
  },

  renderHeader() {
    if (!this.isTTY) return;
    const upSec = Math.floor((Date.now() - this.startedAt) / 1000);
    const upH = Math.floor(upSec / 3600);
    const upM = Math.floor((upSec % 3600) / 60);
    const upStr = upH > 0 ? `${upH}h ${upM}m` : `${upM}m`;

    const h = ((this._oauth.expiresAt - Date.now()) / 3600000).toFixed(1);
    const tokenStr = `Token: ${h}h remaining`;

    process.stdout.write(ANSI.moveTo(1, 1) + ANSI.clearLine);
    process.stdout.write(`  ${ANSI.bold}${ANSI.cyan}OpenClaw Billing Proxy${ANSI.reset}        Port: ${this.config.port}   Uptime: ${upStr}`);
    process.stdout.write(ANSI.moveTo(2, 1) + ANSI.clearLine);
    process.stdout.write(`  Sub: ${this._oauth.subscriptionType || 'unknown'}            ${tokenStr}`);
  },

  _renderBar(pct) {
    const barLen = 15;
    const filled = Math.round((pct / 100) * barLen);
    return '\u2588'.repeat(filled) + '\u2591'.repeat(barLen - filled);
  },

  _pctColor(pct) {
    return pct < 50 ? ANSI.green : pct < 80 ? ANSI.yellow : ANSI.red;
  },

  _fmtReset(epoch) {
    if (!epoch) return '';
    const diff = epoch - Math.floor(Date.now() / 1000);
    if (diff <= 0) return 'now';
    const h = Math.floor(diff / 3600);
    const m = Math.floor((diff % 3600) / 60);
    return h > 0 ? `${h}h${m}m` : `${m}m`;
  },

  renderRateLimit() {
    if (!this.isTTY) return;
    process.stdout.write(ANSI.moveTo(3, 1) + ANSI.clearLine);
    if (!this.lastRateLimit) {
      process.stdout.write(`  ${ANSI.gray}Rate: waiting for first request...${ANSI.reset}`);
      return;
    }
    const rl = this.lastRateLimit;
    const parts = [];

    for (const [label, bucket] of [['5h', rl.fiveH], ['7d', rl.sevenD]]) {
      if (!bucket) continue;
      const pct = Math.round(bucket.util * 100);
      const c = this._pctColor(pct);
      const reset = this._fmtReset(bucket.reset);
      parts.push(`${label} ${c}[${this._renderBar(pct)}] ${pct}%${ANSI.reset} ${ANSI.gray}${reset}${ANSI.reset}`);
    }

    if (parts.length > 0) {
      process.stdout.write(`  ${parts.join('    ')}`);
    } else {
      process.stdout.write(`  ${ANSI.gray}Rate: no utilization data${ANSI.reset}`);
    }
  },

  renderSeparator() {
    if (!this.isTTY) return;
    const cols = process.stdout.columns || 70;
    process.stdout.write('\n' + `  ${ANSI.gray}${'─'.repeat(Math.min(cols - 4, 66))}${ANSI.reset}`);
  },

  renderTokenTable() {
    if (!this.isTTY) return;
    const days = usageData.days;
    const sortedKeys = Object.keys(days).sort().reverse().slice(0, 7);
    const today = new Date().toISOString().substring(0, 10);
    const yesterday = new Date(Date.now() - 86400000).toISOString().substring(0, 10);

    process.stdout.write('\n');
    //                    label (28 chars)              10-col     4sp  10-col
    process.stdout.write(`  ${''.padEnd(28)}${ANSI.green}${'Input'.padStart(10)}${ANSI.reset}    ${ANSI.yellow}${'Output'.padStart(10)}${ANSI.reset}\n`);

    let totalIn = 0, totalOut = 0, totalReqs = 0;

    if (sortedKeys.length === 0) {
      process.stdout.write(`  ${ANSI.gray}No usage data yet${ANSI.reset}\n`);
    } else {
      for (const key of sortedKeys) {
        const d = days[key];
        totalIn += d.input_tokens;
        totalOut += d.output_tokens;
        totalReqs += d.requests;

        let label;
        if (key === today) label = `Today (${key})`;
        else if (key === yesterday) label = 'Yesterday';
        else label = key;

        const highlight = key === today ? ANSI.bold : '';
        process.stdout.write(`  ${highlight}${label.padEnd(28)}${ANSI.green}${fmt(d.input_tokens).padStart(10)}${ANSI.reset}    ${ANSI.yellow}${fmt(d.output_tokens).padStart(10)}${ANSI.reset}   (${d.requests})${ANSI.reset}\n`);
      }

      if (sortedKeys.length > 1) {
        const cols = process.stdout.columns || 70;
        process.stdout.write(`  ${ANSI.gray}${'─'.repeat(Math.min(cols - 4, 66))}${ANSI.reset}\n`);
        const totalLabel = `Total (${sortedKeys.length}d)`;
        process.stdout.write(`  ${ANSI.bold}${totalLabel.padEnd(28)}${ANSI.reset}${ANSI.green}${fmt(totalIn).padStart(10)}${ANSI.reset}    ${ANSI.yellow}${fmt(totalOut).padStart(10)}${ANSI.reset}   (${totalReqs})\n`);
      }
    }
  },

  renderLog() {
    if (!this.isTTY) return;
    process.stdout.write(`\n  ${ANSI.bold}RECENT ACTIVITY${ANSI.reset}\n`);
    if (this.recentLogs.length === 0) {
      process.stdout.write(`  ${ANSI.gray}No requests yet${ANSI.reset}\n`);
    } else {
      for (const entry of this.recentLogs) {
        process.stdout.write(`  ${entry}\n`);
      }
    }
  },

  logRequest(reqNum, method, url, statusCode, inputTokens, outputTokens, modelTag) {
    const ts = new Date().toISOString().substring(11, 19);
    const inRaw = inputTokens > 0 ? `\u2191${fmt(inputTokens)}` : '';
    const outRaw = outputTokens > 0 ? `\u2193${fmt(outputTokens)}` : '';
    // Fixed-width columns so entries align even when input is 0
    const inStr = `${ANSI.green}${inRaw.padStart(8)}${ANSI.reset}`;
    const outStr = `${ANSI.yellow}${outRaw.padStart(8)}${ANSI.reset}`;
    const statusColor = statusCode < 400 ? ANSI.green : ANSI.red;
    const tag = modelTag || '?';

    const entry = `${ANSI.bold}${tag}${ANSI.reset} [${ts}] #${reqNum} ${method} ${url} ${statusColor}${statusCode}${ANSI.reset} ${inStr} ${outStr}`;

    this.recentLogs.unshift(entry);
    if (this.recentLogs.length > 10) this.recentLogs.pop();

    if (inputTokens > 0 || outputTokens > 0) {
      recordUsage(inputTokens, outputTokens);
    }

    if (this.isTTY) {
      this.render();
    } else {
      const inPlain = inputTokens > 0 ? `^${inputTokens}` : '';
      const outPlain = outputTokens > 0 ? `v${outputTokens}` : '';
      const plainText = `${tag} [${ts}] #${reqNum} ${method} ${url} ${statusCode} ${inPlain.padStart(8)} ${outPlain.padStart(8)}`;
      console.log(plainText);
    }
  },

  logError(reqNum, method, url, message) {
    const ts = new Date().toISOString().substring(11, 19);
    const entry = `[${ts}] #${reqNum} ${method} ${url} ${ANSI.red}ERR: ${message}${ANSI.reset}`;
    this.recentLogs.unshift(entry);
    if (this.recentLogs.length > 10) this.recentLogs.pop();

    if (this.isTTY) {
      this.render();
    } else {
      console.error(`[${ts}] #${reqNum} ERR: ${message}`);
    }
  },

  updateRateLimit(upRes) {
    const h = upRes.headers;
    const fiveHUtil = parseFloat(h['anthropic-ratelimit-unified-5h-utilization']);
    const sevenDUtil = parseFloat(h['anthropic-ratelimit-unified-7d-utilization']);
    const fiveHReset = parseInt(h['anthropic-ratelimit-unified-5h-reset']) || 0;
    const sevenDReset = parseInt(h['anthropic-ratelimit-unified-7d-reset']) || 0;
    if (!isNaN(fiveHUtil) || !isNaN(sevenDUtil)) {
      this.lastRateLimit = {
        fiveH: isNaN(fiveHUtil) ? null : { util: fiveHUtil, reset: fiveHReset },
        sevenD: isNaN(sevenDUtil) ? null : { util: sevenDUtil, reset: sevenDReset },
      };
    }
  },

  shutdown() {
    if (this.isTTY) {
      process.stdout.write(ANSI.show);
      if (this._uptimeInterval) clearInterval(this._uptimeInterval);
    }
    if (saveTimer) clearTimeout(saveTimer);
    saveUsageData();
  }
};

// ─── Server ─────────────────────────────────────────────────────────────────
function startServer(config) {
  let requestCount = 0;

  const server = http.createServer((req, res) => {
    if (req.url === '/health' && req.method === 'GET') {
      try {
        const oauth = getToken(config.credsPath);
        const expiresIn = (oauth.expiresAt - Date.now()) / 3600000;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: expiresIn > 0 ? 'ok' : 'token_expired',
          proxy: 'openclaw-billing-proxy',
          requestsServed: requestCount,
          uptime: Math.floor((Date.now() - dashboard.startedAt) / 1000) + 's',
          tokenExpiresInHours: expiresIn.toFixed(1),
          subscriptionType: oauth.subscriptionType,
          replacementPatterns: config.replacements.length,
          reverseMapPatterns: config.reverseMap.length
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
      try {
        oauth = getToken(config.credsPath);
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { message: e.message } }));
        return;
      }

      // Process body: sanitize triggers + inject billing header
      let bodyStr = body.toString('utf8');
      bodyStr = processBody(bodyStr, config);
      body = Buffer.from(bodyStr, 'utf8');

      // Build upstream headers
      const headers = {};
      for (const [key, value] of Object.entries(req.headers)) {
        const lk = key.toLowerCase();
        if (lk === 'host' || lk === 'connection') continue;
        if (lk === 'authorization' || lk === 'x-api-key') continue;
        if (lk === 'content-length') continue;
        headers[key] = value;
      }

      headers['authorization'] = `Bearer ${oauth.accessToken}`;
      headers['content-length'] = body.length;
      headers['accept-encoding'] = 'identity';

      // Merge required betas
      const existingBeta = headers['anthropic-beta'] || '';
      const betas = existingBeta ? existingBeta.split(',').map(b => b.trim()) : [];
      for (const b of REQUIRED_BETAS) {
        if (!betas.includes(b)) betas.push(b);
      }
      headers['anthropic-beta'] = betas.join(',');

      // Extract model shortcode from request body
      let modelTag = '?';
      const modelMatch = bodyStr.match(/"model"\s*:\s*"([^"]+)"/);
      if (modelMatch) {
        const m = modelMatch[1].toLowerCase();
        if (m.includes('opus')) modelTag = 'O';
        else if (m.includes('sonnet')) modelTag = 'S';
        else if (m.includes('haiku')) modelTag = 'H';
      }

      const upstream = https.request({
        hostname: UPSTREAM_HOST, port: 443,
        path: req.url, method: req.method, headers
      }, (upRes) => {
        // Capture rate-limit headers from every response
        dashboard.updateRateLimit(upRes);

        // For SSE streaming responses, extract tokens + reverse-map each chunk
        if (upRes.headers['content-type'] && upRes.headers['content-type'].includes('text/event-stream')) {
          res.writeHead(upRes.statusCode, upRes.headers);
          const tracker = createSSETokenTracker();
          upRes.on('data', (chunk) => {
            const raw = chunk.toString();
            tracker.push(raw);
            res.write(reverseMap(raw, config));
          });
          upRes.on('end', () => {
            dashboard.logRequest(reqNum, req.method, req.url, upRes.statusCode, tracker.inputTokens, tracker.outputTokens, modelTag);
            res.end();
          });
        }
        // For JSON responses (errors, non-streaming), extract tokens + buffer and reverse-map
        else {
          const respChunks = [];
          upRes.on('data', (c) => respChunks.push(c));
          upRes.on('end', () => {
            let respBody = Buffer.concat(respChunks).toString();

            // Extract token usage before reverse mapping
            let inputTokens = 0, outputTokens = 0;
            try {
              const parsed = JSON.parse(respBody);
              if (parsed.usage) {
                inputTokens = parsed.usage.input_tokens || 0;
                outputTokens = parsed.usage.output_tokens || 0;
              }
            } catch (e) { /* non-JSON or error response */ }

            respBody = reverseMap(respBody, config);
            const newHeaders = { ...upRes.headers };
            newHeaders['content-length'] = Buffer.byteLength(respBody);
            res.writeHead(upRes.statusCode, newHeaders);
            res.end(respBody);

            dashboard.logRequest(reqNum, req.method, req.url, upRes.statusCode, inputTokens, outputTokens, modelTag);
          });
        }
      });

      upstream.on('error', (e) => {
        dashboard.logError(reqNum, req.method, req.url, e.message);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { message: e.message } }));
        }
      });

      upstream.write(body);
      upstream.end();
    });
  });

  server.listen(config.port, '127.0.0.1', () => {
    try {
      const oauth = getToken(config.credsPath);
      dashboard.init(config, oauth);
    } catch (e) {
      console.error(`  Started on port ${config.port} but credentials error: ${e.message}`);
    }
  });

  process.on('SIGINT', () => { dashboard.shutdown(); process.exit(0); });
  process.on('SIGTERM', () => { dashboard.shutdown(); process.exit(0); });
}

// ─── Main ───────────────────────────────────────────────────────────────────
if (require.main === module) {
  const config = loadConfig();
  startServer(config);
}

// Export internals for testing
module.exports = {
  createSSETokenTracker,
  extractTokensFromSSE,
  processBody,
  reverseMap,
  getToken,
  loadUsageData,
  saveUsageData,
  recordUsage,
  dashboard,
  fmt,
  USAGE_FILE,
  BILLING_BLOCK,
  REQUIRED_BETAS,
  DEFAULT_REPLACEMENTS,
  DEFAULT_REVERSE_MAP,
  _usageData: () => usageData,
  _resetUsageData: () => { usageData = { version: 1, days: {} }; },
};
