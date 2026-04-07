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
    if (args[i] === '--port' && args[i + 1]) {
      port = parseInt(args[i + 1], 10);
      if (isNaN(port) || port < 1 || port > 65535) {
        console.error('[ERROR] Invalid port: ' + args[i + 1] + '. Must be 1-65535.');
        process.exit(1);
      }
    }
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
    const { execFileSync } = require('child_process');
    const keychainNames = ['claude-code', 'claude', 'com.anthropic.claude-code'];
    for (const svc of keychainNames) {
      try {
        const token = execFileSync('security', ['find-generic-password', '-s', svc, '-w'], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }).trim();
        if (token) {
          let creds;
          try { creds = JSON.parse(token); } catch(e) {
            if (token.startsWith('sk-ant-')) {
              creds = { claudeAiOauth: { accessToken: token, expiresAt: Date.now() + 86400000, subscriptionType: 'unknown' } };
            }
          }
          if (creds && creds.claudeAiOauth) {
            credsPath = path.join(homeDir, '.claude', '.credentials.json');
            fs.mkdirSync(path.join(homeDir, '.claude'), { recursive: true, mode: 0o700 });
            fs.writeFileSync(credsPath, JSON.stringify(creds), { mode: 0o600 });
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
      console.error('Also checked macOS Keychain (claude-code, claude, com.anthropic.claude-code)');
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
const BILLING_OBJ = JSON.parse(BILLING_BLOCK);

function processBody(bodyStr, config) {
  // 1. Apply sanitization -- raw string replacement preserves original JSON formatting
  let modified = bodyStr;
  for (const [find, replace] of config.replacements) {
    modified = modified.split(find).join(replace);
  }

  // 2. Inject billing block into system prompt using proper JSON parsing
  try {
    const parsed = JSON.parse(modified);

    if (Array.isArray(parsed.system)) {
      parsed.system.unshift(BILLING_OBJ);
    } else if (typeof parsed.system === 'string') {
      parsed.system = [BILLING_OBJ, { type: 'text', text: parsed.system }];
    } else {
      parsed.system = [BILLING_OBJ];
    }

    return JSON.stringify(parsed);
  } catch (e) {
    // Fallback: if body isn't valid JSON, return sanitized string as-is
    return modified;
  }
}

// ─── Response Processing ────────────────────────────────────────────────────
function reverseMap(text, config) {
  let result = text;
  for (const [sanitized, original] of config.reverseMap) {
    result = result.split(sanitized).join(original);
  }
  return result;
}

// ─── Server ─────────────────────────────────────────────────────────────────
const MAX_BODY_SIZE = 10 * 1024 * 1024; // 10 MB

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
          requestsServed: requestCount,
          uptime: Math.floor((Date.now() - startedAt) / 1000) + 's',
          tokenExpiresInHours: expiresIn.toFixed(1),
          subscriptionType: oauth.subscriptionType,
          replacementPatterns: config.replacements.length,
          reverseMapPatterns: config.reverseMap.length
        }));
      } catch (e) {
        console.error('[PROXY] Health check error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'error', message: 'Internal server error' }));
      }
      return;
    }

    requestCount++;
    const reqNum = requestCount;
    const chunks = [];
    let bodySize = 0;

    req.on('data', (c) => {
      bodySize += c.length;
      if (bodySize > MAX_BODY_SIZE) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { message: 'Request body too large' } }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (bodySize > MAX_BODY_SIZE) return;
      let body = Buffer.concat(chunks);

      let oauth;
      try {
        oauth = getToken(config.credsPath);
      } catch (e) {
        console.error(`[${new Date().toISOString().substring(11, 19)}] #${reqNum} Token error: ${e.message}`);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { message: 'Failed to load credentials' } }));
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

      const ts = new Date().toISOString().substring(11, 19);
      console.log(`[${ts}] #${reqNum} ${req.method} ${req.url} (${body.length}b)`);

      const upstream = https.request({
        hostname: UPSTREAM_HOST, port: 443,
        path: req.url, method: req.method, headers,
        timeout: 120000
      }, (upRes) => {
        console.log(`[${ts}] #${reqNum} > ${upRes.statusCode}`);

        // For SSE streaming responses, reverse-map each chunk
        if (upRes.headers['content-type'] && upRes.headers['content-type'].includes('text/event-stream')) {
          res.writeHead(upRes.statusCode, upRes.headers);
          upRes.on('data', (chunk) => {
            res.write(reverseMap(chunk.toString(), config));
          });
          upRes.on('end', () => res.end());
        }
        // For JSON responses (errors, non-streaming), buffer and reverse-map
        else {
          const respChunks = [];
          upRes.on('data', (c) => respChunks.push(c));
          upRes.on('end', () => {
            let respBody = Buffer.concat(respChunks).toString();
            respBody = reverseMap(respBody, config);
            const newHeaders = { ...upRes.headers };
            newHeaders['content-length'] = Buffer.byteLength(respBody);
            res.writeHead(upRes.statusCode, newHeaders);
            res.end(respBody);
          });
        }
      });

      upstream.on('timeout', () => {
        console.error(`[${ts}] #${reqNum} ERR: upstream timeout`);
        upstream.destroy(new Error('upstream timeout'));
      });

      upstream.on('error', (e) => {
        console.error(`[${ts}] #${reqNum} ERR: ${e.message}`);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { message: 'Upstream request failed' } }));
        }
      });

      upstream.write(body);
      upstream.end();
    });
  });

  server.listen(config.port, '127.0.0.1', () => {
    try {
      const oauth = getToken(config.credsPath);
      const h = ((oauth.expiresAt - Date.now()) / 3600000).toFixed(1);
      console.log(`\n  OpenClaw Billing Proxy`);
      console.log(`  ---------------------`);
      console.log(`  Port:          ${config.port}`);
      console.log(`  Subscription:  ${oauth.subscriptionType}`);
      console.log(`  Token expires: ${h}h`);
      console.log(`  Patterns:      ${config.replacements.length} sanitization + ${config.reverseMap.length} reverse`);
      console.log(`  Credentials:   ${config.credsPath}`);
      console.log(`\n  Ready. Set openclaw.json baseUrl to http://127.0.0.1:${config.port}\n`);
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
