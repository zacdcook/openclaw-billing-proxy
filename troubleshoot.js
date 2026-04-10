#!/usr/bin/env node
/**
 * Troubleshoot script for OpenClaw Billing Proxy
 *
 * Runs diagnostic checks to identify why the proxy isn't working.
 * Tests each layer independently: credentials, token, billing header,
 * sanitization, and full request.
 *
 * Usage: node troubleshoot.js
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');

const homeDir = os.homedir();
let passed = 0;
let failed = 0;

function ok(name, detail) {
  passed++;
  console.log('  [PASS] ' + name + (detail ? ' -- ' + detail : ''));
}

function fail(name, detail) {
  failed++;
  console.log('  [FAIL] ' + name + (detail ? ' -- ' + detail : ''));
}

function info(msg) {
  console.log('  [INFO] ' + msg);
}

// ─── Step 1: Find credentials ───────────────────────────────────────────────
console.log('\n1. Checking Claude Code credentials...\n');

const credsPaths = [
  path.join(homeDir, '.claude', '.credentials.json'),
  path.join(homeDir, '.claude', 'credentials.json')
];

let credsPath = null;
let creds = null;

for (const p of credsPaths) {
  if (fs.existsSync(p)) {
    const stat = fs.statSync(p);
    if (stat.size === 0) {
      fail('Credentials file exists but is EMPTY: ' + p);
      info('Run: claude auth logout && claude auth login');
      continue;
    }
    try {
      const raw = fs.readFileSync(p, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed.claudeAiOauth && parsed.claudeAiOauth.accessToken) {
        credsPath = p;
        creds = parsed;
        ok('Credentials found', p + ' (' + stat.size + ' bytes)');
      } else {
        fail('Credentials file exists but has no OAuth token', p);
        info('File contains: ' + Object.keys(parsed).join(', '));
        info('Run: claude auth login (use browser OAuth, not API key)');
      }
    } catch (e) {
      fail('Credentials file exists but invalid JSON', p + ' -- ' + e.message);
    }
    break;
  }
}

// macOS Keychain fallback
if (!credsPath && process.platform === 'darwin') {
  info('No credential files found. Checking macOS Keychain...');
  const { execSync } = require('child_process');
  const keychainNames = ['Claude Code-credentials', 'claude-code', 'claude', 'com.anthropic.claude-code'];
  for (const svc of keychainNames) {
    try {
      const token = execSync('security find-generic-password -s "' + svc + '" -w 2>/dev/null', { encoding: 'utf8' }).trim();
      if (token) {
        ok('Token found in macOS Keychain', 'service: ' + svc);
        try {
          creds = JSON.parse(token);
        } catch(e) {
          if (token.startsWith('sk-ant-')) {
            creds = { claudeAiOauth: { accessToken: token, expiresAt: Date.now() + 86400000, subscriptionType: 'unknown' } };
            info('Raw token extracted (not full JSON structure)');
          }
        }
        if (creds && creds.claudeAiOauth) {
          credsPath = path.join(homeDir, '.claude', '.credentials.json');
          info('To make this permanent, run: node setup.js');
          info('Setup will extract the Keychain token to a file for the proxy');
        }
        break;
      }
    } catch(e) { /* not found */ }
  }
  if (!creds) {
    fail('Token not found in macOS Keychain either');
  }
}

if (!credsPath || !creds) {
  if (!creds) fail('No credentials found anywhere');
  info('');
  info('Searched files: ' + credsPaths.join(', '));
  if (process.platform === 'darwin') {
    info('Searched Keychain: Claude Code-credentials, claude-code, claude, com.anthropic.claude-code');
  }
  info('');
  info('To fix:');
  info('  npm install -g @anthropic-ai/claude-code');
  info('  claude auth login');
  info('  claude -p "test" --max-turns 1 --no-session-persistence   (forces credential write)');
  info('');
  info('Then run: node setup.js   (auto-extracts Keychain tokens on Mac)');
  console.log('\nCannot continue without credentials. Fix this first.\n');
  process.exit(1);
}

// ─── Step 2: Check token validity ───────────────────────────────────────────
console.log('\n2. Checking token...\n');

const oauth = creds.claudeAiOauth;
const token = oauth.accessToken;
const expiresIn = (oauth.expiresAt - Date.now()) / 3600000;

ok('Token prefix', token.substring(0, 20) + '...');
ok('Subscription', oauth.subscriptionType || 'unknown');

if (expiresIn > 0) {
  ok('Token expiry', expiresIn.toFixed(1) + ' hours remaining');
} else {
  fail('Token EXPIRED', Math.abs(expiresIn).toFixed(1) + ' hours ago');
  info('Run: claude auth login (to refresh)');
  info('Or open Claude Code CLI briefly -- it auto-refreshes');
}

// ─── Step 3: Test API connectivity ──────────────────────────────────────────
console.log('\n3. Testing API connectivity...\n');

function apiTest(name, body, headers) {
  return new Promise((resolve) => {
    const bodyStr = JSON.stringify(body);
    const h = Object.assign({
      'content-type': 'application/json',
      'authorization': 'Bearer ' + token,
      'anthropic-version': '2023-06-01',
      'anthropic-beta': 'claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,effort-2025-11-24',
      'content-length': Buffer.byteLength(bodyStr),
      'accept-encoding': 'identity'
    }, headers || {});

    const req = https.request({
      hostname: 'api.anthropic.com', port: 443,
      path: '/v1/messages', method: 'POST', headers: h
    }, (res) => {
      let data = '';
      res.on('data', (c) => data += c);
      res.on('end', () => {
        const overage = res.headers['anthropic-ratelimit-unified-overage-status'] || 'missing';
        resolve({ status: res.statusCode, overage: overage, body: data });
      });
    });
    req.on('error', (e) => resolve({ status: 0, error: e.message }));
    req.write(bodyStr);
    req.end();
  });
}

async function runTests() {
  // Test 3a: Raw API connectivity (no billing header)
  const raw = await apiTest('raw', {
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 8,
    messages: [{ role: 'user', content: 'Say OK' }]
  });

  if (raw.status === 401) {
    ok('API reachable', 'Got 401 (expected without billing header)');
  } else if (raw.status === 200) {
    ok('API reachable', 'Got 200 (token works without billing header on this model)');
  } else if (raw.status === 0) {
    fail('Cannot reach api.anthropic.com', raw.error);
    info('Check internet connection and DNS resolution');
  } else {
    info('API returned ' + raw.status + ' -- unexpected');
    try { info('Error: ' + JSON.parse(raw.body).error.message); } catch(e) {}
  }

  // Test 3b: With billing header (Haiku)
  console.log('\n4. Testing billing header (Haiku)...\n');

  const billing = await apiTest('billing-haiku', {
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 8,
    system: [
      { type: 'text', text: 'x-anthropic-billing-header: cc_version=2.1.80.a46; cc_entrypoint=sdk-cli; cch=00000;' },
      { type: 'text', text: 'Test.' }
    ],
    messages: [{ role: 'user', content: 'Say OK' }]
  });

  if (billing.status === 200) {
    if (billing.overage === 'rejected') {
      ok('Billing header works', 'Haiku 200, overage=rejected (subscription billing!)');
    } else {
      ok('Billing header works', 'Haiku 200, overage=' + billing.overage);
      if (billing.overage !== 'rejected') {
        info('overage status is not "rejected" -- may be billing to Extra Usage');
      }
    }
  } else {
    fail('Billing header rejected', 'Status ' + billing.status);
    try { info('Error: ' + JSON.parse(billing.body).error.message); } catch(e) {}
    info('Your Claude Code version may use a different billing header');
    info('Run the capture proxy to get YOUR billing header (see README)');
  }

  // Test 3c: With billing header (Sonnet)
  console.log('\n5. Testing billing header (Sonnet)...\n');

  const sonnet = await apiTest('billing-sonnet', {
    model: 'claude-sonnet-4-6',
    max_tokens: 8,
    system: [
      { type: 'text', text: 'x-anthropic-billing-header: cc_version=2.1.80.a46; cc_entrypoint=sdk-cli; cch=00000;' },
      { type: 'text', text: 'Test.' }
    ],
    messages: [{ role: 'user', content: 'Say OK' }]
  });

  if (sonnet.status === 200) {
    ok('Sonnet works', 'Status 200, overage=' + sonnet.overage);
  } else if (sonnet.status === 429) {
    info('Sonnet rate limited (429) -- try again in a few minutes');
    info('This is normal if you have active Claude Code sessions');
  } else {
    fail('Sonnet failed', 'Status ' + sonnet.status);
    try { info('Error: ' + JSON.parse(sonnet.body).error.message); } catch(e) {}
  }

  // Test 3d: With "OpenClaw" in body (should fail without sanitization)
  console.log('\n6. Testing trigger phrase detection...\n');

  const trigger = await apiTest('trigger-test', {
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 8,
    system: [
      { type: 'text', text: 'x-anthropic-billing-header: cc_version=2.1.80.a46; cc_entrypoint=sdk-cli; cch=00000;' },
      { type: 'text', text: 'You are a personal assistant running inside OpenClaw.' }
    ],
    messages: [{ role: 'user', content: 'Say OK' }]
  });

  if (trigger.status === 400) {
    ok('Trigger detection confirmed', '"running inside OpenClaw" correctly triggers rejection');
    info('This is expected -- the proxy sanitizes this phrase');
  } else if (trigger.status === 200) {
    info('Trigger phrase was NOT detected (unexpected) -- detection may have changed');
  }

  // Test 3e: Check if proxy is running
  console.log('\n7. Checking proxy...\n');

  const proxyCheck = await new Promise((resolve) => {
    const req = http.request({
      hostname: '127.0.0.1', port: 18801,
      path: '/health', method: 'GET'
    }, (res) => {
      let data = '';
      res.on('data', (c) => data += c);
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', (e) => resolve({ status: 0, error: e.message }));
    req.end();
  });

  if (proxyCheck.status === 200) {
    try {
      const health = JSON.parse(proxyCheck.body);
      const patternCount = health.replacementPatterns || (health.layers && health.layers.stringReplacements) || '?';
      ok('Proxy running', 'Port 18801, ' + health.requestsServed + ' requests served, ' + patternCount + ' patterns');
      if (health.tokenExpiresInHours && parseFloat(health.tokenExpiresInHours) <= 0) {
        fail('Proxy token expired', 'Run: claude auth login');
      }
    } catch(e) {
      ok('Proxy running', 'Port 18801');
    }
  } else {
    fail('Proxy not running on port 18801', proxyCheck.error || 'Status ' + proxyCheck.status);
    info('Start it with: node proxy.js');
  }

  // Test 3f: Send a test request through the proxy
  if (proxyCheck.status === 200) {
    console.log('\n8. Testing end-to-end through proxy...\n');

    const e2e = await new Promise((resolve) => {
      const body = JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 8,
        system: 'You are a personal assistant running inside OpenClaw. Test with sessions_spawn and sessions_yield.',
        messages: [{ role: 'user', content: 'Say E2E_OK' }]
      });
      const req = http.request({
        hostname: '127.0.0.1', port: 18801,
        path: '/v1/messages', method: 'POST',
        headers: {
          'content-type': 'application/json',
          'anthropic-version': '2023-06-01',
          'authorization': 'Bearer dummy-proxy-will-replace',
          'content-length': Buffer.byteLength(body)
        }
      }, (res) => {
        let data = '';
        res.on('data', (c) => data += c);
        res.on('end', () => resolve({ status: res.statusCode, body: data }));
      });
      req.on('error', (e) => resolve({ status: 0, error: e.message }));
      req.write(body);
      req.end();
    });

    if (e2e.status === 200) {
      ok('End-to-end test PASSED', 'Request with trigger phrases went through proxy successfully');
    } else {
      fail('End-to-end test FAILED', 'Status ' + e2e.status);
      try {
        const err = JSON.parse(e2e.body);
        if (err.error) {
          info('Error: ' + err.error.message);
          if (err.error.message.includes('extra usage') || err.error.message.includes('Third-party')) {
            info('');
            info('The proxy is not fully sanitizing your request body.');
            info('Your OpenClaw version may have additional trigger terms.');
            info('Add more patterns to config.json replacements array.');
            info('See README for troubleshooting guidance.');
          }
        }
      } catch(e) {
        info('Response: ' + (e2e.body || e2e.error || 'no response body').substring(0, 200));
      }
    }
  }

  // ─── 9. OpenClaw Configuration Check ───────────────────────────────────────
  console.log('\n9. Checking OpenClaw configuration...\n');

  const ocConfigPaths = [
    path.join(os.homedir(), '.openclaw', 'openclaw.json'),
    path.join(os.homedir(), '.openclaw', 'config.json')
  ];

  let ocConfigFound = false;
  for (const ocPath of ocConfigPaths) {
    if (fs.existsSync(ocPath)) {
      try {
        const ocRaw = fs.readFileSync(ocPath, 'utf8');
        const ocConfig = JSON.parse(ocRaw.charCodeAt(0) === 0xFEFF ? ocRaw.slice(1) : ocRaw);
        ocConfigFound = true;

        const baseUrl = ocConfig.models &&
          ocConfig.models.providers &&
          ocConfig.models.providers.anthropic &&
          ocConfig.models.providers.anthropic.baseUrl;

        if (baseUrl) {
          if (baseUrl.includes('127.0.0.1:18801') || baseUrl.includes('localhost:18801')) {
            ok('OpenClaw baseUrl points to proxy', baseUrl);
          } else if (baseUrl.includes('127.0.0.1') || baseUrl.includes('localhost')) {
            info('OpenClaw baseUrl: ' + baseUrl + ' (custom port -- make sure proxy is on that port)');
          } else {
            fail('OpenClaw baseUrl is NOT pointing to the proxy', baseUrl);
            info('Change models.providers.anthropic.baseUrl to "http://127.0.0.1:18801" in ' + ocPath);
            info('Then restart the OpenClaw gateway.');
            info('');
            info('Note: ANTHROPIC_BASE_URL env var does NOT control OpenClaw routing.');
            info('You must set baseUrl in openclaw.json under models.providers.anthropic.');
            info('If you intentionally use a separate provider for the proxy, this FAIL can be ignored.');
          }
        } else {
          fail('No baseUrl found in OpenClaw config', 'OpenClaw is using the default Anthropic API directly');
          info('Add this to ' + ocPath + ':');
          info('  "models": { "providers": { "anthropic": { "baseUrl": "http://127.0.0.1:18801" } } }');
          info('Then restart the OpenClaw gateway.');
          info('If you intentionally use a separate provider for the proxy, this FAIL can be ignored.');
        }
      } catch(e) {
        info('Found ' + ocPath + ' but failed to parse: ' + e.message);
      }
      break;
    }
  }

  if (!ocConfigFound) {
    info('OpenClaw config not found at ~/.openclaw/openclaw.json');
    info('(This check only works if OpenClaw is installed on this machine)');
  }

  // ─── Summary ──────────────────────────────────────────────────────────────
  console.log('\n---------------------------------');
  console.log('  Results: ' + passed + ' passed, ' + failed + ' failed');
  console.log('---------------------------------\n');

  if (failed === 0) {
    console.log('  Everything looks good! If OpenClaw requests still fail,');
    console.log('  check the proxy console for 400 errors and add sanitization');
    console.log('  patterns to config.json for any trigger terms in your content.\n');
  } else {
    console.log('  Fix the FAIL items above and run this script again.\n');
  }
}

runTests();
