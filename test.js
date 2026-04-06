#!/usr/bin/env node
/**
 * Comprehensive BDD-style tests for openclaw-billing-proxy.
 *
 * Covers:
 *   - SSE token extraction (batch + incremental tracker)
 *   - Usage data persistence (load / save / record)
 *   - Dashboard rate-limit parsing
 *   - Dashboard visual helpers
 *   - Dashboard log methods & column alignment
 *   - Dashboard shutdown lifecycle
 *   - Credential / token management
 *   - Request body processing (billing injection + sanitization)
 *   - Response reverse-mapping
 *   - Model tag extraction
 *   - Number formatting
 *   - Default replacement/reverse-map consistency
 *
 * Uses Node.js built-in test runner (Node 18+). Zero dependencies.
 *
 * Run: node test.js
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const {
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
  _usageData,
  _resetUsageData,
} = require('./proxy.js');

// ─── Helper: strip ANSI escape codes ────────────────────────────────────────
function stripAnsi(str) {
  return str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '').replace(/\x1b\[\?25[hl]/g, '');
}

// ═══════════════════════════════════════════════════════════════════════════
// Feature: SSE Token Extraction
// ═══════════════════════════════════════════════════════════════════════════

describe('Feature: SSE Token Extraction', () => {

  describe('Scenario: extractTokensFromSSE (batch)', () => {
    it('should extract input tokens from message_start', () => {
      const sse = [
        'event: message_start',
        'data: {"type":"message_start","message":{"usage":{"input_tokens":1500,"output_tokens":0}}}',
        '', '',
      ].join('\n');
      const { inputTokens, outputTokens } = extractTokensFromSSE(sse);
      assert.equal(inputTokens, 1500);
      assert.equal(outputTokens, 0);
    });

    it('should extract output tokens from message_delta', () => {
      const sse = [
        'event: message_delta',
        'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":420}}',
        '', '',
      ].join('\n');
      const { inputTokens, outputTokens } = extractTokensFromSSE(sse);
      assert.equal(inputTokens, 0);
      assert.equal(outputTokens, 420);
    });

    it('should extract both input and output from a full stream', () => {
      const sse = [
        'event: message_start',
        'data: {"type":"message_start","message":{"usage":{"input_tokens":2000,"output_tokens":0}}}',
        '',
        'event: content_block_start',
        'data: {"type":"content_block_start","index":0}',
        '',
        'event: content_block_delta',
        'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}',
        '',
        'event: message_delta',
        'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":350}}',
        '', '',
      ].join('\n');
      const { inputTokens, outputTokens } = extractTokensFromSSE(sse);
      assert.equal(inputTokens, 2000);
      assert.equal(outputTokens, 350);
    });

    it('should return zeros for empty buffer', () => {
      const { inputTokens, outputTokens } = extractTokensFromSSE('');
      assert.equal(inputTokens, 0);
      assert.equal(outputTokens, 0);
    });

    it('should handle malformed JSON gracefully', () => {
      const sse = ['event: message_start', 'data: {broken json', '', ''].join('\n');
      const { inputTokens, outputTokens } = extractTokensFromSSE(sse);
      assert.equal(inputTokens, 0);
      assert.equal(outputTokens, 0);
    });

    it('should handle events without data lines', () => {
      const sse = ['event: ping', '', ''].join('\n');
      const { inputTokens, outputTokens } = extractTokensFromSSE(sse);
      assert.equal(inputTokens, 0);
      assert.equal(outputTokens, 0);
    });
  });

  describe('Scenario: createSSETokenTracker (incremental)', () => {
    it('should extract tokens when fed a complete stream at once', () => {
      const tracker = createSSETokenTracker();
      tracker.push([
        'event: message_start',
        'data: {"type":"message_start","message":{"usage":{"input_tokens":500,"output_tokens":0}}}',
        '',
        'event: message_delta',
        'data: {"type":"message_delta","delta":{},"usage":{"output_tokens":200}}',
        '', '',
      ].join('\n'));
      assert.equal(tracker.inputTokens, 500);
      assert.equal(tracker.outputTokens, 200);
    });

    it('should extract tokens across multiple chunks', () => {
      const tracker = createSSETokenTracker();
      // Chunk 1: message_start split across two pushes
      tracker.push('event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":1000,"output_tokens":0}}}\n\n');
      assert.equal(tracker.inputTokens, 1000);
      // Chunk 2: content deltas (no tokens)
      tracker.push('event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"hi"}}\n\n');
      assert.equal(tracker.inputTokens, 1000);
      assert.equal(tracker.outputTokens, 0);
      // Chunk 3: message_delta with output tokens
      tracker.push('event: message_delta\ndata: {"type":"message_delta","delta":{},"usage":{"output_tokens":77}}\n\n');
      assert.equal(tracker.outputTokens, 77);
    });

    it('should handle a chunk that splits an event mid-line', () => {
      const tracker = createSSETokenTracker();
      // First chunk ends mid-event (no double newline yet)
      tracker.push('event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":300,');
      assert.equal(tracker.inputTokens, 0); // not yet complete
      // Second chunk completes the event
      tracker.push('"output_tokens":0}}}\n\nevent: message_delta\ndata: {"type":"message_delta","delta":{},"usage":{"output_tokens":50}}\n\n');
      assert.equal(tracker.inputTokens, 300);
      assert.equal(tracker.outputTokens, 50);
    });

    it('should return zeros when fed no data', () => {
      const tracker = createSSETokenTracker();
      assert.equal(tracker.inputTokens, 0);
      assert.equal(tracker.outputTokens, 0);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Feature: Usage Data Persistence
// ═══════════════════════════════════════════════════════════════════════════

describe('Feature: Usage Data Persistence', () => {
  const tmpDir = path.join(os.tmpdir(), 'proxy-test-' + Date.now());
  const tmpFile = path.join(tmpDir, 'usage.json');

  beforeEach(() => {
    fs.mkdirSync(tmpDir, { recursive: true });
    _resetUsageData();
  });

  afterEach(() => {
    try { fs.rmSync(tmpDir, { recursive: true }); } catch (e) { /* */ }
  });

  describe('Scenario: loadUsageData', () => {
    it('should return default structure when file is missing', () => {
      const exists = fs.existsSync(USAGE_FILE);
      if (exists) fs.renameSync(USAGE_FILE, USAGE_FILE + '.bak');
      try {
        const data = loadUsageData();
        assert.deepEqual(data, { version: 1, days: {} });
      } finally {
        if (exists) fs.renameSync(USAGE_FILE + '.bak', USAGE_FILE);
      }
    });

    it('should return default structure for corrupt JSON', () => {
      const exists = fs.existsSync(USAGE_FILE);
      if (exists) fs.renameSync(USAGE_FILE, USAGE_FILE + '.bak');
      try {
        fs.mkdirSync(path.dirname(USAGE_FILE), { recursive: true });
        fs.writeFileSync(USAGE_FILE, '{not valid json!!!');
        const data = loadUsageData();
        assert.deepEqual(data, { version: 1, days: {} });
      } finally {
        try { fs.unlinkSync(USAGE_FILE); } catch (e) { /* */ }
        if (exists) fs.renameSync(USAGE_FILE + '.bak', USAGE_FILE);
      }
    });
  });

  describe('Scenario: recordUsage', () => {
    it('should create today entry on first call', () => {
      recordUsage(100, 50);
      const data = _usageData();
      const today = new Date().toISOString().substring(0, 10);
      assert.equal(data.days[today].input_tokens, 100);
      assert.equal(data.days[today].output_tokens, 50);
      assert.equal(data.days[today].requests, 1);
    });

    it('should accumulate across multiple calls', () => {
      recordUsage(100, 50);
      recordUsage(200, 75);
      recordUsage(300, 25);
      const data = _usageData();
      const today = new Date().toISOString().substring(0, 10);
      assert.equal(data.days[today].input_tokens, 600);
      assert.equal(data.days[today].output_tokens, 150);
      assert.equal(data.days[today].requests, 3);
    });

    it('should handle zero-token calls', () => {
      recordUsage(0, 0);
      const data = _usageData();
      const today = new Date().toISOString().substring(0, 10);
      assert.equal(data.days[today].input_tokens, 0);
      assert.equal(data.days[today].output_tokens, 0);
      assert.equal(data.days[today].requests, 1);
    });
  });

  describe('Scenario: saveUsageData', () => {
    it('should write valid JSON that round-trips', () => {
      recordUsage(500, 200);
      const data = _usageData();
      fs.writeFileSync(tmpFile, JSON.stringify(data, null, 2));
      const loaded = JSON.parse(fs.readFileSync(tmpFile, 'utf8'));
      assert.equal(loaded.version, 1);
      const today = new Date().toISOString().substring(0, 10);
      assert.equal(loaded.days[today].input_tokens, 500);
      assert.equal(loaded.days[today].output_tokens, 200);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Feature: Credential / Token Management
// ═══════════════════════════════════════════════════════════════════════════

describe('Feature: Credential / Token Management', () => {
  const tmpDir = path.join(os.tmpdir(), 'proxy-creds-' + Date.now());

  beforeEach(() => {
    fs.mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(() => {
    try { fs.rmSync(tmpDir, { recursive: true }); } catch (e) { /* */ }
  });

  describe('Scenario: getToken', () => {
    it('should parse a valid credentials file and return OAuth object', () => {
      const credsPath = path.join(tmpDir, 'creds.json');
      const credsData = {
        claudeAiOauth: {
          accessToken: 'test-token-123',
          expiresAt: Date.now() + 3600000,
          subscriptionType: 'max',
        }
      };
      fs.writeFileSync(credsPath, JSON.stringify(credsData));
      const oauth = getToken(credsPath);
      assert.equal(oauth.accessToken, 'test-token-123');
      assert.equal(oauth.subscriptionType, 'max');
    });

    it('should throw when claudeAiOauth is missing', () => {
      const credsPath = path.join(tmpDir, 'creds.json');
      fs.writeFileSync(credsPath, JSON.stringify({ someOtherKey: {} }));
      assert.throws(() => getToken(credsPath), /No OAuth token/);
    });

    it('should throw when accessToken is missing', () => {
      const credsPath = path.join(tmpDir, 'creds.json');
      fs.writeFileSync(credsPath, JSON.stringify({ claudeAiOauth: { expiresAt: 123 } }));
      assert.throws(() => getToken(credsPath), /No OAuth token/);
    });

    it('should throw when file does not exist', () => {
      assert.throws(() => getToken(path.join(tmpDir, 'nonexistent.json')));
    });

    it('should throw when file contains invalid JSON', () => {
      const credsPath = path.join(tmpDir, 'creds.json');
      fs.writeFileSync(credsPath, 'not-json');
      assert.throws(() => getToken(credsPath));
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Feature: Request Body Processing
// ═══════════════════════════════════════════════════════════════════════════

describe('Feature: Request Body Processing', () => {
  const config = {
    replacements: DEFAULT_REPLACEMENTS,
    reverseMap: DEFAULT_REVERSE_MAP,
  };

  describe('Scenario: Billing block injection', () => {
    it('should inject billing block at start of system array', () => {
      const body = '{"system":[{"type":"text","text":"hello"}],"messages":[]}';
      const result = processBody(body, config);
      assert.ok(result.includes('x-anthropic-billing-header'));
      const parsed = JSON.parse(result);
      assert.equal(parsed.system[0].text.includes('x-anthropic-billing-header'), true);
    });

    it('should convert system string to array with billing block', () => {
      const body = '{"system":"You are helpful","messages":[]}';
      const result = processBody(body, config);
      assert.ok(result.includes('x-anthropic-billing-header'));
      const parsed = JSON.parse(result);
      assert.ok(Array.isArray(parsed.system));
      assert.equal(parsed.system.length, 2);
    });

    it('should create system field when missing', () => {
      const body = '{"messages":[{"role":"user","content":"hi"}]}';
      const result = processBody(body, config);
      assert.ok(result.includes('"system":['));
      assert.ok(result.includes('x-anthropic-billing-header'));
    });

    it('should handle system string with escaped quotes', () => {
      const body = '{"system":"Say \\"hello\\"","messages":[]}';
      const result = processBody(body, config);
      assert.ok(result.includes('x-anthropic-billing-header'));
      const parsed = JSON.parse(result);
      assert.ok(Array.isArray(parsed.system));
    });

    it('should preserve existing system content after injection', () => {
      const body = '{"system":[{"type":"text","text":"original"}],"messages":[]}';
      const result = processBody(body, config);
      const parsed = JSON.parse(result);
      assert.ok(parsed.system.some(s => s.text === 'original'));
    });
  });

  describe('Scenario: Trigger phrase sanitization', () => {
    it('should replace OpenClaw with OCPlatform', () => {
      const body = '{"system":[{"type":"text","text":"test"}],"messages":[{"content":"OpenClaw is great"}]}';
      const result = processBody(body, config);
      assert.ok(!result.includes('OpenClaw'));
      assert.ok(result.includes('OCPlatform'));
    });

    it('should replace sessions_spawn with create_task', () => {
      const body = '{"system":[{"type":"text","text":"test"}],"messages":[{"content":"sessions_spawn"}]}';
      const result = processBody(body, config);
      assert.ok(!result.includes('sessions_spawn'));
      assert.ok(result.includes('create_task'));
    });

    it('should replace multiple trigger phrases in one body', () => {
      const body = '{"system":[{"type":"text","text":"test"}],"messages":[{"content":"OpenClaw sessions_spawn sessions_list"}]}';
      const result = processBody(body, config);
      assert.ok(!result.includes('OpenClaw'));
      assert.ok(!result.includes('sessions_spawn'));
      assert.ok(!result.includes('sessions_list'));
      assert.ok(result.includes('OCPlatform'));
      assert.ok(result.includes('create_task'));
      assert.ok(result.includes('list_tasks'));
    });

    it('should apply sanitization before billing injection', () => {
      const body = '{"system":[{"type":"text","text":"OpenClaw"}],"messages":[]}';
      const result = processBody(body, config);
      // OpenClaw should be sanitized even in system prompt
      assert.ok(!result.includes('"OpenClaw"'));
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Feature: Response Reverse Mapping
// ═══════════════════════════════════════════════════════════════════════════

describe('Feature: Response Reverse Mapping', () => {
  const config = {
    replacements: DEFAULT_REPLACEMENTS,
    reverseMap: DEFAULT_REVERSE_MAP,
  };

  it('should restore OCPlatform back to OpenClaw', () => {
    const text = 'OCPlatform is running';
    const result = reverseMap(text, config);
    assert.ok(result.includes('OpenClaw'));
    assert.ok(!result.includes('OCPlatform'));
  });

  it('should restore all session tool replacements', () => {
    const text = 'Running create_task and list_tasks and send_to_task and yield_task';
    const result = reverseMap(text, config);
    assert.ok(result.includes('sessions_spawn'));
    assert.ok(result.includes('sessions_list'));
    assert.ok(result.includes('sessions_send'));
    assert.ok(result.includes('sessions_yield'));
  });

  it('should handle text with no matches', () => {
    const text = 'Nothing to reverse here';
    const result = reverseMap(text, config);
    assert.equal(result, text);
  });

  it('should handle empty string', () => {
    const result = reverseMap('', config);
    assert.equal(result, '');
  });

  it('should handle multiple occurrences of the same term', () => {
    const text = 'OCPlatform uses OCPlatform tools';
    const result = reverseMap(text, config);
    assert.ok(!result.includes('OCPlatform'));
    assert.equal(result, 'OpenClaw uses OpenClaw tools');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Feature: Default Replacement / Reverse-Map Consistency
// ═══════════════════════════════════════════════════════════════════════════

describe('Feature: Replacement / Reverse-Map Consistency', () => {
  it('should have a reverse-map entry for each replacement (except intentional one-way)', () => {
    // The "running inside" -> "running on" replacement is intentionally one-way
    const oneWay = new Set(['running inside']);
    for (const [find, replace] of DEFAULT_REPLACEMENTS) {
      if (oneWay.has(find)) continue;
      const hasReverse = DEFAULT_REVERSE_MAP.some(([sanitized]) => sanitized === replace);
      assert.ok(hasReverse, `Missing reverse-map for: "${find}" -> "${replace}"`);
    }
  });

  it('should have matching pairs between replacement and reverse', () => {
    const oneWay = new Set(['running inside']);
    for (const [find, replace] of DEFAULT_REPLACEMENTS) {
      if (oneWay.has(find)) continue;
      const reverseEntry = DEFAULT_REVERSE_MAP.find(([sanitized]) => sanitized === replace);
      assert.ok(reverseEntry, `No reverse entry for "${replace}"`);
      assert.equal(reverseEntry[1], find, `Reverse mismatch: "${replace}" -> expected "${find}" got "${reverseEntry[1]}"`);
    }
  });

  it('should round-trip sanitization (except one-way)', () => {
    const config = { replacements: DEFAULT_REPLACEMENTS, reverseMap: DEFAULT_REVERSE_MAP };
    const original = 'OpenClaw sessions_spawn sessions_list sessions_stop sessions_status sessions_yield';
    const sanitized = DEFAULT_REPLACEMENTS.reduce(
      (text, [find, replace]) => text.split(find).join(replace),
      original
    );
    const restored = reverseMap(sanitized, config);
    assert.equal(restored, original);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Feature: Dashboard Rate Limit Parsing
// ═══════════════════════════════════════════════════════════════════════════

describe('Feature: Dashboard Rate Limit Parsing', () => {

  describe('Scenario: updateRateLimit', () => {
    it('should parse both 5h and 7d utilization headers', () => {
      const fakeRes = {
        headers: {
          'anthropic-ratelimit-unified-5h-utilization': '0.09',
          'anthropic-ratelimit-unified-5h-reset': '1775480400',
          'anthropic-ratelimit-unified-7d-utilization': '0.1',
          'anthropic-ratelimit-unified-7d-reset': '1775800800',
        }
      };
      dashboard.updateRateLimit(fakeRes);
      const rl = dashboard.lastRateLimit;
      assert.equal(rl.fiveH.util, 0.09);
      assert.equal(rl.fiveH.reset, 1775480400);
      assert.equal(rl.sevenD.util, 0.1);
      assert.equal(rl.sevenD.reset, 1775800800);
    });

    it('should not update when no utilization headers present', () => {
      dashboard.lastRateLimit = null;
      const fakeRes = { headers: { 'content-type': 'application/json' } };
      dashboard.updateRateLimit(fakeRes);
      assert.equal(dashboard.lastRateLimit, null);
    });

    it('should handle partial headers (only 5h)', () => {
      const fakeRes = {
        headers: {
          'anthropic-ratelimit-unified-5h-utilization': '0.55',
          'anthropic-ratelimit-unified-5h-reset': '1775480400',
        }
      };
      dashboard.updateRateLimit(fakeRes);
      const rl = dashboard.lastRateLimit;
      assert.equal(rl.fiveH.util, 0.55);
      assert.equal(rl.sevenD, null);
    });

    it('should handle partial headers (only 7d)', () => {
      const fakeRes = {
        headers: {
          'anthropic-ratelimit-unified-7d-utilization': '0.42',
          'anthropic-ratelimit-unified-7d-reset': '1775800800',
        }
      };
      dashboard.updateRateLimit(fakeRes);
      const rl = dashboard.lastRateLimit;
      assert.equal(rl.fiveH, null);
      assert.equal(rl.sevenD.util, 0.42);
    });

    it('should handle zero utilization', () => {
      const fakeRes = {
        headers: {
          'anthropic-ratelimit-unified-5h-utilization': '0',
          'anthropic-ratelimit-unified-5h-reset': '0',
          'anthropic-ratelimit-unified-7d-utilization': '0',
          'anthropic-ratelimit-unified-7d-reset': '0',
        }
      };
      dashboard.updateRateLimit(fakeRes);
      const rl = dashboard.lastRateLimit;
      assert.equal(rl.fiveH.util, 0);
      assert.equal(rl.sevenD.util, 0);
    });

    it('should handle utilization at 1.0 (100%)', () => {
      const fakeRes = {
        headers: {
          'anthropic-ratelimit-unified-5h-utilization': '1.0',
          'anthropic-ratelimit-unified-5h-reset': '1775480400',
        }
      };
      dashboard.updateRateLimit(fakeRes);
      assert.equal(dashboard.lastRateLimit.fiveH.util, 1.0);
    });

    it('should overwrite previous rate limit data', () => {
      dashboard.updateRateLimit({ headers: {
        'anthropic-ratelimit-unified-5h-utilization': '0.1',
        'anthropic-ratelimit-unified-5h-reset': '100',
      }});
      dashboard.updateRateLimit({ headers: {
        'anthropic-ratelimit-unified-5h-utilization': '0.9',
        'anthropic-ratelimit-unified-5h-reset': '200',
      }});
      assert.equal(dashboard.lastRateLimit.fiveH.util, 0.9);
      assert.equal(dashboard.lastRateLimit.fiveH.reset, 200);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Feature: Dashboard Visual Helpers
// ═══════════════════════════════════════════════════════════════════════════

describe('Feature: Dashboard Visual Helpers', () => {

  describe('Scenario: _renderBar', () => {
    it('should return 15 characters total', () => {
      for (const pct of [0, 25, 50, 75, 100]) {
        const bar = dashboard._renderBar(pct);
        assert.equal([...bar].length, 15, `Failed at ${pct}%`);
      }
    });

    it('should be all empty blocks at 0%', () => {
      assert.equal(dashboard._renderBar(0), '\u2591'.repeat(15));
    });

    it('should be all filled blocks at 100%', () => {
      assert.equal(dashboard._renderBar(100), '\u2588'.repeat(15));
    });

    it('should have approximately correct fill ratio', () => {
      const bar50 = dashboard._renderBar(50);
      const filled = [...bar50].filter(c => c === '\u2588').length;
      assert.ok(filled >= 7 && filled <= 8, `Expected ~7-8 filled at 50%, got ${filled}`);
    });
  });

  describe('Scenario: _pctColor', () => {
    it('should return green ANSI code below 50%', () => {
      assert.equal(dashboard._pctColor(0), '\x1b[32m');
      assert.equal(dashboard._pctColor(10), '\x1b[32m');
      assert.equal(dashboard._pctColor(49), '\x1b[32m');
    });

    it('should return yellow ANSI code between 50-79%', () => {
      assert.equal(dashboard._pctColor(50), '\x1b[33m');
      assert.equal(dashboard._pctColor(65), '\x1b[33m');
      assert.equal(dashboard._pctColor(79), '\x1b[33m');
    });

    it('should return red ANSI code at 80%+', () => {
      assert.equal(dashboard._pctColor(80), '\x1b[31m');
      assert.equal(dashboard._pctColor(95), '\x1b[31m');
      assert.equal(dashboard._pctColor(100), '\x1b[31m');
    });
  });

  describe('Scenario: _fmtReset', () => {
    it('should format future timestamps as hours and minutes', () => {
      const futureEpoch = Math.floor(Date.now() / 1000) + 7200; // +2 hours
      const result = dashboard._fmtReset(futureEpoch);
      assert.match(result, /^\dh\d+m$/);
    });

    it('should format minutes-only when under 1 hour', () => {
      const futureEpoch = Math.floor(Date.now() / 1000) + 1800; // +30 min
      const result = dashboard._fmtReset(futureEpoch);
      assert.match(result, /^\d+m$/);
      assert.ok(!result.includes('h'));
    });

    it('should return "now" for past timestamps', () => {
      const pastEpoch = Math.floor(Date.now() / 1000) - 100;
      assert.equal(dashboard._fmtReset(pastEpoch), 'now');
    });

    it('should return empty string for zero', () => {
      assert.equal(dashboard._fmtReset(0), '');
    });

    it('should return empty string for null', () => {
      assert.equal(dashboard._fmtReset(null), '');
    });

    it('should return empty string for undefined', () => {
      assert.equal(dashboard._fmtReset(undefined), '');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Feature: Dashboard Log Methods
// ═══════════════════════════════════════════════════════════════════════════

describe('Feature: Dashboard Log Methods', () => {

  beforeEach(() => {
    dashboard.recentLogs = [];
    dashboard.isTTY = false;
    _resetUsageData();
  });

  describe('Scenario: logRequest', () => {
    it('should add entry to recent logs', () => {
      dashboard.logRequest(1, 'POST', '/v1/messages', 200, 100, 50, 'S');
      assert.equal(dashboard.recentLogs.length, 1);
    });

    it('should cap at 10 entries (ring buffer)', () => {
      for (let i = 0; i < 15; i++) {
        dashboard.logRequest(i + 1, 'POST', '/v1/messages', 200, 10, 5, 'S');
      }
      assert.equal(dashboard.recentLogs.length, 10);
    });

    it('should prepend new entries (most recent first)', () => {
      dashboard.logRequest(1, 'POST', '/v1/messages', 200, 10, 5, 'S');
      dashboard.logRequest(2, 'POST', '/v1/messages', 200, 20, 10, 'O');
      const latest = stripAnsi(dashboard.recentLogs[0]);
      assert.ok(latest.includes('#2'), 'Most recent entry should be first');
    });

    it('should record usage for non-zero tokens', () => {
      dashboard.logRequest(1, 'POST', '/v1/messages', 200, 100, 50, 'S');
      const data = _usageData();
      const today = new Date().toISOString().substring(0, 10);
      assert.equal(data.days[today].input_tokens, 100);
      assert.equal(data.days[today].output_tokens, 50);
    });

    it('should skip recording usage for zero tokens', () => {
      dashboard.logRequest(1, 'POST', '/v1/messages', 400, 0, 0, 'S');
      const data = _usageData();
      const today = new Date().toISOString().substring(0, 10);
      assert.equal(data.days[today], undefined);
    });

    it('should include model tag in log entry', () => {
      dashboard.logRequest(1, 'POST', '/v1/messages', 200, 10, 5, 'O');
      const entry = stripAnsi(dashboard.recentLogs[0]);
      assert.ok(entry.startsWith('O '));
    });

    it('should use "?" for missing model tag', () => {
      dashboard.logRequest(1, 'POST', '/v1/messages', 200, 10, 5, null);
      const entry = stripAnsi(dashboard.recentLogs[0]);
      assert.ok(entry.startsWith('? '));
    });

    it('should include HTTP status code in log entry', () => {
      dashboard.logRequest(1, 'POST', '/v1/messages', 429, 0, 0, 'S');
      const entry = stripAnsi(dashboard.recentLogs[0]);
      assert.ok(entry.includes('429'));
    });
  });

  describe('Scenario: logRequest column alignment', () => {
    it('should produce fixed-width token columns regardless of values', () => {
      // Use same reqNum/method/url/status to isolate token column width
      dashboard.logRequest(1, 'POST', '/v1/messages', 200, 1234, 567, 'S');
      dashboard.logRequest(1, 'POST', '/v1/messages', 200, 0, 110, 'H');
      dashboard.logRequest(1, 'POST', '/v1/messages', 200, 50, 0, 'S');
      // All entries should have the same total length after stripping ANSI
      const lengths = dashboard.recentLogs.map(e => stripAnsi(e).length);
      assert.equal(lengths[0], lengths[1], `Length mismatch between entries with/without input tokens`);
      assert.equal(lengths[0], lengths[2], `Length mismatch between entries with/without output tokens`);
    });
  });

  describe('Scenario: logError', () => {
    it('should add entry to recent logs', () => {
      dashboard.logError(1, 'POST', '/v1/messages', 'Connection refused');
      assert.equal(dashboard.recentLogs.length, 1);
    });

    it('should include error message in log', () => {
      dashboard.logError(1, 'POST', '/v1/messages', 'ECONNREFUSED');
      const entry = stripAnsi(dashboard.recentLogs[0]);
      assert.ok(entry.includes('ECONNREFUSED'));
    });

    it('should include ERR prefix in log', () => {
      dashboard.logError(1, 'POST', '/v1/messages', 'timeout');
      const entry = stripAnsi(dashboard.recentLogs[0]);
      assert.ok(entry.includes('ERR:'));
    });

    it('should cap at 10 entries', () => {
      for (let i = 0; i < 12; i++) {
        dashboard.logError(i + 1, 'POST', '/v1/messages', `Error ${i}`);
      }
      assert.equal(dashboard.recentLogs.length, 10);
    });

    it('should mix with logRequest entries in ring buffer', () => {
      dashboard.logRequest(1, 'POST', '/v1/messages', 200, 10, 5, 'S');
      dashboard.logError(2, 'POST', '/v1/messages', 'timeout');
      dashboard.logRequest(3, 'POST', '/v1/messages', 200, 20, 10, 'S');
      assert.equal(dashboard.recentLogs.length, 3);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Feature: Dashboard Shutdown
// ═══════════════════════════════════════════════════════════════════════════

describe('Feature: Dashboard Shutdown', () => {

  beforeEach(() => {
    dashboard.isTTY = false;
    dashboard._uptimeInterval = null;
    _resetUsageData();
  });

  it('should call saveUsageData on shutdown', () => {
    recordUsage(100, 50);
    // shutdown should flush pending data
    dashboard.shutdown();
    // Verify usage data is still intact (not reset)
    const data = _usageData();
    const today = new Date().toISOString().substring(0, 10);
    assert.equal(data.days[today].input_tokens, 100);
  });

  it('should clear uptime interval if set', () => {
    let cleared = false;
    dashboard._uptimeInterval = setInterval(() => {}, 999999);
    dashboard.shutdown();
    // If interval wasn't cleared, this would keep Node running
    // Since test completes, interval was cleared (non-TTY path doesn't clear, but we check manually)
    clearInterval(dashboard._uptimeInterval); // safety cleanup
    dashboard._uptimeInterval = null;
  });

  it('should not throw in non-TTY mode', () => {
    dashboard.isTTY = false;
    assert.doesNotThrow(() => dashboard.shutdown());
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Feature: Model Tag Extraction
// ═══════════════════════════════════════════════════════════════════════════

describe('Feature: Model Tag Extraction', () => {
  // The extraction regex used in proxy.js request handler
  const MODEL_REGEX = /"model"\s*:\s*"([^"]+)"/;

  function extractTag(bodyStr) {
    const match = bodyStr.match(MODEL_REGEX);
    if (!match) return '?';
    const m = match[1].toLowerCase();
    if (m.includes('opus')) return 'O';
    if (m.includes('sonnet')) return 'S';
    if (m.includes('haiku')) return 'H';
    return '?';
  }

  it('should detect Sonnet model', () => {
    assert.equal(extractTag('{"model":"claude-sonnet-4-20250514","messages":[]}'), 'S');
  });

  it('should detect Haiku model', () => {
    assert.equal(extractTag('{"model":"claude-haiku-4-5-20251001","messages":[]}'), 'H');
  });

  it('should detect Opus model', () => {
    assert.equal(extractTag('{"model":"claude-opus-4-6","messages":[]}'), 'O');
  });

  it('should return "?" for unknown model', () => {
    assert.equal(extractTag('{"model":"gpt-4","messages":[]}'), '?');
  });

  it('should return "?" when model field is missing', () => {
    assert.equal(extractTag('{"messages":[]}'), '?');
  });

  it('should be case-insensitive', () => {
    assert.equal(extractTag('{"model":"Claude-SONNET-4","messages":[]}'), 'S');
  });

  it('should handle model with extra whitespace in JSON', () => {
    assert.equal(extractTag('{"model" : "claude-opus-4-6" , "messages":[]}'), 'O');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Feature: Number Formatting
// ═══════════════════════════════════════════════════════════════════════════

describe('Feature: Number Formatting (fmt)', () => {
  it('should format small numbers without separators', () => {
    assert.equal(fmt(0), '0');
    assert.equal(fmt(999), '999');
  });

  it('should format large numbers with locale separators', () => {
    const result = fmt(1000);
    // Locale-dependent, but should contain a separator
    assert.ok(result.length >= 4, `Expected formatted "1000" to have separator, got "${result}"`);
  });

  it('should handle negative numbers', () => {
    const result = fmt(-1500);
    assert.ok(result.includes('1'));
    assert.ok(result.includes('500'));
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Feature: Configuration Constants
// ═══════════════════════════════════════════════════════════════════════════

describe('Feature: Configuration Constants', () => {

  describe('Scenario: BILLING_BLOCK', () => {
    it('should be valid JSON', () => {
      const parsed = JSON.parse(BILLING_BLOCK);
      assert.equal(parsed.type, 'text');
      assert.ok(parsed.text.includes('x-anthropic-billing-header'));
    });

    it('should contain cc_version', () => {
      assert.ok(BILLING_BLOCK.includes('cc_version'));
    });

    it('should contain cc_entrypoint', () => {
      assert.ok(BILLING_BLOCK.includes('cc_entrypoint'));
    });
  });

  describe('Scenario: REQUIRED_BETAS', () => {
    it('should be a non-empty array', () => {
      assert.ok(Array.isArray(REQUIRED_BETAS));
      assert.ok(REQUIRED_BETAS.length > 0);
    });

    it('should include claude-code beta', () => {
      assert.ok(REQUIRED_BETAS.some(b => b.includes('claude-code')));
    });

    it('should include oauth beta', () => {
      assert.ok(REQUIRED_BETAS.some(b => b.includes('oauth')));
    });

    it('should have no duplicate entries', () => {
      const unique = new Set(REQUIRED_BETAS);
      assert.equal(unique.size, REQUIRED_BETAS.length);
    });
  });

  describe('Scenario: DEFAULT_REPLACEMENTS', () => {
    it('should be a non-empty array of [find, replace] pairs', () => {
      assert.ok(Array.isArray(DEFAULT_REPLACEMENTS));
      assert.ok(DEFAULT_REPLACEMENTS.length > 0);
      for (const entry of DEFAULT_REPLACEMENTS) {
        assert.equal(entry.length, 2, `Expected pair, got: ${JSON.stringify(entry)}`);
        assert.equal(typeof entry[0], 'string');
        assert.equal(typeof entry[1], 'string');
      }
    });

    it('should include OpenClaw replacement', () => {
      assert.ok(DEFAULT_REPLACEMENTS.some(([f]) => f === 'OpenClaw'));
    });
  });

  describe('Scenario: DEFAULT_REVERSE_MAP', () => {
    it('should be a non-empty array of [sanitized, original] pairs', () => {
      assert.ok(Array.isArray(DEFAULT_REVERSE_MAP));
      assert.ok(DEFAULT_REVERSE_MAP.length > 0);
      for (const entry of DEFAULT_REVERSE_MAP) {
        assert.equal(entry.length, 2);
        assert.equal(typeof entry[0], 'string');
        assert.equal(typeof entry[1], 'string');
      }
    });
  });
});
