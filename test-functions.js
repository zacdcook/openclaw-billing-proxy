'use strict';
const assert = require('assert');
const crypto = require('crypto');

// --- copy all constants here ---
const BILLING_HASH_SALT = '59cf53e54c78';
const BILLING_HASH_INDICES = [4, 7, 20];
const CC_VERSION = '2.1.97';

const REQUIRED_BETAS = [
  'oauth-2025-04-20',
  'claude-code-20250219',
  'interleaved-thinking-2025-05-14',
  'prompt-caching-scope-2026-01-05',
  'context-management-2025-06-27'
];

const THINK_MASK_PREFIX = '__OBP_THINK_MASK_';
const THINK_MASK_SUFFIX = '__';
const THINK_BLOCK_PATTERNS = ['{"type":"thinking"', '{"type":"redacted_thinking"'];

const DEFAULT_TOOL_RENAMES = [
  ['exec', 'mcp_Bash'],
  ['process', 'mcp_BashSession'],
  ['browser', 'mcp_BrowserControl'],
  ['canvas', 'mcp_CanvasView'],
  ['nodes', 'mcp_DeviceControl'],
  ['cron', 'mcp_Scheduler'],
  ['message', 'mcp_SendMessage'],
  ['tts', 'mcp_Speech'],
  ['gateway', 'mcp_SystemCtl'],
  ['agents_list', 'mcp_AgentList'],
  ['list_tasks', 'mcp_TaskList'],
  ['get_history', 'mcp_TaskHistory'],
  ['send_to_task', 'mcp_TaskSend'],
  ['create_task', 'mcp_TaskCreate'],
  ['subagents', 'mcp_AgentControl'],
  ['session_status', 'mcp_StatusCheck'],
  ['web_search', 'mcp_WebSearch'],
  ['web_fetch', 'mcp_WebFetch'],
  ['pdf', 'mcp_PdfParse'],
  ['image_generate', 'mcp_ImageCreate'],
  ['music_generate', 'mcp_MusicCreate'],
  ['video_generate', 'mcp_VideoCreate'],
  ['memory_search', 'mcp_KnowledgeSearch'],
  ['memory_get', 'mcp_KnowledgeGet'],
  ['lcm_expand_query', 'mcp_ContextQuery'],
  ['lcm_grep', 'mcp_ContextGrep'],
  ['lcm_describe', 'mcp_ContextDescribe'],
  ['lcm_expand', 'mcp_ContextExpand'],
  ['yield_task', 'mcp_TaskYield'],
  ['task_store', 'mcp_TaskStore'],
  ['task_yield_interrupt', 'mcp_TaskYieldInterrupt']
];

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
  ['rt_version', 'cc_version'],
  ['rt_entrypoint', 'cc_entrypoint'],
  ['routing config', 'billing header'],
  ['usage quota', 'extra usage']
];

// --- copy all functions here ---

function computeCch(text) {
  return crypto.createHash('sha256').update(text).digest('hex').slice(0, 5);
}

function computeBillingFingerprint(firstUserText) {
  const chars = BILLING_HASH_INDICES.map(i => firstUserText[i] || '0').join('');
  const input = `${BILLING_HASH_SALT}${chars}${CC_VERSION}`;
  return crypto.createHash('sha256').update(input).digest('hex').slice(0, 3);
}

function extractFirstUserText(bodyStr) {
  const msgsIdx = bodyStr.indexOf('"messages":[');
  if (msgsIdx === -1) return '';
  const userIdx = bodyStr.indexOf('"role":"user"', msgsIdx);
  if (userIdx === -1) return '';
  const contentIdx = bodyStr.indexOf('"content"', userIdx);
  if (contentIdx === -1 || contentIdx > userIdx + 500) return '';
  const afterContent = bodyStr[contentIdx + '"content"'.length + 1];
  if (afterContent === '"') {
    const textStart = contentIdx + '"content":"'.length;
    let end = textStart;
    while (end < bodyStr.length) {
      if (bodyStr[end] === '\\') { end += 2; continue; }
      if (bodyStr[end] === '"') break;
      end++;
    }
    return bodyStr.slice(textStart, end)
      .replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
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

function getModelBetas(modelId) {
  const m = (modelId || '').toLowerCase();
  const betas = [...REQUIRED_BETAS];
  if (m.includes('haiku')) {
    const idx = betas.indexOf('interleaved-thinking-2025-05-14');
    if (idx !== -1) betas.splice(idx, 1);
  }
  if (m.includes('4-6') || m.includes('4_6')) {
    if (!betas.includes('effort-2025-11-24')) betas.push('effort-2025-11-24');
  }
  return betas;
}

function findMatchingBrace(str, start) {
  let d = 0, inStr = false;
  for (let i = start; i < str.length; i++) {
    const c = str[i];
    if (inStr) {
      if (c === '\\') { i++; continue; }
      if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; continue; }
    if (c === '{') d++;
    else if (c === '}') { d--; if (d === 0) return i; }
  }
  return -1;
}

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

function stripEffortFromObject(str, objectKey) {
  const keyPattern = '"' + objectKey + '"';
  let pos = str.indexOf(keyPattern);
  if (pos === -1) return str;
  let braceStart = str.indexOf('{', pos + keyPattern.length);
  if (braceStart === -1) return str;
  const braceEnd = findMatchingBrace(str, braceStart);
  if (braceEnd === -1) return str;
  const inner = str.slice(braceStart + 1, braceEnd);
  let cleaned = inner
    .replace(/,\s*"effort"\s*:\s*(?:"[^"]*"|\d+(?:\.\d+)?|true|false|null)/, '')
    .replace(/"effort"\s*:\s*(?:"[^"]*"|\d+(?:\.\d+)?|true|false|null),?\s*/, '');
  cleaned = cleaned.replace(/,\s*$/, '').trim();
  if (cleaned === '') {
    const keyStart = str.lastIndexOf(',', pos);
    if (keyStart !== -1 && str.slice(keyStart, pos).trim() === ',') {
      return str.slice(0, keyStart) + str.slice(braceEnd + 1);
    }
    return str.slice(0, pos) + str.slice(braceEnd + 1);
  }
  return str.slice(0, braceStart + 1) + cleaned + str.slice(braceEnd);
}

function repairToolPairs(bodyStr) {
  const msgsStart = bodyStr.indexOf('"messages":[');
  if (msgsStart === -1) return bodyStr;
  const arrayOpenIdx = msgsStart + '"messages":'.length;
  const arrayCloseIdx = findMatchingBracket(bodyStr, arrayOpenIdx);
  if (arrayCloseIdx === -1) return bodyStr;
  const messagesJson = bodyStr.slice(arrayOpenIdx, arrayCloseIdx + 1);
  let messages;
  try {
    messages = JSON.parse(messagesJson);
  } catch (e) {
    console.warn('[REPAIR] Could not parse messages array:', e.message);
    return bodyStr;
  }
  if (!Array.isArray(messages)) return bodyStr;
  const toolUseIds = new Set();
  const toolResultIds = new Set();
  for (const message of messages) {
    if (!Array.isArray(message.content)) continue;
    for (const block of message.content) {
      if (block.type === 'tool_use' && typeof block.id === 'string') toolUseIds.add(block.id);
      if (block.type === 'tool_result' && typeof block.tool_use_id === 'string') toolResultIds.add(block.tool_use_id);
    }
  }
  const orphanedUses = new Set();
  for (const id of toolUseIds) { if (!toolResultIds.has(id)) orphanedUses.add(id); }
  const orphanedResults = new Set();
  for (const id of toolResultIds) { if (!toolUseIds.has(id)) orphanedResults.add(id); }
  if (orphanedUses.size === 0 && orphanedResults.size === 0) return bodyStr;
  console.log(`[REPAIR] Removing ${orphanedUses.size} orphaned tool_use and ${orphanedResults.size} orphaned tool_result blocks`);
  const candidateRepaired = messages.map((message) => {
    if (!Array.isArray(message.content)) return message;
    const filtered = message.content.filter((block) => {
      if (block.type === 'tool_use' && typeof block.id === 'string') return !orphanedUses.has(block.id);
      if (block.type === 'tool_result' && typeof block.tool_use_id === 'string') return !orphanedResults.has(block.tool_use_id);
      return true;
    });
    if (filtered.length === 0) return null;
    return { ...message, content: filtered };
  });
  const repaired = [];
  for (let i = 0; i < candidateRepaired.length; i++) {
    if (candidateRepaired[i] !== null) {
      repaired.push(candidateRepaired[i]);
    } else {
      const prevRole = repaired.length > 0 ? repaired[repaired.length - 1].role : null;
      const nextMsg = candidateRepaired.slice(i + 1).find(m => m !== null);
      const nextRole = nextMsg ? nextMsg.role : null;
      if (prevRole && nextRole && prevRole === nextRole) {
        repaired.push({ ...messages[i], content: [{ type: 'text', text: '(removed)' }] });
      }
    }
  }
  const repairedJson = JSON.stringify(repaired);
  return bodyStr.slice(0, arrayOpenIdx) + repairedJson + bodyStr.slice(arrayCloseIdx + 1);
}

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

function reverseMap(text, config) {
  let r = text;
  for (const [orig, cc] of config.toolRenames) {
    r = r.split('"' + cc + '"').join('"' + orig + '"');
    r = r.split('\\"' + cc + '\\"').join('\\"' + orig + '\\"');
  }
  for (const [orig, renamed] of config.propRenames) {
    r = r.split('"' + renamed + '"').join('"' + orig + '"');
    r = r.split('\\"' + renamed + '\\"').join('\\"' + orig + '\\"');
  }
  for (const [sanitized, original] of config.reverseMap) {
    r = r.split(sanitized).join(original);
  }
  return r;
}

// --- test helper ---

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  PASS: ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL: ${name}`);
    console.log(`    Expected: ${e.expected !== undefined ? JSON.stringify(e.expected) : ''}`);
    console.log(`    Actual:   ${e.actual !== undefined ? JSON.stringify(e.actual) : ''}`);
    console.log(`    Error:    ${e.message}`);
    failed++;
  }
}

// --- test suites ---

console.log('\n=== proxy.js Pure Function Unit Tests ===\n');

// A. computeCch
console.log('--- computeCch ---');
test('computeCch: hello world', () => {
  const expected = crypto.createHash('sha256').update('hello world').digest('hex').slice(0,5);
  assert.strictEqual(computeCch('hello world'), expected);
});
test('computeCch: empty string returns 5-char hex', () => {
  const result = computeCch('');
  assert.strictEqual(result.length, 5);
  assert.match(result, /^[0-9a-f]{5}$/);
});
test('computeCch: different inputs produce different outputs', () => {
  assert.notStrictEqual(computeCch('abc'), computeCch('xyz'));
});

// B. computeBillingFingerprint
console.log('\n--- computeBillingFingerprint ---');
test('computeBillingFingerprint: consistent for same input', () => {
  const a = computeBillingFingerprint('hello world test');
  const b = computeBillingFingerprint('hello world test');
  assert.strictEqual(a, b);
});
test('computeBillingFingerprint: different text produces different fingerprint', () => {
  assert.notStrictEqual(computeBillingFingerprint('hello world test'), computeBillingFingerprint('different input xyz'));
});
test('computeBillingFingerprint: returns 3-char hex string', () => {
  const result = computeBillingFingerprint('some text here');
  assert.strictEqual(result.length, 3);
  assert.match(result, /^[0-9a-f]{3}$/);
});
test('computeBillingFingerprint: short text uses 0 padding', () => {
  const result = computeBillingFingerprint('hi');
  assert.strictEqual(typeof result, 'string');
  assert.strictEqual(result.length, 3);
});

// C. extractFirstUserText
console.log('\n--- extractFirstUserText ---');
test('extractFirstUserText: simple string content', () => {
  const body = JSON.stringify({ messages: [{ role: 'user', content: 'hello' }] });
  assert.strictEqual(extractFirstUserText(body), 'hello');
});
test('extractFirstUserText: system then user', () => {
  const body = JSON.stringify({ messages: [
    { role: 'system', content: 'sys' },
    { role: 'user', content: 'hi' }
  ]});
  assert.strictEqual(extractFirstUserText(body), 'hi');
});
test('extractFirstUserText: content array format', () => {
  const body = JSON.stringify({ messages: [
    { role: 'user', content: [{ type: 'text', text: 'from array' }] }
  ]});
  assert.strictEqual(extractFirstUserText(body), 'from array');
});
test('extractFirstUserText: no user message returns empty string', () => {
  const body = JSON.stringify({ messages: [{ role: 'assistant', content: 'reply' }] });
  const result = extractFirstUserText(body);
  assert.ok(result === '' || result === null || result === undefined, `Expected empty/null, got ${JSON.stringify(result)}`);
});
test('extractFirstUserText: no messages key returns empty string', () => {
  const body = JSON.stringify({ model: 'claude-sonnet' });
  const result = extractFirstUserText(body);
  assert.ok(result === '' || result === null || result === undefined);
});

// D. getModelBetas
console.log('\n--- getModelBetas ---');
test('getModelBetas: haiku excludes interleaved-thinking', () => {
  const betas = getModelBetas('claude-haiku-4-5');
  assert.ok(!betas.includes('interleaved-thinking-2025-05-14'), 'haiku should NOT have interleaved-thinking');
});
test('getModelBetas: sonnet-4-6 includes effort', () => {
  const betas = getModelBetas('claude-sonnet-4-6');
  assert.ok(betas.includes('effort-2025-11-24'), 'sonnet-4-6 should have effort beta');
});
test('getModelBetas: sonnet-4-5 does NOT include effort', () => {
  const betas = getModelBetas('claude-sonnet-4-5');
  assert.ok(!betas.includes('effort-2025-11-24'), 'sonnet-4-5 should NOT have effort beta');
});
test('getModelBetas: opus-4-6 includes effort', () => {
  const betas = getModelBetas('claude-opus-4-6');
  assert.ok(betas.includes('effort-2025-11-24'), 'opus-4-6 should have effort beta');
});
test('getModelBetas: all results include oauth-2025-04-20', () => {
  for (const model of ['claude-haiku-4-5', 'claude-sonnet-4-6', 'claude-opus-4-6']) {
    const betas = getModelBetas(model);
    assert.ok(betas.includes('oauth-2025-04-20'), `${model} missing oauth beta`);
  }
});
test('getModelBetas: all results include claude-code-20250219', () => {
  for (const model of ['claude-haiku-4-5', 'claude-sonnet-4-6', 'claude-opus-4-6']) {
    const betas = getModelBetas(model);
    assert.ok(betas.includes('claude-code-20250219'), `${model} missing claude-code beta`);
  }
});
test('getModelBetas: no result includes advanced-tool-use or fast-mode', () => {
  for (const model of ['claude-haiku-4-5', 'claude-sonnet-4-6', 'claude-opus-4-6']) {
    const betas = getModelBetas(model);
    assert.ok(!betas.includes('advanced-tool-use-2025-11-20'), `${model} has unexpected advanced-tool-use`);
    assert.ok(!betas.includes('fast-mode-2026-02-01'), `${model} has unexpected fast-mode`);
  }
});
test('getModelBetas: sonnet-4-6 includes interleaved-thinking', () => {
  const betas = getModelBetas('claude-sonnet-4-6');
  assert.ok(betas.includes('interleaved-thinking-2025-05-14'), 'sonnet-4-6 should have interleaved-thinking');
});

// E. stripEffortFromObject
console.log('\n--- stripEffortFromObject ---');
test('stripEffortFromObject: removes effort from output_config', () => {
  const input = '{"model":"claude-haiku","output_config":{"effort":"high","other":"value"}}';
  const result = stripEffortFromObject(input, 'output_config');
  assert.ok(!result.includes('"effort"'), 'effort should be removed');
  assert.ok(result.includes('"other":"value"'), 'other fields should remain');
});
test('stripEffortFromObject: input without effort is unchanged', () => {
  const input = '{"model":"claude-haiku","output_config":{"max_tokens":1000}}';
  const result = stripEffortFromObject(input, 'output_config');
  assert.ok(result.includes('"max_tokens":1000'), 'unchanged fields should remain');
  assert.ok(!result.includes('"effort"'), 'no effort to remove is fine');
});
test('stripEffortFromObject: removes effort from thinking block', () => {
  const input = '{"thinking":{"effort":"high","type":"enabled"}}';
  const result = stripEffortFromObject(input, 'thinking');
  assert.ok(!result.includes('"effort"'), 'effort removed from thinking');
  assert.ok(result.includes('"type":"enabled"'), 'other fields remain');
});
test('stripEffortFromObject: key not present returns original', () => {
  const input = '{"model":"claude-haiku"}';
  const result = stripEffortFromObject(input, 'output_config');
  assert.strictEqual(result, input);
});
test('stripEffortFromObject: effort only — object removed', () => {
  const input = '{"model":"claude-haiku","output_config":{"effort":"high"}}';
  const result = stripEffortFromObject(input, 'output_config');
  assert.ok(!result.includes('"effort"'), 'effort removed');
});

// F. repairToolPairs
console.log('\n--- repairToolPairs ---');
test('repairToolPairs: matched pair unchanged', () => {
  const body = JSON.stringify({
    messages: [
      { role: 'assistant', content: [{ type: 'tool_use', id: 'tu_1', name: 'exec', input: {} }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'tu_1', content: 'ok' }] }
    ]
  });
  const result = repairToolPairs(body);
  const parsed = JSON.parse(result);
  const msgs = JSON.parse(result.match(/"messages":(\[.*\])/s)?.[1]);
  assert.strictEqual(msgs.length, 2, 'matched pair: both messages should remain');
});
test('repairToolPairs: orphaned tool_use removed', () => {
  const body = JSON.stringify({
    messages: [
      { role: 'assistant', content: [
        { type: 'tool_use', id: 'tu_orphan', name: 'exec', input: {} }
      ]}
    ]
  });
  const result = repairToolPairs(body);
  assert.ok(!result.includes('"tu_orphan"'), 'orphaned tool_use should be removed');
});
test('repairToolPairs: orphaned tool_result removed', () => {
  const body = JSON.stringify({
    messages: [
      { role: 'user', content: [
        { type: 'tool_result', tool_use_id: 'tu_missing', content: 'result' }
      ]}
    ]
  });
  const result = repairToolPairs(body);
  assert.ok(!result.includes('"tu_missing"'), 'orphaned tool_result should be removed');
});
test('repairToolPairs: no messages key returns original', () => {
  const body = '{"model":"claude"}';
  assert.strictEqual(repairToolPairs(body), body);
});

// G. maskThinkingBlocks / unmaskThinkingBlocks
console.log('\n--- maskThinkingBlocks / unmaskThinkingBlocks ---');
test('maskThinkingBlocks: round-trip preserves content', () => {
  const original = 'before {"type":"thinking","thinking":"secret content here"} after';
  const { masked, masks } = maskThinkingBlocks(original);
  assert.ok(!masked.includes('"thinking"'), 'masked string should not contain thinking');
  const restored = unmaskThinkingBlocks(masked, masks);
  assert.strictEqual(restored, original);
});
test('maskThinkingBlocks: no thinking blocks unchanged', () => {
  const input = '{"type":"text","text":"normal content"}';
  const { masked, masks } = maskThinkingBlocks(input);
  assert.strictEqual(masked, input);
  assert.strictEqual(masks.length, 0);
});
test('maskThinkingBlocks: redacted_thinking round-trip', () => {
  const original = 'before {"type":"redacted_thinking","data":"encrypted=="}  after';
  const { masked, masks } = maskThinkingBlocks(original);
  assert.ok(!masked.includes('"redacted_thinking"'), 'should be masked');
  const restored = unmaskThinkingBlocks(masked, masks);
  assert.strictEqual(restored, original);
});
test('maskThinkingBlocks: multiple blocks round-trip', () => {
  const original = '{"type":"thinking","thinking":"block1"} text {"type":"thinking","thinking":"block2"}';
  const { masked, masks } = maskThinkingBlocks(original);
  assert.strictEqual(masks.length, 2);
  const restored = unmaskThinkingBlocks(masked, masks);
  assert.strictEqual(restored, original);
});

// H. reverseMap
console.log('\n--- reverseMap ---');
test('reverseMap: restores mcp_Bash to exec', () => {
  const config = { toolRenames: DEFAULT_TOOL_RENAMES, propRenames: [], reverseMap: [] };
  const input = '{"name":"mcp_Bash","input":{}}';
  const result = reverseMap(input, config);
  assert.ok(result.includes('"exec"'), `Expected "exec" in result, got: ${result}`);
  assert.ok(!result.includes('"mcp_Bash"'), 'mcp_Bash should be reversed');
});
test('reverseMap: restores mcp_SendMessage to message', () => {
  const config = { toolRenames: DEFAULT_TOOL_RENAMES, propRenames: [], reverseMap: [] };
  const input = '{"name":"mcp_SendMessage"}';
  const result = reverseMap(input, config);
  assert.ok(result.includes('"message"'), `Expected "message" in result, got: ${result}`);
});
test('reverseMap: applies reverseMap strings', () => {
  const config = { toolRenames: [], propRenames: [], reverseMap: DEFAULT_REVERSE_MAP };
  const input = 'OCPlatform is running';
  const result = reverseMap(input, config);
  assert.ok(result.includes('OpenClaw'), `Expected OpenClaw restored, got: ${result}`);
});
test('reverseMap: handles escaped quotes in tool names', () => {
  const config = { toolRenames: DEFAULT_TOOL_RENAMES, propRenames: [], reverseMap: [] };
  const input = '{"partial_json":"{\\"name\\":\\"mcp_Bash\\"}"}';
  const result = reverseMap(input, config);
  assert.ok(result.includes('\\"exec\\"'), `Expected escaped exec restored, got: ${result}`);
});
test('reverseMap: empty input unchanged', () => {
  const config = { toolRenames: DEFAULT_TOOL_RENAMES, propRenames: [], reverseMap: DEFAULT_REVERSE_MAP };
  assert.strictEqual(reverseMap('', config), '');
});

// --- summary ---
console.log(`\nResults: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);
if (failed > 0) process.exit(1);
