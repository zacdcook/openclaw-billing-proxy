// Boundary tests for the raw-string SSE reverse path (companion to
// sse-reversemap.test.js). Pure local logic — no network, no proxy, no API.
//
// Property under test: for ANY way a logical value is fragmented across SSE
// *_delta events, the client-reassembled result equals reverseMap() applied to
// the whole value. Plus: thinking byte-equality, multi-block isolation, flush,
// JSON validity, and the raw-string codec helpers.
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  reverseMap, applySseReverseMapChunks,
  jsonStringDecode, jsonStringEncode, findSseStringField, extractSseIntField,
} = require('../proxy.js');

// Deterministic config — independent of the host's config.json / credentials.
const CONFIG = {
  reverseMap: [
    ['ocplatform', 'openclaw'],
    ['OCPlatform', 'OpenClaw'],
    ['skillhub.example.com', 'clawhub.com'],
    ['skillhub', 'clawhub'],
    ['hb_signal', 'heartbeat'],
    ['create_task', 'sessions_spawn'],
  ],
  toolRenames: [['exec', 'Bash'], ['message', 'SendMessage'], ['create_task', 'TaskCreate']],
  propRenames: [['session_id', 'thread_id'], ['wake_at', 'trigger_at']],
};

// ── builders ────────────────────────────────────────────────────────────────
function startEvent(index, kind) {
  const cb = kind === 'thinking' ? { type: 'thinking', thinking: '' }
    : kind === 'redacted_thinking' ? { type: 'redacted_thinking', data: 'abc' }
    : kind === 'tool_use' ? { type: 'tool_use', id: 'tu', name: 'Bash', input: {} }
    : { type: 'text', text: '' };
  return 'event: content_block_start\ndata: ' +
    JSON.stringify({ type: 'content_block_start', index, content_block: cb }) + '\n\n';
}
function deltaEvent(index, field, value) {
  const delta = field === 'partial_json' ? { type: 'input_json_delta', partial_json: value }
    : field === 'thinking' ? { type: 'thinking_delta', thinking: value }
    : { type: 'text_delta', text: value };
  return 'event: content_block_delta\ndata: ' +
    JSON.stringify({ type: 'content_block_delta', index, delta }) + '\n\n';
}
function stopEvent(index) {
  return 'event: content_block_stop\ndata: ' +
    JSON.stringify({ type: 'content_block_stop', index }) + '\n\n';
}

// ── reassembly + validity ─────────────────────────────────────────────────────
function dataLines(out) {
  return out.split('\n\n').map((e) => e.trim()).filter(Boolean)
    .map((e) => e.split('\n').find((l) => l.startsWith('data: ')))
    .filter(Boolean).map((l) => l.slice(6));
}
function assertAllValidJson(out) {
  for (const d of dataLines(out)) JSON.parse(d); // throws on any malformed emitted event
}
function reassemble(out) {
  const acc = {};
  for (const d of dataLines(out)) {
    const p = JSON.parse(d);
    if (p.type !== 'content_block_delta' || !p.delta || typeof p.index !== 'number') continue;
    const f = p.delta.type === 'input_json_delta' ? 'pj' : p.delta.type === 'text_delta' ? 'tx'
      : p.delta.type === 'thinking_delta' ? 'th' : null;
    if (!f) continue;
    const v = f === 'pj' ? p.delta.partial_json : f === 'tx' ? p.delta.text : p.delta.thinking;
    acc[p.index + ':' + f] = (acc[p.index + ':' + f] || '') + v;
  }
  return acc;
}
function streamOf(field, parts, byteChunkSize) {
  const kind = field === 'partial_json' ? 'tool_use' : 'text';
  let sse = startEvent(0, kind);
  for (const p of parts) sse += deltaEvent(0, field, p);
  sse += stopEvent(0);
  let chunks = [sse];
  if (byteChunkSize) {
    const buf = Buffer.from(sse, 'utf8'); chunks = [];
    for (let i = 0; i < buf.length; i += byteChunkSize) chunks.push(buf.slice(i, i + byteChunkSize));
  }
  const out = applySseReverseMapChunks(chunks, CONFIG);
  assertAllValidJson(out);
  return reassemble(out)['0:' + (field === 'partial_json' ? 'pj' : 'tx')] || '';
}

// Assert reconstruct === reverseMap(whole) for EVERY 2-way split, all 3-way
// splits, char-by-char, single event, and byte-level TCP fragmentation.
function everySplit(field, W) {
  const expected = reverseMap(W, CONFIG);
  for (let i = 1; i < W.length; i++) {
    assert.equal(streamOf(field, [W.slice(0, i), W.slice(i)]), expected, `2-way @${i}`);
  }
  for (let a = 1; a < W.length - 1; a++) for (let b = a + 1; b < W.length; b++) {
    assert.equal(streamOf(field, [W.slice(0, a), W.slice(a, b), W.slice(b)]), expected, `3-way @${a},${b}`);
  }
  assert.equal(streamOf(field, [W]), expected, 'single event');
  assert.equal(streamOf(field, W.split('')), expected, 'char-by-char');
  assert.equal(streamOf(field, [W.slice(0, (W.length / 2) | 0), W.slice((W.length / 2) | 0)], 3), expected, 'byte chunks=3');
}

// ── 1. text_delta boundary splits ────────────────────────────────────────────
test('text: brand/dict targets at every split', () => {
  everySplit('text', 'open ~/.ocplatform via skillhub.example.com hb_signal ok');
});
test('text: capitalized OCPlatform + multiple targets', () => {
  everySplit('text', 'OCPlatform talks to ocplatform through skillhub');
});

// ── 2. input_json_delta, REAL-quote tool input (the common case) ─────────────
test('json (real quotes): C1 property key thread_id -> session_id', () => {
  everySplit('partial_json', '{"thread_id":"abc-123","wake_at":17}');
});
test('json (real quotes): renamed tool name as a value', () => {
  everySplit('partial_json', '{"target_tool":"TaskCreate"}');
});
test('json (real quotes): ocplatform path in a command arg', () => {
  everySplit('partial_json', '{"command":"ls ~/.ocplatform/cfg"}');
});

// ── 3. input_json_delta, ESCAPED-quote (nested-JSON) form, like #56 ──────────
test('json (escaped quotes): property + tool name', () => {
  everySplit('partial_json', '{\\"session_id\\":\\"x\\",\\"message\\":\\"hi\\"}');
});

// ── 4. multi-byte / surrogate boundaries ─────────────────────────────────────
test('text: emoji surrogate pairs adjacent to a target, every split', () => {
  everySplit('text', 'hi \u{1F600} run ocplatform \u{1F680} skillhub done');
});
test('text: CJK around a target', () => {
  everySplit('text', '請執行 ocplatform 然後連到 skillhub.example.com');
});

// ── 5. escaped characters inside the value ───────────────────────────────────
test('json: escaped quote inside a string value', () => {
  everySplit('partial_json', '{"q":"say \\"ocplatform\\" now"}');
});
test('text: newline and tab around a target', () => {
  everySplit('text', 'line1\nline2\tocplatform\tend');
});

// ── 6. thinking byte-equality (vector B preserved) ───────────────────────────
test('thinking + redacted_thinking pass through byte-identical (targets NOT reversed)', () => {
  const events = [
    startEvent(0, 'thinking'),
    deltaEvent(0, 'thinking', 'plan: run ocplatform via skillhub'),
    stopEvent(0),
    startEvent(1, 'redacted_thinking'),
    deltaEvent(1, 'thinking', 'ocplatform secret'),
    stopEvent(1),
  ];
  const out = applySseReverseMapChunks(events, CONFIG);
  assert.equal(out, events.join(''));
});
test('a text block after a thinking block still reverses (no desync)', () => {
  const events = [
    startEvent(0, 'thinking'), deltaEvent(0, 'thinking', 'ocplatform'), stopEvent(0),
    startEvent(1, 'text'), deltaEvent(1, 'text', 'now run oc'), deltaEvent(1, 'text', 'platform'), stopEvent(1),
  ];
  const out = applySseReverseMapChunks(events, CONFIG);
  assert.equal(reassemble(out)['1:tx'], 'now run openclaw');
});

// ── 7. multiple content blocks interleaved (per-index isolation) ─────────────
test('two tool_use blocks streaming concurrently stay isolated', () => {
  const events = [
    startEvent(0, 'tool_use'), startEvent(1, 'tool_use'),
    deltaEvent(0, 'partial_json', '{"a":"oc'),
    deltaEvent(1, 'partial_json', '{"b":"skill'),
    deltaEvent(0, 'partial_json', 'platform"}'),
    deltaEvent(1, 'partial_json', 'hub"}'),
    stopEvent(0), stopEvent(1),
  ];
  const out = applySseReverseMapChunks(events, CONFIG);
  assertAllValidJson(out);
  const r = reassemble(out);
  assert.equal(r['0:pj'], '{"a":"openclaw"}');
  assert.equal(r['1:pj'], '{"b":"clawhub"}');
});

// ── 8. flush without content_block_stop ──────────────────────────────────────
test('flushAll emits held tail when stream ends with no stop', () => {
  const events = [startEvent(0, 'text'), deltaEvent(0, 'text', 'go to oc'), deltaEvent(0, 'text', 'platform')];
  const out = applySseReverseMapChunks(events, CONFIG); // no stop, no manual flush — applySseReverseMapChunks calls flushAll
  assert.equal(reassemble(out)['0:tx'], 'go to openclaw');
});

// ── 9. fake "index"/"partial_json" inside a value must not fool extraction ───
test('envelope index/field anchoring is escape-aware', () => {
  everySplit('text', 'note: "index": 9 and "partial_json" appear; run ocplatform');
});

// ── 10. raw-string codec helpers ─────────────────────────────────────────────
test('jsonStringDecode/Encode round-trip + valid JSON body', () => {
  const cases = [
    'plain', 'q"uote and \\back', 'tab\tnl\ncr\r', 'café 日本語 résumé',
    'emoji \u{1F600}\u{1F680}', 'slash a/b', 'ctrlend',
  ];
  for (const s of cases) {
    const enc = jsonStringEncode(s);
    JSON.parse('"' + enc + '"');                 // enc must be a valid JSON string body
    assert.equal(jsonStringDecode(enc), s, `round-trip ${JSON.stringify(s)}`);
  }
});
test('jsonStringEncode escapes lone surrogate (transport-safe, reassembles)', () => {
  const encHi = jsonStringEncode('\uD83D');
  assert.equal(encHi, '\\ud83d');
  JSON.parse('"' + encHi + '"');
  const encLo = jsonStringEncode('\uDE00');
  assert.equal(encLo, '\\ude00');
  // a valid pair stays literal (not over-escaped)
  assert.equal(jsonStringEncode('\u{1F600}'), '\u{1F600}');
});
test('jsonStringDecode handles \\uXXXX and escapes', () => {
  assert.equal(jsonStringDecode('\\u0041\\n\\t\\"\\\\'), 'A\n\t"\\');
});
test('findSseStringField / extractSseIntField anchor on the envelope', () => {
  const ds = '{"type":"content_block_delta","index":7,"delta":{"type":"input_json_delta","partial_json":"{\\"k\\":\\"v\\"}"}}';
  assert.equal(extractSseIntField(ds, 'index'), 7);
  const loc = findSseStringField(ds, 'partial_json');
  assert.equal(ds.slice(loc.start, loc.end), '{\\"k\\":\\"v\\"}');
  assert.equal(extractSseIntField(ds, 'nope'), null);
  assert.equal(findSseStringField(ds, 'nope'), null);
});

// ── 11. signature_delta inside a thinking block must stay byte-identical ──────
// (the signature is cryptographically validated on the next turn — any mutation
// breaks the conversation).
test('signature_delta inside a thinking block passes through byte-identical', () => {
  const sig = 'event: content_block_delta\ndata: ' +
    JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'signature_delta', signature: 'ErUBC+ocplatform/sig+base64==' } }) + '\n\n';
  const events = [startEvent(0, 'thinking'), deltaEvent(0, 'thinking', 'reasoning about ocplatform'), sig, stopEvent(0)];
  const out = applySseReverseMapChunks(events, CONFIG);
  assert.equal(out, events.join(''));
});

// ── 12. non-content_block events (ping / message_delta) pass through untouched
//        and do not desync the carry buffer ─────────────────────────────────────
test('ping / message_delta interleaved pass through and do not desync the stream', () => {
  const ping = 'event: ping\ndata: ' + JSON.stringify({ type: 'ping' }) + '\n\n';
  const msgDelta = 'event: message_delta\ndata: ' +
    JSON.stringify({ type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 5 } }) + '\n\n';
  const events = [startEvent(0, 'text'), deltaEvent(0, 'text', 'go to oc'), ping, deltaEvent(0, 'text', 'platform'), stopEvent(0), msgDelta];
  const out = applySseReverseMapChunks(events, CONFIG);
  assertAllValidJson(out);
  assert.equal(reassemble(out)['0:tx'], 'go to openclaw', 'token reverses across the ping-interrupted deltas');
  assert.ok(out.includes(ping), 'ping passed through unchanged');
  assert.ok(out.includes(msgDelta), 'message_delta passed through unchanged');
});

// ── 13. cut landing INSIDE a surrogate pair (each delta carries a lone half) ──
test('split inside a surrogate pair reassembles the astral char intact', () => {
  const W = 'x\u{1F600}y ocplatform';     // 😀 = 😀
  const hi = W.indexOf('\uD83D');
  const got = streamOf('text', [W.slice(0, hi + 1), W.slice(hi + 1)]); // cut between high and low
  assert.equal(got, reverseMap(W, CONFIG));
  assert.ok(got.includes('\u{1F600}'), 'astral code point intact after reassembly');
});

// ── 14. extractSseIntField numeric edge cases ────────────────────────────────
test('extractSseIntField: negative, post-colon spaces, non-numeric, no suffix/prefix collision', () => {
  assert.equal(extractSseIntField('{"index":-5}', 'index'), -5);
  assert.equal(extractSseIntField('{"index":   42}', 'index'), 42);
  assert.equal(extractSseIntField('{"index":abc}', 'index'), null);
  assert.equal(extractSseIntField('{"index_hint":1,"index":3}', 'index'), 3);
  assert.equal(extractSseIntField('{"stop_index":9,"index":7}', 'index'), 7);
});

// ── 15. combined: surrogate-pair split + escaped fake envelope in one value ───
test('combined surrogate + embedded escaped fake-envelope in one text value', () => {
  everySplit('text', 'pre \u{1F680} say "index": 9 then ocplatform end');
});

// ── DOCUMENTED LIMITATIONS ───────────────────────────────────────────────────
// Two properties are inherited from PR #56's streamReverse + the single
// currentBlockIsThinking flag. Both are SAFE under the real default config and the
// Anthropic streaming contract, and are intentionally left unchanged here per the
// maintainer's "keep streamReverse verbatim" direction. We lock the SUPPORTED shape:
//
// (a) Chaining configs — if one entry's OUTPUT can combine with later streamed bytes
//     to re-form ANOTHER entry's search key, the streamed result can diverge from
//     reverseMap(whole). Default config has no such window-splitting chain.
test('non-chaining multi-entry config round-trips at every split (supported shape)', () => {
  const cfg = { reverseMap: [['aaa', 'X'], ['bbb', 'Y']], toolRenames: [], propRenames: [] };
  const W = 'aaa mid bbb end';
  const expected = reverseMap(W, cfg);
  for (let i = 1; i < W.length; i++) {
    const sse = startEvent(0, 'text') + deltaEvent(0, 'text', W.slice(0, i)) + deltaEvent(0, 'text', W.slice(i)) + stopEvent(0);
    assert.equal(reassemble(applySseReverseMapChunks([sse], cfg))['0:tx'], expected, `@${i}`);
  }
});
//
// (b) Thinking isolation — currentBlockIsThinking is a single flag, not per-index.
//     The Anthropic stream emits content blocks strictly sequentially (never
//     interleaved), so this is safe. We lock the contract-shaped behavior.
test('sequential thinking then text (contract order) reverses correctly', () => {
  const events = [
    startEvent(0, 'thinking'), deltaEvent(0, 'thinking', 'ocplatform'), stopEvent(0),
    startEvent(1, 'text'), deltaEvent(1, 'text', 'run ocplatform'), stopEvent(1),
  ];
  const out = applySseReverseMapChunks(events, CONFIG);
  assert.equal(reassemble(out)['0:th'], 'ocplatform', 'thinking token NOT reversed');
  assert.equal(reassemble(out)['1:tx'], 'run openclaw', 'following text block reversed');
});
