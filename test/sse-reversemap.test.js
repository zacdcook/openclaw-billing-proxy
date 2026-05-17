const test = require('node:test');
const assert = require('node:assert/strict');
const { reverseMap, applySseReverseMapChunks } = require('../proxy.js');

// Deterministic config — independent of the host's config.json.
const CONFIG = {
  reverseMap: [
    ['ocplatform', 'openclaw'],
    ['routing-layer', 'billing-proxy'],
  ],
  toolRenames: [['message', 'SendMessage']],
  propRenames: [['path', 'file_path']],
};

function textEvent(index, text) {
  return 'event: content_block_delta\ndata: ' +
    JSON.stringify({ type: 'content_block_delta', index, delta: { type: 'text_delta', text } }) + '\n\n';
}
function jsonEvent(index, partial) {
  return 'event: content_block_delta\ndata: ' +
    JSON.stringify({ type: 'content_block_delta', index, delta: { type: 'input_json_delta', partial_json: partial } }) + '\n\n';
}
function stopEvent(index) {
  return 'data: ' + JSON.stringify({ type: 'content_block_stop', index }) + '\n\n';
}

// Reassemble the text_delta / input_json_delta payloads from transformer output.
function reconstruct(out, field) {
  return out.split('\n\n').map((e) => e.trim()).filter(Boolean)
    .map((e) => e.split('\n').find((l) => l.startsWith('data: ')))
    .filter(Boolean)
    .map((l) => JSON.parse(l.slice(6)))
    .filter((p) => p.type === 'content_block_delta' && p.delta &&
      (p.delta.type === 'text_delta' || p.delta.type === 'input_json_delta'))
    .map((p) => (field in p.delta ? p.delta[field] : ''))
    .join('');
}

test('text_delta: exact reconstruction at every two-way split offset', () => {
  const full = 'open ~/.ocplatform inside the routing-layer please';
  const expected = reverseMap(full, CONFIG);
  for (let i = 1; i < full.length; i++) {
    const events = [textEvent(0, full.slice(0, i)), textEvent(0, full.slice(i)), stopEvent(0)];
    const got = reconstruct(applySseReverseMapChunks(events, CONFIG), 'text');
    assert.equal(got, expected, `split at offset ${i}`);
  }
});

test('text_delta: exact reconstruction when split into single characters', () => {
  const full = 'cd ocplatform/routing-layer/run';
  const expected = reverseMap(full, CONFIG);
  const events = full.split('').map((ch) => textEvent(0, ch));
  events.push(stopEvent(0));
  const got = reconstruct(applySseReverseMapChunks(events, CONFIG), 'text');
  assert.equal(got, expected);
});

test('input_json_delta: exact reconstruction at every two-way split offset', () => {
  // partial_json carries tool args; inner quotes arrive JSON-escaped.
  const full = '{\\"path\\":\\"~/.ocplatform/ws\\",\\"SendMessage\\":\\"hi\\"}';
  const expected = reverseMap(full, CONFIG);
  for (let i = 1; i < full.length; i++) {
    const events = [jsonEvent(1, full.slice(0, i)), jsonEvent(1, full.slice(i)), stopEvent(1)];
    const got = reconstruct(applySseReverseMapChunks(events, CONFIG), 'partial_json');
    assert.equal(got, expected, `split at offset ${i}`);
  }
});

test('split token across raw TCP chunks within one SSE event', () => {
  const event = textEvent(0, 'cd ~/.ocplatform/workspace') + stopEvent(0);
  const splitPoint = event.indexOf('ocplatform') + 'ocpla'.length;
  const chunks = [event.slice(0, splitPoint), event.slice(splitPoint)];
  const got = reconstruct(applySseReverseMapChunks(chunks, CONFIG), 'text');
  assert.equal(got, 'cd ~/.openclaw/workspace');
});

test('flushAll emits the held tail when no content_block_stop arrives', () => {
  // Token split across events, stream ends abruptly without a stop event.
  const events = [textEvent(0, 'go to ~/.ocpla'), textEvent(0, 'tform/ws')];
  const got = reconstruct(applySseReverseMapChunks(events, CONFIG), 'text');
  assert.equal(got, 'go to ~/.openclaw/ws');
});

test('thinking and redacted_thinking blocks pass through byte-identical', () => {
  const events = [
    'data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking"}}\n\n',
    'data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"raw ocplatform routing-layer"}}\n\n',
    'data: {"type":"content_block_stop","index":0}\n\n',
    'data: {"type":"content_block_start","index":1,"content_block":{"type":"redacted_thinking"}}\n\n',
    'data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"ocplatform"}}\n\n',
    'data: {"type":"content_block_stop","index":1}\n\n',
  ];
  const out = applySseReverseMapChunks(events, CONFIG);
  assert.equal(out, events.join(''));
});
