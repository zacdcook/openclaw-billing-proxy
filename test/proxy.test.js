const test = require('node:test');
const assert = require('node:assert/strict');

const {
  DEFAULT_REVERSE_MAP,
  DEFAULT_REPLACEMENTS,
  DEFAULT_TOOL_RENAMES,
  DEFAULT_PROP_RENAMES,
  maskToolUseInputs,
  processBody,
  reverseMap
} = require('../proxy');

function defaultConfig() {
  return {
    replacements: DEFAULT_REPLACEMENTS,
    reverseMap: DEFAULT_REVERSE_MAP,
    toolRenames: DEFAULT_TOOL_RENAMES,
    propRenames: DEFAULT_PROP_RENAMES,
    stripSystemConfig: false,
    stripToolDescriptions: false,
    injectCCStubs: false,
    stripTrailingAssistantPrefill: false
  };
}

test('reverseMap restores path strings in one chunk', () => {
  const input = '{"path":"/home/user/.ocplatform/ocplatform.json"}';
  const output = reverseMap(input, defaultConfig());

  assert.equal(output, '{"path":"/home/user/.openclaw/openclaw.json"}');
});

test('maskToolUseInputs masks only the input object for a tool_use block', () => {
  const body = '{"type":"tool_use","id":"x","name":"Read","input":{"path":"/home/user/.openclaw/openclaw.json"}}';
  const { masked, masks } = maskToolUseInputs(body);

  assert.deepEqual(masks, ['{"path":"/home/user/.openclaw/openclaw.json"}']);
  assert.match(masked, /"input":__OBP_TOOL_INPUT_MASK_0__/);
  assert.match(masked, /"type":"tool_use"/);
});

test('processBody does not sanitize tool_use input paths in message history', () => {
  const body = JSON.stringify({
    model: 'claude-sonnet-4-5',
    max_tokens: 256,
    system: [{ type: 'text', text: 'OpenClaw is running inside /home/user/.openclaw' }],
    messages: [
      { role: 'user', content: 'Use /home/user/.openclaw/openclaw.json' },
      {
        role: 'assistant',
        content: [
          {
            type: 'tool_use',
            id: 'toolu_1',
            name: 'Read',
            input: { path: '/home/user/.openclaw/openclaw.json' }
          }
        ]
      }
    ],
    tools: []
  });

  const output = processBody(body, defaultConfig());

  assert.match(output, /ocplatform/);
  assert.match(output, /"input":\{"path":"\/home\/user\/\.openclaw\/openclaw\.json"\}/);
});
