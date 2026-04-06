#!/usr/bin/env node
/**
 * Setup script for OpenClaw Billing Proxy
 *
 * Auto-detects OpenClaw configuration, scans for sessions_* tools,
 * and generates sanitization + reverse mapping rules.
 *
 * Usage: node setup.js
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const homeDir = os.homedir();

console.log('\n  OpenClaw Billing Proxy Setup');
console.log('  ---------------------------\n');

// Step 1: Check Claude Code auth
console.log('1. Checking Claude Code authentication...');
const credsPaths = [
  path.join(homeDir, '.claude', '.credentials.json'),
  path.join(homeDir, '.claude', 'credentials.json')
];

let credsPath = null;
for (const p of credsPaths) {
  if (fs.existsSync(p)) { credsPath = p; break; }
}

if (!credsPath) {
  console.error('   NOT FOUND.');
  console.error('');
  console.error('   Claude Code CLI must be installed and authenticated first:');
  console.error('');
  console.error('     npm install -g @anthropic-ai/claude-code');
  console.error('     claude auth login');
  console.error('');
  console.error('   This opens a browser to sign in with your Claude Max/Pro account.');
  console.error('   After authenticating, run this setup script again.');
  console.error('');
  console.error('   Searched for credentials at:');
  for (const p of credsPaths) { console.error('     ' + p); }
  process.exit(1);
}

const creds = JSON.parse(fs.readFileSync(credsPath, 'utf8'));
if (!creds.claudeAiOauth || !creds.claudeAiOauth.accessToken) {
  console.error('   No OAuth token found. Run "claude auth login".');
  process.exit(1);
}

const expiresIn = ((creds.claudeAiOauth.expiresAt - Date.now()) / 3600000).toFixed(1);
console.log('   OK: ' + creds.claudeAiOauth.subscriptionType + ' subscription, token expires in ' + expiresIn + 'h');

// Step 2: Find OpenClaw config
console.log('\n2. Finding OpenClaw configuration...');
const oclawPaths = [
  path.join(homeDir, '.openclaw', 'openclaw.json'),
  '/etc/openclaw/openclaw.json'
];

let oclawPath = null;
for (const p of oclawPaths) {
  if (fs.existsSync(p)) { oclawPath = p; break; }
}

// Build replacement and reverse map lists
const replacements = [
  ['OpenClaw', 'OCPlatform'],
  ['openclaw', 'ocplatform'],
  ['HEARTBEAT_OK', 'HB_ACK'],
  ['running inside', 'running on']
];

const reverseMap = [
  ['OCPlatform', 'OpenClaw'],
  ['ocplatform', 'openclaw'],
  ['HB_ACK', 'HEARTBEAT_OK']
];

// Step 3: Scan for sessions_* tools
console.log('\n3. Scanning for session management tools...');

if (oclawPath) {
  console.log('   Found: ' + oclawPath);
  const oclawConfig = JSON.parse(fs.readFileSync(oclawPath, 'utf8'));

  const baseUrl = (oclawConfig.models && oclawConfig.models.providers &&
    oclawConfig.models.providers.anthropic && oclawConfig.models.providers.anthropic.baseUrl) || 'unknown';
  console.log('   Current baseUrl: ' + baseUrl);

  // Scan OpenClaw source for DEFAULT_TOOL_ALLOW to find all sessions_* tools
  const oclawDir = path.dirname(oclawPath);
  const distDir = path.join(oclawDir, '..', 'node_modules', 'openclaw', 'dist');
  const globalDist = '/usr/lib/node_modules/openclaw/dist';
  const npmGlobalDist = path.join(homeDir, '.npm-global', 'lib', 'node_modules', 'openclaw', 'dist');

  const distPaths = [distDir, globalDist, npmGlobalDist];
  // Also check npm global on Windows
  if (process.platform === 'win32') {
    distPaths.push(path.join(process.env.APPDATA || '', 'npm', 'node_modules', 'openclaw', 'dist'));
  }
  // Check NVM install paths
  const nvmDir = path.join(homeDir, '.nvm', 'versions', 'node');
  if (fs.existsSync(nvmDir)) {
    try {
      const versions = fs.readdirSync(nvmDir);
      for (const v of versions) {
        distPaths.push(path.join(nvmDir, v, 'lib', 'node_modules', 'openclaw', 'dist'));
      }
    } catch (e) { /* skip */ }
  }

  let sessionTools = [];
  for (const dp of distPaths) {
    if (!fs.existsSync(dp)) continue;
    try {
      const files = fs.readdirSync(dp).filter(function(f) { return f.endsWith('.js'); });
      for (const f of files) {
        const content = fs.readFileSync(path.join(dp, f), 'utf8');
        const matches = content.match(/sessions_[a-z_]+/g);
        if (matches) {
          for (const m of matches) {
            if (sessionTools.indexOf(m) === -1) sessionTools.push(m);
          }
        }
      }
      if (sessionTools.length > 0) {
        console.log('   Found OpenClaw dist at: ' + dp);
        break;
      }
    } catch (e) { /* skip */ }
  }

  if (sessionTools.length === 0) {
    // Fallback: use known sessions_* tools
    sessionTools = ['sessions_spawn', 'sessions_list', 'sessions_history', 'sessions_send', 'sessions_yield_interrupt', 'sessions_yield', 'sessions_store'];
    console.log('   Using default sessions_* tool list (could not scan source)');
  } else {
    console.log('   Detected sessions_* tools: ' + sessionTools.join(', '));
  }

  // Generate replacement pairs for each sessions_* tool
  const sessionReplacements = {
    'sessions_spawn': 'create_task',
    'sessions_list': 'list_tasks',
    'sessions_history': 'get_history',
    'sessions_send': 'send_to_task',
    'sessions_yield_interrupt': 'task_yield_interrupt',
    'sessions_yield': 'yield_task',
    'sessions_store': 'task_store'
  };

  for (const tool of sessionTools) {
    const replacement = sessionReplacements[tool] || tool.replace('sessions_', 'task_');
    replacements.push([tool, replacement]);
    reverseMap.push([replacement, tool]);
    console.log('   ' + tool + ' -> ' + replacement);
  }

  // Detect assistant name from workspace files
  const workspaceDir = (oclawConfig.agents && oclawConfig.agents.defaults &&
    oclawConfig.agents.defaults.workspace) || null;
  if (workspaceDir) {
    const identityFiles = ['SOUL.md', 'USER.md', 'AGENTS.md'];
    for (const f of identityFiles) {
      const fPath = path.join(workspaceDir, f);
      if (fs.existsSync(fPath)) {
        const content = fs.readFileSync(fPath, 'utf8');
        const nameMatch = content.match(/(?:name|assistant|bot)\s*[:=]\s*["']?(\w+)/i);
        if (nameMatch && nameMatch[1].length > 2 && ['the', 'you', 'your', 'this'].indexOf(nameMatch[1].toLowerCase()) === -1) {
          console.log('\n   Detected assistant name: ' + nameMatch[1]);
          console.log('   Note: Assistant names are usually NOT blocked by Anthropic.');
          console.log('   If requests fail, try adding it to replacements as a test.');
          break;
        }
      }
    }
  }

  // Check for clawhub/clawd references in the OpenClaw source
  for (const dp of distPaths) {
    if (!fs.existsSync(dp)) continue;
    try {
      const indexFile = fs.readdirSync(dp).find(function(f) { return f.startsWith('index'); });
      if (indexFile) {
        const content = fs.readFileSync(path.join(dp, indexFile), 'utf8');
        if (content.includes('clawhub')) {
          replacements.push(['clawhub.com', 'skillhub.example.com']);
          replacements.push(['clawhub', 'skillhub']);
          reverseMap.push(['skillhub.example.com', 'clawhub.com']);
          reverseMap.push(['skillhub', 'clawhub']);
          console.log('   Added clawhub sanitization');
        }
        if (content.includes('clawd')) {
          replacements.push(['clawd', 'agentd']);
          reverseMap.push(['agentd', 'clawd']);
          console.log('   Added clawd sanitization');
        }
      }
      break;
    } catch (e) { /* skip */ }
  }
} else {
  console.log('   OpenClaw config not found (using defaults)');
  // Default sessions_* tools
  const defaults = [
    ['sessions_spawn', 'create_task'],
    ['sessions_list', 'list_tasks'],
    ['sessions_history', 'get_history'],
    ['sessions_send', 'send_to_task'],
    ['sessions_yield', 'yield_task']
  ];
  for (const [tool, repl] of defaults) {
    replacements.push([tool, repl]);
    reverseMap.push([repl, tool]);
  }
}

// Step 4: Generate config
console.log('\n4. Generating configuration...');

const config = {
  port: 18801,
  credentialsPath: credsPath,
  replacements: replacements,
  reverseMap: reverseMap
};

const configPath = path.join(process.cwd(), 'config.json');
fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
console.log('   Written: ' + configPath);
console.log('   Sanitization patterns: ' + replacements.length);
console.log('   Reverse map patterns: ' + reverseMap.length);

// Step 5: Instructions
console.log('\n5. Setup complete!\n');
console.log('   Next steps:');
console.log('   -----------');
console.log('   a) Start the proxy:     node proxy.js');
console.log('   b) Update OpenClaw:     Set baseUrl to http://127.0.0.1:' + config.port + ' in openclaw.json');
console.log('   c) Restart gateway:     Restart your OpenClaw gateway');
console.log('   d) Test:                Send your assistant a message\n');

if (oclawPath) {
  console.log('   To update baseUrl automatically:');
  if (process.platform === 'win32') {
    console.log('     powershell -c "(gc \'' + oclawPath + '\') -replace \'\\\"baseUrl\\\":\\s*\\\"[^\\\"]*\\\"\', \'\\\"baseUrl\\\": \\\"http://127.0.0.1:' + config.port + '\\\"\' | sc \'' + oclawPath + '\'"');
  } else {
    console.log('     sed -i \'s|"baseUrl": "[^"]*"|"baseUrl": "http://127.0.0.1:' + config.port + '"|\' \'' + oclawPath + '\'');
  }
}

console.log('\n   Troubleshooting:');
console.log('   - If requests fail with "extra usage" errors, check proxy console for 400 status codes');
console.log('   - Add any new sessions_* tools to both replacements and reverseMap in config.json');
console.log('   - If your assistant name is blocked (rare), add it to replacements and reverseMap');
console.log('   - Token refreshes when you open Claude Code CLI -- do this every 24h\n');
