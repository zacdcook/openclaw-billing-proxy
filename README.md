# OpenClaw Billing Proxy（中文版）

让 OpenClaw 使用 Claude Max/Pro 套餐内额度，而不走 Extra Usage 额外计费。

**零额外成本 · 完整 OpenClaw 功能 · 无需修改 OpenClaw 代码**

---

## 背景

2026 年 4 月 4 日，Anthropic 封锁了第三方工具（包括 OpenClaw）直接使用 Claude 订阅额度。所有非 Claude Code 的请求都被路由到 Extra Usage（按量付费）。

本项目通过在 OpenClaw 和 Anthropic API 之间插入一层代理，将请求伪装成 Claude Code 会话，从而继续使用套餐内额度。

---

## 原理

Anthropic 使用**四层检测机制**识别第三方工具：

| 层 | 检测方式 | 本项目的对策 |
|---|---|---|
| **L1: Billing Header** | 检查系统提示中的 `x-anthropic-billing-header` | 注入 84 字符的 Claude Code 计费标识（含 SHA256 动态哈希） |
| **L2: 关键词扫描** | 扫描请求体中的 ~30 个已知触发词 | 29 组全局查找替换（OpenClaw→OCPlatform 等） |
| **L3: 工具名指纹** | 分析工具名组合，匹配 OpenClaw 的 29 个工具 | 将所有工具重命名为 PascalCase Claude Code 风格 + 注入 5 个假 CC 工具 |
| **L4: 系统提示模板匹配** | 匹配 OpenClaw 特有的 ~28K 字符结构化段落 | 剥离配置段落，替换为 ~500 字符的自然语言 |

**检测是累积评分的**——必须同时应对所有四层。

---

## 架构

```
OpenClaw
  │
  │ /v1/messages (Anthropic 格式)
  ▼
┌────────────────────────────────────┐
│  Nginx (:443 TLS)                  │
│  按域名/路径路由                    │
└────────────┬───────────────────────┘
             │
             ▼
┌────────────────────────────────────┐
│  Billing Proxy (:18804)            │
│                                    │
│  出站处理（7 层）：                  │
│  1. 注入 Billing Header            │
│  2. 替换 OAuth Token               │
│  3. 关键词替换（29 组）             │
│  4. 工具名 PascalCase 重命名       │
│  5. 系统提示模板剥离               │
│  6. 工具描述删除                   │
│  7. 属性重命名 + 尾部消息剥离       │
│                                    │
│  入站处理：                         │
│  全部反向还原（工具名/属性/关键词） │
│  SSE 流式逐 chunk 处理             │
└────────────┬───────────────────────┘
             │
             ▼
       api.anthropic.com
       （走套餐内额度）
```

---

## 部署

### 前提条件

- Node.js 18+
- Claude Max 或 Pro 订阅
- Claude Code CLI 已安装并登录（`claude auth login`）
- OpenClaw 正在运行

### Step 1: 安装

```bash
git clone https://github.com/kongkong7777/openclaw-billing-proxy.git
cd openclaw-billing-proxy
```

### Step 2: 配置

运行自动配置：

```bash
node setup.js
```

或手动创建 `config.json`：

```json
{
  "port": 18804,
  "credentialsPath": "~/.claude/.credentials.json",
  "stripToolDescriptions": true,
  "injectCCStubs": true
}
```

### Step 3: 启动

```bash
node proxy.js
```

### Step 4: 配置 OpenClaw

在 OpenClaw 的 `openclaw.json` 中，将 `baseUrl` 改为代理地址：

```json
{
  "baseUrl": "http://127.0.0.1:18804"
}
```

重启 OpenClaw Gateway。

---

## Systemd 服务（推荐）

创建 `/etc/systemd/system/billing-proxy.service`：

```ini
[Unit]
Description=OpenClaw Billing Proxy
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/openclaw-billing-proxy
ExecStart=/usr/bin/node proxy.js
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable billing-proxy
sudo systemctl start billing-proxy
```

---

## 配合 CLIProxyAPI 使用

如果你同时使用 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 管理多个 AI 模型，推荐以下架构：

```
:443 (Nginx + TLS)
  ├─ /v1/messages*  → billing-proxy (:18804) → api.anthropic.com
  │                   （Claude 走套餐）
  ├─ /management*   → CLIProxyAPI (:18801)
  │                   （管理面板）
  └─ /* (其他 API)  → CLIProxyAPI (:18801)
                      （GPT/Gemini/Codex 等）
```

CLIProxyAPI 改为内部端口（如 18801），关闭 TLS（由 Nginx 处理）：

```yaml
# CLIProxyAPI config.yaml
port: 18801
tls:
  enable: false
```

---

## 工具名映射表

| OpenClaw 工具名 | 伪装后（CC 风格） |
|---|---|
| exec | Bash |
| process | BashSession |
| browser | BrowserControl |
| canvas | CanvasView |
| cron | Scheduler |
| message | SendMessage |
| tts | Speech |
| gateway | SystemCtl |
| agents_list | AgentList |
| create_task | TaskCreate |
| list_tasks | TaskList |
| get_history | TaskHistory |
| send_to_task | TaskSend |
| subagents | AgentControl |
| session_status | StatusCheck |
| web_search | WebSearch |
| web_fetch | WebFetch |
| pdf | PdfParse |
| memory_search | KnowledgeSearch |
| memory_get | KnowledgeGet |
| yield_task | TaskYield |
| task_store | TaskStore |
| task_yield_interrupt | TaskYieldInterrupt |

另外注入 5 个假 Claude Code 工具：`Glob`, `Grep`, `Agent`, `NotebookEdit`, `TodoRead`

---

## 关键词替换表

| 原始 | 替换为 |
|---|---|
| OpenClaw | OCPlatform |
| openclaw | ocplatform |
| sessions_spawn | create_task |
| sessions_list | list_tasks |
| sessions_history | get_history |
| sessions_send | send_to_task |
| sessions_yield | yield_task |
| sessions_store | task_store |
| HEARTBEAT_OK | HB_ACK |
| running inside | running on |

响应返回时**自动反向还原**，OpenClaw 无感知。

---

## 属性重命名

| 原始属性 | 替换为 |
|---|---|
| session_id | thread_id |
| conversation_id | thread_ref |

---

## Header 伪装

代理注入完整的 Claude Code HTTP Headers：

- `User-Agent: claude-cli/{version} (external, cli)`
- `anthropic-version: 2023-06-01`
- `anthropic-beta: claude-code-20250219,oauth-2025-04-20,...`
- 完整的 Stainless SDK headers（`x-stainless-*`）
- `x-claude-code-session-id: {uuid}`

---

## OAuth Token 管理

- 从 `~/.claude/.credentials.json` 读取 Claude Code 的 OAuth token
- 每次请求时刷新读取（支持 token 自动续期）
- macOS 支持从 Keychain 提取

---

## 故障排查

```bash
node troubleshoot.js
```

检查：credentials 文件、token 有效性、网络连通性、API 响应。

---

## 注意事项

- 这是非官方工具，Anthropic 可能随时更新检测机制
- 建议配合 `claude setup-token`（1 年有效期）使用，避免频繁 token 过期
- 如果出现 "extra usage" 错误，运行 `node troubleshoot.js` 排查

---

## 版本历史

| 版本 | 日期 | 变更 |
|---|---|---|
| v2.0 | 2026-04-08 | 四层检测对抗：工具名指纹绕过、系统模板剥离、描述删除、CC 工具注入 |
| v1.4 | 2026-04-06 | macOS Keychain 支持 |
| v1.3 | 2026-04-06 | 发现 HEARTBEAT_OK 触发词 |
| v1.2 | 2026-04-05 | 双向反向映射 |
| v1.1 | 2026-04-05 | 精简为 7 个已验证触发词 |
| v1.0 | 2026-04-05 | 基础凭证替换 + 18 个替换规则 |

---

## License

MIT

---

## 致谢

基于 [zacdcook/openclaw-billing-proxy](https://github.com/zacdcook/openclaw-billing-proxy) 项目。
