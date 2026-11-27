# Outsider — 端到端加密带外密钥传输与交接系统设计方案

> **定位**：面向 AI Agent、自动化脚本与无头服务器环境的**带外（Out-of-Band）人工审批密钥传输系统**。实现「密钥不落盘、不进 LLM 上下文、中转端零知识、移动端密码管理器一键填充」的安全密钥解锁与交接流程。

---

## 1. 系统总览与核心目标

### 1.1 解决的问题

当 AI Agent（通过 Skill 调用 CLI）或自动化程序需要临时使用某个敏感密钥（API Token、数据库密码、SSH 私钥口令、Docker 登录凭证等）时，传统方式面临三大痛点：

1. **落盘与常驻风险**：将密钥写入 `.env` 或配置文件，长期暴露在工作区或宿主机上。
2. **上下文泄漏风险**：若密钥通过标准输出返回给 AI Agent，明文会直接进入 LLM 对话历史、日志与遥测。
3. **传输与中转信任风险**：跨设备/跨网络人工送入密钥时，若经由公网中转服务，必须确保中转服务器既无法窥探明文，也无法伪造或调包申请端公钥。

### 1.2 三端架构

```mermaid
flowchart LR
    Agent["AI Agent / 宿主脚本"] -->|"调用 Skill CLI"| Req["申请端 Requester (Rust CLI)"]
    Req -->|"1. 生成临时 X25519 密钥对 (内存)\n2. 用长期 Ed25519 私钥对请求签名\n3. 提交请求并阻塞等待密文"| Relay["中转端 Relay (Go 单二进制 · 零知识)"]
    Relay -->|"4. 校验白名单公钥签名\n5. 推送通知 (含审批 URL)"| Notify["通知渠道 (Shoutrrr / Webhook)"]
    Notify -->|"6. 点击 URL 打开审批页"| App["批准端 Approver (内嵌浏览器 Web UI)"]
    PM["密码管理器 (Bitwarden / 1Password / Apple Passwords)"] -.->|"7. 自动识别表单并填充密钥"| App
    App -->|"8. 本地验签 (TOFU 已信任申请端公钥)\n9. 用申请端 X25519 公钥加密 (E2EE) 并上传密文"| Relay
    Relay -->|"10. 唤醒阻塞连接并一次性转发密文 (随即销毁)"| Req
    Req -->|"11. 内存解密并擦除私钥\n12. 通过 env/stdin/file/askpass 交接"| Target["目标使用程序 (docker / psql / ssh / sops...)"]
```

### 1.3 核心设计原则

- **中转端零知识与无数据库（Zero-Knowledge, DB-Free Relay）**：明文只在批准端浏览器和申请端 CLI 内存中存在；中转端仅通过静态配置文件（`relay.toml`）保存已信任申请端的公开 `Ed25519` 公钥列表，运行时会话与密文纯内存暂存、读后即焚、绝不落盘或记日志。
- **端到端身份真实性（Ed25519 + 浏览器 TOFU）**：每台申请端持有长期 `Ed25519` 身份密钥对每次解锁请求签名；批准端浏览器在首次审批点击「信任并继续」后，将申请端公钥持久化保存在浏览器本地，后续自动验签，防范中转端调包临时公钥或篡改申请上下文。
- **Agent 上下文隔离（LLM-Blind Handoff）**：申请端 CLI 仅通过 `outsider run` 作为父进程直接拉起目标程序并注入密钥，架构上不提供任何将明文打印到 `stdout` 的接口，同时默认对子进程输出执行实时脱敏（Redaction），确保密钥不进入 AI Agent 上下文。
- **密码管理器原生友好**：批准端统一采用基于密钥名 slug 的路径前缀 URL 与标准登录表单，严格适配 Bitwarden、1Password、Apple Passwords 等自动填充引擎的 URI 匹配与表单识别规则。
- **跨代理与弱网鲁棒**：阻塞等待采用 25 秒分片长轮询（Long Polling），避免被 Nginx / Cloudflare / 企业代理的空闲超时切断。

---

## 2. 端到端加密、身份验签与安全模型

### 2.1 唯一锁定密码学协议（Protocol `v1`）

遵循「不提供运行时算法协商、通过协议版本隐式绑定唯一套件」原则，`v1` 协议唯一锁定以下组合（现代浏览器 `window.crypto.subtle` 全部原生支持，零第三方 JS 依赖）：

| 层级 | 锁定算法 | 生命周期与职责 |
| :--- | :--- | :--- |
| **申请端身份签名** | `Ed25519`（RFC 8032） | **长期密钥对**（`~/.config/outsider/identity.key`，`0600`）：仅用于对每次解锁请求签名，证明 `pk_req` 与上下文确由信任申请端发出（同时替代静态 `client_token`） |
| **密钥交换（ECDH）** | `X25519`（RFC 7748） | **一次性临时密钥对**（纯内存生成、解密即擦除）：公钥固定 32 字节（Base64URL 为 43 字符）；严格拒绝全零共享密钥（`!shared.was_contributory()`） |
| **密钥派生（KDF）** | `HKDF-SHA256`（RFC 5869） | 从共享秘密派生 32 字节一次性对称加密密钥，并将双方公钥绑定进 `info`（Transcript Binding） |
| **认证加密（AEAD）** | `AES-256-GCM` | 12 字节随机 Nonce + 16 字节认证标签；借助 `AAD` 绑定会话与上下文摘要 |

> **浏览器运行时要求**：批准端依赖现代浏览器原生 WebCrypto `X25519` 与 `Ed25519` 支持（Safari 17+ / iOS 17+、Chrome 133+、Firefox 130+），页面初始化时检测 `crypto.subtle` 能力并在极老旧环境中给出明确提示。

### 2.2 上下文哈希与请求身份签名

为彻底避免 Rust / Go / JS 三端在 JSON 规范化上的差异坑，`context_hash` 采用**长度前缀二进制编码**（三端各 ~10 行代码，字节级零歧义）：

```text
encode_str(s) = uint32_be(len(utf8(s))) || utf8(s)

context_bytes = "outsider-ctx-v1" || 0x00
                || encode_str(name)
                || encode_str(reason)
                || encode_str(command_summary)

context_hash  = SHA-256(context_bytes)    // 32B
```

随后申请端使用长期 `Ed25519` 私钥 `id_sk` 对本次请求的核心字段签名：

```text
sign_input = "outsider-req-v1" || 0x00
             || id_pk (32B)
             || pk_req (32B)
             || context_hash (32B)
             || request_ts_unix_be64 (8B)
             || ttl_secs_be32 (4B)
             || request_nonce (16B)

sig = Ed25519.Sign(id_sk, sign_input)
```

- **中转端验签（防陌生人刷通知 DoS）**：检查 `id_pk` 在 `relay.toml` 的 `trusted_clients` 白名单中、`|now - request_ts| <= 30s`、`request_nonce` 未在 60s 去重窗口内重放，并验证 `Ed25519.Verify(id_pk, sign_input, sig)`。
- **批准端浏览器验签（防中转端篡改 `pk_req` 与上下文）**：
  - 浏览器本地按上述规则重算 `context_hash`，检查请求未过期，并用 `id_pk` 验证 `sig`。
  - **TOFU 信任原则**：浏览器不自动信任中转端报上来的 `id_pk`。首次遇到某台申请端公钥时，页面顶部展示设备名与 8 位公钥指纹：
    ```text
    id_fp = Base32(SHA-256("outsider-id-fp-v1" || id_pk)[0..5])  // 例：7K4M-9P2X
    ```
    点击「信任并继续」后将该公钥锁死在浏览器本地存储，后续请求自动以本地已存公钥校验（若同名设备公钥发生突变则红框阻断告警）。

### 2.3 加密与 AAD 上下文绑定

批准端验签通过后，在浏览器端通过原生 `window.crypto.subtle` 执行端到端加密：

1. 生成临时 `X25519` 密钥对 `(sk_epk, epk)`。
2. 计算共享密钥：`ss = X25519(sk_epk, pk_req)`（32 字节）。
3. 派生一次性对称密钥：
   ```text
   salt     = UTF8(session_id)
   info     = "outsider-v1-aead-key" || pk_req (32B) || epk (32B)
   aead_key = HKDF-SHA256(ikm = ss, salt = salt, info = info, len = 32)
   ```
4. 构造防篡改关联数据（AAD）：
   ```text
   AAD = "outsider-v1" || 0x00 || session_id || 0x00 || context_hash
   ```
5. 生成 12 字节密码学安全随机数 `nonce = CSPRNG(12)`，执行认证加密：
   ```text
   ciphertext = AES-256-GCM.Seal(aead_key, nonce, plaintext_json, AAD)
   ```
6. 仅上传 `(v: 1, epk, nonce, ciphertext)` 至中转端，随即释放 `sk_epk`、`ss`、`aead_key` 与明文。
7. 申请端收到密文后，使用**本地原始 `sk_req` 与本地 `context_hash`** 构造 AAD 解密；若任何字段被篡改，GCM 认证标签校验失败，立即丢弃。

### 2.4 明文载荷结构（加密前）

浏览器端加密的明文为极简单密钥 JSON（支持单行 Token/密码与多行私钥/证书）：

```json
{
  "v": 1,
  "secret": "s3cr3t-p@ssw0rd"
}
```

### 2.5 完整端到端时序

```mermaid
sequenceDiagram
    autonumber
    participant CLI as 申请端 (Rust CLI)
    participant Relay as 中转端 (Go Relay)
    participant Notify as 通知渠道 (Shoutrrr / Webhook)
    participant Web as 批准端 (Browser + Bitwarden)
    participant Target as 目标程序

    CLI->>CLI: 内存生成临时 X25519 密钥对 (sk_req, pk_req)
    CLI->>CLI: 计算 context_hash, 用长期 Ed25519 私钥签名 sig
    CLI->>Relay: POST /v1/requests (id_pk, pk_req, context, ts, ttl, nonce, sig)
    Relay->>Relay: 核对 relay.toml 白名单 + 防重放 + Ed25519 验签
    Relay->>Relay: 创建内存 Session (PENDING), 生成 session_id / wait_token / approve_token
    Relay->>Notify: 发送通知 (设备名 + 上下文 + 审批 URL)
    Relay-->>CLI: 201 Created (session_id, wait_token)

    loop 分片长轮询 (每次 25s, 直至终态或 TTL 超时)
        CLI->>Relay: GET /v1/requests/{session_id}/wait (Bearer wait_token)
        Note over Relay: 在 Go channel + request context 上阻塞挂起
    end

    Notify->>Web: 用户点击审批 URL (/approve/<name_slug>/<approve_token>, 可经 Cloudflare Access 验权)
    Web->>Relay: GET /v1/approve/{approve_token} (拉取签名请求包与公开 session_id)
    Relay-->>Web: 返回 session_id, id_pk, client_name, pk_req, context, ts, ttl, nonce, sig, expires_at
    Web->>Web: 本地重算 context_hash + WebCrypto Ed25519 验签 (防篡改 pk_req 与上下文)
    Web->>Web: 查浏览器本地信任表 (TOFU: 已信任直接放行 / 首次点「信任并继续」保存 / 公钥突变红警阻断)
    Web->>Web: 渲染登录表单, Bitwarden 匹配路径前缀 URL 并自动填充密钥
    Web->>Web: 点击「加密并发送」: 生成临时 X25519 epk, HKDF 派生密钥, AES-256-GCM 加密
    Web->>Relay: POST /v1/approve/{approve_token} (v=1, epk, nonce, ciphertext)
    Web->>Web: 清空表单输入与内存变量
    Relay->>Relay: 校验一次性状态 -> 存入内存并 close(done) 唤醒等待方
    Relay-->>Web: 200 OK (已发送)

    Relay-->>CLI: 唤醒长轮询, 返回加密信封 (同时从内存彻底删除密文!)
    CLI->>CLI: 用 sk_req + 本地 AAD 解密; 立即 zeroize(sk_req)
    CLI->>Target: 按指定模式注入密钥并拉起目标程序 (env/stdin/file/askpass/arg)
    Target-->>CLI: 进程退出 (exit code)
    CLI->>CLI: 清理临时文件, zeroize(secret), 透传 exit code
```

### 2.6 威胁模型与信任边界

| 威胁场景 | 防御机制 | 残余风险与说明 |
| :--- | :--- | :--- |
| **中转端被动窃听（Honest-but-Curious）** | E2EE（`sk_req` 永不离开申请端内存），密文阅后即焚不落盘 | 完全防御 |
| **中转端篡改请求上下文（Bait-and-Switch）** | 申请端 `Ed25519` 签名覆盖 `context_hash` + AEAD `AAD` 绑定 `context_hash` | 完全防御（审批端验签即阻断，申请端解密亦双保险失败） |
| **中转端主动 MITM（替换 `pk_req`）** | `Ed25519` 签名绑定 `pk_req`，批准端以浏览器本地已存的 `id_pk`（TOFU）验签，同名设备公钥突变触发红警阻断 | 审批页内嵌于自建中转单二进制，需信任自己维护的中转实例本身未被攻破 |
| **不可信 Notifier（窃听元数据 / 抢先提交假密文 / 钓鱼）** | 1. **防伪造提交**：推荐前置 **Cloudflare Access（Email OTP）** 保护 `/approve/*` 与 `/v1/approve/*`；<br>2. **防元数据泄露**：可开启 `redact_notification_metadata = true` 仅推送审批链接；<br>3. **防钓鱼**：Bitwarden 按真实域名+路径前缀匹配，假域名不会弹出自动填充 | 不可信 Notifier 仍可能扣留或延迟消息（纯可用性 DoS） |
| **恶意第三方刷通知轰炸（DoS）** | 中转端校验 `relay.toml` 中的 `trusted_clients` Ed25519 签名 + 时间戳/nonce 防重放 + 单设备并发与频率限制 | 有效缓解 |
| **AI Agent 偷窥或日志泄露明文** | 不提供明文 `stdout` 输出接口；`outsider run` 直接托管子进程；`SKILL.md` 规范约束；默认 `--redact` 脱敏子进程输出 | 无法防御目标程序主动把密钥发往外网（需靠审批者审核通知中的命令摘要） |

---

## 3. 申请端设计（Rust CLI + Agent Skill）

### 3.1 技术选型与内存安全

- **语言**：Rust（静态链接单文件二进制，支持 `linux-x86_64`、`linux-aarch64`、`macos-aarch64`、`macos-x86_64`、`windows-x86_64`）。
- **内存卫生**：
  - 所有私钥（`id_sk` 与临时 `sk_req`）、共享密钥、明文缓冲区统一使用 `zeroize::Zeroizing<T>` 包装，Drop 时强制清零内存。
  - 注册 `SIGINT` / `SIGTERM` 信号处理，确保异常中断时也会清理临时文件并通知中转端取消请求（`DELETE /v1/requests/{id}`）。

### 3.2 命令行接口（CLI UX）

主命令：`outsider`

```bash
# 首次初始化：生成长期 Ed25519 身份密钥与 config.toml，
# 并直接输出可粘贴进 relay.toml 的 [[trusted_clients]] 片段与 8 位公钥指纹
outsider init --relay https://relay.example.com --name macbook-pro

# 查看当前设备公钥、TOML 片段与指纹
outsider id

# 核心子命令：申请密钥并直接拉起目标程序
# --name 既用于展示，也会自动规范化为审批 URL 路径段（如 DOCKER_PAT -> /approve/docker-pat/...）
outsider run \
  --name "DOCKER_PAT" \
  --reason "Push release image v1.2.0" \
  --timeout 120 \
  --stdin \
  -- docker login -u myuser --password-stdin

# 环境变量注入示例（如数据库连接密码）
outsider run \
  --name "prod-db" \
  --reason "Run database migration" \
  --env PGPASSWORD \
  -- psql -h db.prod -U admin -d app -f migrate.sql

# 多变量 .env 推荐组合（Outsider + SOPS）：本地存加密的 .env.enc，远程仅审批提供单行 SOPS_AGE_KEY
outsider run \
  --name "myproject-sops" \
  --reason "Run staging integration tests" \
  --env SOPS_AGE_KEY \
  -- sops exec-env .env.enc "pytest tests/integration/"

# 检查与中转端连通性、签名白名单及本地配置状态
outsider doctor
```

> **等待期终端反馈（`stderr`）**：阻塞等待审批期间，CLI 仅向 `stderr` 打印简洁状态（例如 `[outsider] Waiting for approval: prod-db (120s) | Device FP: 7K4M-9P2X`），绝不污染 `stdout`。

### 3.3 密钥交接方式（Handoff Modes）

聚焦高频实用场景，`outsider run` 提供 **5 种密钥交接模式**（架构上不提供将明文输出到 `stdout` 的模式）：

| 模式 | CLI 参数 | 底层实现机制 | 典型适用程序 | 安全性 |
| :--- | :--- | :--- | :--- | :---: |
| **1. 环境变量** | `--env VAR` <br> `--env VAR="prefix_{{secret}}"` | 直接通过 `Command::env()` 注入子进程环境块，不污染父 Shell 环境 | `aws`、`curl`、`python`、`psql (PGPASSWORD)`、`gh (GH_TOKEN)`、`sops (SOPS_AGE_KEY)`、`terraform`、绝大多数 SDK | 高 |
| **2. 标准输入** | `--stdin` <br> `--stdin-template "{{secret}}\n"` <br> `--no-stdin-newline` | 创建匿名管道写入明文后立即关闭写端，绑定为子进程 `stdin` | `docker login --password-stdin`、`sudo -S`、`rclone`、`openssl -pass stdin` | 极高 |
| **3. 临时内存文件** | `--file` <br> `--file-env KEY_FILE` | 优先在 `/dev/shm`（Linux 内存盘）或系统临时目录创建 `0600` 随机临时文件，将路径注入参数占位符 `{{file}}` 或环境变量；子进程退出或收到信号时覆写清零并删除 | `ssh -i {{file}}`、`kubectl --kubeconfig {{file}}`、`ansible-vault --vault-password-file {{file}}`、证书/JSON 凭证文件 | 高 |
| **4. ASKPASS 代理** | `--askpass` | 自动设置 `SSH_ASKPASS` / `SUDO_ASKPASS` / `GIT_ASKPASS` 指向 `outsider` 自身内部的 `askpass-helper`，通过父子进程间私有一次性 Unix Socket / 管道传递密钥，无需暴露给环境或屏幕 | `ssh`、`ssh-add`、`git push/fetch`、`sudo -A` | 极高 |
| **5. 命令行参数替换** | `--arg-placeholder "{{secret}}"` | 将目标命令 `argv` 中的占位符替换为明文 | 仅接受 `--token <val>` / `-p<val>` 的遗留 CLI | 中（同机用户可能经 `ps` 看到，CLI 会打印警告） |

> **子进程输出脱敏（`--redact`，默认开启）**：
> `outsider run` 代理子进程的 `stdout` 和 `stderr`，使用流式滑动窗口匹配明文（及其 Base64 / URL-encoded 变体），在转发给调用方（AI Agent）前自动替换为 `[REDACTED:OUTSIDER]`，防止目标命令报错或开启 debug 时意外把密钥打印回 LLM 上下文。

### 3.4 退出码约定

当目标程序正常拉起并退出时，直接透传目标程序的退出码；仅当 `outsider` 自身阶段失败时返回保留退出码：

- `0`：目标程序成功执行（或透传目标程序退出码）
- `100`：配置错误或参数无效
- `101`：无法连接中转端 / 设备公钥未授权或验签失败
- `102`：等待超时（Expired）
- `103`：密文解密或 AAD 完整性校验失败（疑似篡改）

### 3.5 本地配置结构

默认目录：`~/.config/outsider/`
- `identity.key`：申请端 `Ed25519` 长期私钥（强制校验权限 `0600`）
- `config.toml`：运行配置（支持环境变量 `OUTSIDER_RELAY_URL`、`OUTSIDER_IDENTITY_KEY` 覆盖）：

```toml
relay_url = "https://relay.example.com"
identity_key_path = "~/.config/outsider/identity.key"
default_timeout_secs = 120
default_redact = true
```

### 3.6 Agent Skill 分发结构

按照「二进制 + `SKILL.md` 作为一个 Skill 分发」的要求，通过根目录 `scripts/package-skill.sh` 从 `docs/SKILL.md`、`docs/references/` 与编译产物组装如下分发包：

```text
outsider/
├── SKILL.md                    # Agent 指令规范（触发场景、命令模板、安全红线）
├── bin/
│   └── outsider                # 平台原生静态二进制（单平台分发包）
│   # 或多架构通用包：
│   # ├── outsider              # 极简 POSIX wrapper，按 uname -s/-m 分发
│   # ├── outsider-linux-x86_64
│   # ├── outsider-linux-aarch64
│   # └── outsider-darwin-aarch64
└── references/
    └── handoff-examples.md     # 常见工具（sops/gh/docker/ssh/psql/curl/gpg）的交接命令速查
```

**`SKILL.md` 必须包含的核心规则**：
1. **何时触发**：当任务需要敏感密钥/凭证、且宿主机环境变量或配置文件中不存在时，主动调用 `bin/outsider run`；若项目采用 SOPS 加密的 `.env.enc` 管理多变量敏感配置，优先使用 `--env SOPS_AGE_KEY -- sops exec-env .env.enc "..."`（或 `sops exec-file`）组合。
2. **禁止泄露红线**：
   - 严禁尝试让目标命令 `echo` / `printenv` 或写文件来转存/打印密钥；优先使用不写磁盘的运行模式（如 `--env GH_TOKEN -- gh ...`，避免 `gh auth login` 等持久化写盘命令）。
   - 严禁使用 `--arg-placeholder`（除非目标工具完全不支持 `env`/`stdin`/`file`/`askpass`）。
   - 交接方式优先级严格遵循：`stdin` / `askpass` > `env` > `file` > `arg`。
3. **提供清晰审批上下文**：必须填写有意义的简短 ASCII `--name`（同时作为 Bitwarden URL 路径匹配标识，如 `github-pat`、`prod-db`、`myproject-sops`）和 `--reason`（向用户清晰解释为什么需要该密钥以及将执行什么操作）。
4. **超时处理**：若返回退出码 `102`（等待超时），向用户说明未收到批准并询问是否需要重新发起，**严禁自动循环重试骚扰用户**。

---

## 4. 中转端设计（Go Zero-Knowledge Relay）

### 4.1 技术选型与极简配置（无数据库）

- **单静态二进制：Go（标准库 `net/http` + `embed.FS` + `crypto/ed25519` + 官方 `shoutrrr`）**
  - 中转端不涉及 X25519 / AES-GCM 加解密，核心职责仅为验签、内存路由阻塞与通知分发；采用 Go 原生 `import` 官方 `shoutrrr` 库开箱支持 20+ 通知渠道，`CGO_ENABLED=0` 极速静态编译，内存占用 ~10MB。
  - 使用 `embed.FS` 将 `web/` 静态审批页直接内嵌进单二进制，可部署在任意 VPS、家庭服务器（搭配 Cloudflare Tunnel / Caddy 自动 HTTPS）或 Docker 容器中。
  - 与 Rust CLI、前端 JS 共享一份 `protocol/test-vectors.json` 跨语言测试向量，确保 `context_hash` 与 `Ed25519` 签名字节级一致。
- **无需数据库 + `SIGHUP` 热重载**：
  - 已信任的**申请端** `Ed25519` 公钥白名单直接写在 `relay.toml` 中（类似 SSH `authorized_keys`）；**无需登记任何审批端（手机/浏览器）设备**。
  - 支持 `SIGHUP` 热重载 `relay.toml`（或直接毫秒级重启进程），同时支持 `OUTSIDER_RELAY_*` 环境变量覆盖。

**最小可用配置（约 10 行即可运行）**：

```toml
public_base_url = "https://relay.example.com"

# 通知渠道统一使用 [[notifiers]]，支持 type = "shoutrrr" 或 type = "webhook"（可配多个并行推送）
[[notifiers]]
type = "shoutrrr"
url = "telegram://123456:ABC-DEF...@telegram?chats=987654321"

# 仅需保存申请端的公开 Ed25519 公钥（可直接粘贴 outsider init 的输出）
[[trusted_clients]]
name = "macbook-pro"
public_key = "<base64url-32-byte-ed25519-pubkey>"
```

**可选调优项（均有默认值，无需手写）**：

```toml
listen_addr = "127.0.0.1:8080"
redact_notification_metadata = false   # 设为 true 时通知仅发审批链接，隐藏密钥名/理由/命令摘要
default_ttl_secs = 120
max_ttl_secs = 300
grace_ttl_secs = 30
max_pending_per_client = 3
rate_limit_per_min = 10
```

### 4.2 会话状态机

无需显式拒绝操作——不批准的请求直接忽略，等待 TTL 到期自动过期销毁即可：

```mermaid
stateDiagram-v2
    [*] --> PENDING: POST /v1/requests (白名单验签通过 -> 生成 session + 发通知)
    PENDING --> APPROVED: POST /v1/approve/{approve_token} (批准端提交密文)
    PENDING --> CANCELLED: DELETE /v1/requests/{id} (申请端 Ctrl+C 取消)
    PENDING --> EXPIRED: 超过 TTL (默认 120s)
    APPROVED --> CONSUMED: 申请端成功取走密文 (立即从内存擦除密文!)
    APPROVED --> EXPIRED: 密文未被及时取走 (超过 grace TTL 30s)
    CONSUMED --> [*]
    CANCELLED --> [*]
    EXPIRED --> [*]
```

### 4.3 阻塞等待机制（分片长轮询）

统一采用**服务端 Go channel 唤醒 + 客户端 25 秒分片长轮询**（同时兼容公网 Nginx/Cloudflare 代理超时与局域网毫秒级响应）：

- 中转端为每个 `Session` 维护一个 `done chan struct{}`（及受 `sync.Mutex` 保护的状态与密文字段）。
- `POST /v1/requests` 创建会话并推送通知，立即返回 `session_id` + `wait_token`。
- `GET /v1/requests/{session_id}/wait?timeout=25` 在服务端通过 `select` 阻塞等待 `<-s.done`、25 秒 `time.NewTimer` 或 `<-r.Context().Done()`。
- 一旦批准端提交密文，中转端调用 `close(s.done)` **毫秒级**唤醒阻塞连接，原子取走密文并清零内存副本返回；若 25s 仍为 `PENDING`，返回 `202 Accepted`（`{"status": "pending", "remaining_secs": 95}`），CLI 无缝发起下一轮长轮询。

### 4.4 REST API 规范

所有接口强制 HTTPS，响应头统一包含 `Cache-Control: no-store`、`Referrer-Policy: no-referrer`。

| 端点 | 方法 | 鉴权 | 说明 |
| :--- | :--- | :--- | :--- |
| `/v1/requests` | `POST` | `Ed25519` 请求签名（`id_pk` 须在 `trusted_clients`） | 申请端创建解锁请求，验签并防重放后触发通知推送，返回 `session_id`、`wait_token`、`expires_at` |
| `/v1/requests/{id}/wait` | `GET` | `Authorization: Bearer <wait_token>` | 申请端阻塞等待结果；若为 `APPROVED`，原子 `take()` 密文返回并置为 `CONSUMED` |
| `/v1/requests/{id}` | `DELETE` | `Authorization: Bearer <wait_token>` | 申请端主动取消（如 Ctrl+C），立即清理内存会话 |
| `/v1/approve/{approve_token}` | `GET` | 路径高熵能力令牌（可前置 Cloudflare Access） | 批准端页面拉取原始签名请求包与公开 `session_id`（`v`、`session_id`、`id_pk`、`client_name`、`pk_req`、`context`、`request_ts`、`ttl_secs`、`request_nonce`、`sig`、`expires_at`、`status`） |
| `/v1/approve/{approve_token}` | `POST` | 路径高熵能力令牌（可前置 Cloudflare Access） | 批准端提交加密信封（`v`、`epk`、`nonce`、`ciphertext`），唤醒申请端 |
| `/approve/{name_slug}/{approve_token}` | `GET` | 路径高熵能力令牌（可前置 Cloudflare Access） | 下发内嵌的静态审批 HTML 页面 |
| `/healthz` | `GET` | 无 | 健康检查 |

#### 核心数据结构示例

**创建请求（`POST /v1/requests`）**：
```json
{
  "v": 1,
  "id_pk": "<base64url-encoded-32-byte-ed25519-public-key>",
  "pk_req": "<base64url-encoded-32-byte-x25519-public-key>",
  "request_ts": 1795693200,
  "ttl_secs": 120,
  "request_nonce": "<base64url-encoded-16-byte-random-nonce>",
  "context": {
    "name": "prod-db",
    "reason": "Run database migration",
    "command_summary": "psql -h db.prod -U admin -d app -f migrate.sql"
  },
  "sig": "<base64url-encoded-64-byte-ed25519-signature>"
}
```

**批准提交（`POST /v1/approve/{approve_token}`）**：
```json
{
  "v": 1,
  "epk": "<base64url-encoded-32-byte-x25519-ephemeral-public-key>",
  "nonce": "<base64url-encoded-12-byte-nonce>",
  "ciphertext": "<base64url-encoded-aes256gcm-ciphertext-with-tag>"
}
```

### 4.5 统一通知抽象（`shoutrrr` + `webhook`）

中转端定义极简 Go 单向推送接口：

```go
type Notifier interface {
    NotifyRequest(ctx context.Context, payload NotifyPayload) error
}
```

配置层仅暴露 **2 种标准 `type`**，不做任何特定平台特化逻辑：

1. **`type = "shoutrrr"`**：直接调用官方 Go `shoutrrr` 库发送通知，一行标准 URL 开箱支持 Telegram、Bark、ntfy、Pushover、Gotify、Slack、Discord、Teams、Matrix、SMTP 等 20+ 渠道。
2. **`type = "webhook"`**：可模板化通用 HTTP 通知，支持自定义 `url`、`method`（默认 `POST`）、`headers`、`body_template`（占位变量：`{{url}}`、`{{device}}`、`{{secret_name}}`、`{{reason}}`、`{{command}}`、`{{ttl_secs}}`），零代码接入飞书、钉钉、企业微信或任何私有接口：

```toml
[[notifiers]]
type = "shoutrrr"
url = "telegram://123456:ABC-DEF...@telegram?chats=987654321"

[[notifiers]]
type = "webhook"
url = "https://open.feishu.cn/open-apis/bot/v2/hook/xxx"
headers = { Content-Type = "application/json" }
body_template = '{"msg_type":"text","content":{"text":"[Outsider] {{device}} 请求 {{secret_name}}\n原因: {{reason}}\n审批: {{url}}"}}'
```

- **精简通知模式（`redact_notification_metadata = true`）**：开启后发给第三方 Notifier 的内容仅包含审批 URL（隐藏密钥名、申请理由与命令摘要），防止第三方推送平台窥探敏感元数据。

### 4.6 安全防护、限流与 Cloudflare Access 适配

- **推荐网关层保护（Cloudflare Zero Trust Access）**：
  - 路由天然按角色分离，可直接用 Cloudflare Access（Email OTP）零代码保护批准端：
    - **加 Email OTP 保护**：`/approve/*` 和 `/v1/approve/*`
    - **设为 Bypass 放行**：`/v1/requests` 和 `/v1/requests/*`（已由申请端 `Ed25519` 签名鉴权）
  - 开启后，即使 Notifier 完全不可信或审批链接意外泄露，未通过本人邮箱验证者也无法拉取或伪造提交密文。
- **防通知轰炸与防重放**：按申请端 `id_pk` 限制最大同时 `PENDING` 会话数（默认 3）与滑动窗口速率限制（如每分钟最多 10 次）；内存维护 60 秒 `seen_nonces` 集合拦截重放请求。
- **零日志泄露**：HTTP Access Log 强制脱敏 URL 路径中的 `approve_token` 与 `session_id`，且绝不记录请求体与响应体。
- **定时清道夫（Reaper）**：后台 goroutine 每 5 秒扫描过期会话与过期 nonce 并清零释放。

---

## 5. 批准端设计（内嵌 Web UI + 密码管理器自动填充）

批准端是一个由 Go `embed.FS` 直接内嵌进中转端的**零第三方脚本依赖极简单页应用（SPA）**，核心聚焦「**浏览器端 TOFU 公钥验签**」与「**让 Bitwarden / 1Password / Apple Passwords 无缝弹出并精准匹配密钥**」。首期采用**语义化原生 HTML + 极低 CSS（无视觉设计，仅保基本可读与布局）**，后续再独立做视觉美化。

### 5.1 浏览器端 TOFU（首次信任并本地保存申请端公钥）

审批端不从中转端自动拉取信任列表，浏览器依赖本地 `localStorage`（`outsider_trusted_clients_v1`）做本地信任判定：

1. **前置密码学验签**：打开页面后，前端立即按长度前缀二进制编码重算 `context_hash`，并用 `window.crypto.subtle`（原生 `Ed25519`）验证 `sig`。验签失败直接阻断并禁用提交按钮。
2. **三种 TOFU 信任状态（同屏无跳转）**：
   - **已信任设备**（`id_pk` 已存在于浏览器本地白名单）：显示 `✓ 已验证信任设备：<设备名>`，直接启用「加密并发送」按钮。
   - **首次遇到的新设备**（本地未保存此 `id_pk`）：在表单上方内联显示首次信任提示，展示设备名与 8 位公钥指纹（如 `7K4M-9P2X`），提供一键 **「信任并继续」** 按钮（点击即保存 `(id_pk, 设备名, 首次信任时间)` 到浏览器本地并原地解锁下方发送按钮）。
   - **同名设备公钥突变（高危告警）**：本地已保存名为 `devbox-01` 的公钥 `id_pk_old`，而本次请求的设备名仍为 `devbox-01` 但公钥变为 `id_pk_new`——页面弹出明确告警并锁死提交按钮，必须由用户主动在设备管理列表移除旧公钥后才可重新信任。
3. **本地设备管理**：使用原生 `<details>` 折叠面板，支持查看与移除浏览器本地已信任的申请端公钥（纯本地操作）。

> **移动端浏览器存储提示**：`localStorage` 按浏览器 Origin 隔离（例如 iOS 上应用内置 `SFSafariViewController` 与外部 Safari 存储独立，但各自内部多次打开均持久共享）。建议平时固定用同一种方式打开审批链接，首次信任一次即可长期免核对。

### 5.2 密码管理器路径前缀 URI 匹配设计

统一采用基于密钥名 slug 与高熵能力令牌的极简路径（无 Query 参数、零额外 DNS 配置）：

```text
https://relay.example.com/approve/<name_slug>/<approve_token>
```

例如：`https://relay.example.com/approve/github-pat/a9f3k8m2x7...`

- **Bitwarden 精准匹配**：对应条目的 URI 设为 `https://relay.example.com/approve/github-pat/`，并将匹配规则设为 **「开头为（Starts with）」**，打开页面即可精准只弹出该密钥。
- **兜底便捷体验**：
  - 审批页顶部提供 `name` 的**一键复制搜索词**按钮，方便直接复用 Vault 中已有的网站条目。
  - 输入框旁提供 **「粘贴」** 按钮与 **单行/多行切换**（`<input type="password">` ↔ `<textarea>`），方便从 Bitwarden 安全笔记或剪贴板一键填入多行私钥。

> **能力路径 `/approve/<name_slug>/<approve_token>` 的优势**：
> 1. `pk_req` 已由 `Ed25519` 签名与浏览器 TOFU 保护，无需放入 URL；
> 2. 路径天然 100% 穿越 Cloudflare Access 邮箱验证重定向，首次验权一步直达；
> 3. 两端权限严格隔离（批准端仅有 `approve_token`，公开 `session_id` 由 `GET /v1/approve/{approve_token}` 下发供计算 `AAD`）；前端加载后调用 `history.replaceState` 擦除地址栏路径中的令牌。

### 5.3 表单工程化、极简无设计与前端安全加固

1. **真实 `<form>` 结构 + 阻断原生提交**：
   ```html
   <form id="secret-form" method="post" action="javascript:void(0)" autocomplete="on">
     <!-- 保留只读 username 输入框并填入 name，显著提高 Bitwarden / iOS AutoFill / 1Password
          识别登录表单并自动填充密码的成功率；该字段不打包进密文 -->
     <input
       id="username"
       name="username"
       type="text"
       autocomplete="username"
       value="prod-db"
       readonly
     />

     <!-- 必须使用 current-password，绝不能使用 new-password（后者会触发密码生成器） -->
     <input
       id="secret"
       name="password"
       type="password"
       autocomplete="current-password"
       autofocus
       required
     />

     <!-- 默认 disabled，待 Ed25519 验签与 TOFU 信任确认通过后才启用 -->
     <button id="submit-btn" type="submit" disabled>加密并发送</button>
   </form>
   ```
2. **严格的 Content-Security-Policy（CSP）**：
   ```http
   Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'
   ```
   其中 **`form-action 'none'`** 从浏览器内核层面杜绝任何原生 HTML 表单提交，确保明文绝不可能以明文 POST 离开浏览器。
3. **极简交互与防误触（低 CSS 无设计原则）**：
   - 使用语义化原生 HTML 元素（`<main>`、`<dl>`、`<form>`、`<details>`、`<pre>`）+ 极少量基础排版 CSS（居中最大宽度、合理间距、警示文字颜色），不做卡片动效或复杂视觉设计，后续再叠加主题样式。
   - 清晰展示：**已验签设备状态**、**密钥名称**、**申请理由**、**目标命令摘要**、**剩余倒计时（秒）**。
   - 一旦 TTL 过期、已发送或申请端主动取消，表单控件置为 `disabled` 并提示原因；不批准的请求直接关闭页面等待 TTL 自动过期即可。
   - 点击「加密并发送」后：执行 WebCrypto 加密 -> 发送密文 -> 立即清空输入框与 JS 变量 -> 显示「已加密发送，可安全关闭此页面」。

---

## 6. 项目代码架构（Monorepo）

采用多语言 Monorepo 组织：**Rust 申请端 CLI** + **Go 中转端 Relay（内嵌 Web 批准端）** + **跨语言协议测试向量** + **文档与 Skill 打包脚本**：

```text
Outsider/
├── .gitignore                         # 忽略本地运行时注入的 /skills/ 及构建产物
├── go.mod                             # Go 模块根（供 relay 零拷贝 embed web/）
├── pyproject.toml                     # 统一 uvx 包（同时提供 outsider 与 outsider-relay）
├── docs/
│   ├── design.md                      # 本文档
│   ├── SKILL.md                       # Agent Skill 指令规范模板
│   └── references/
│       └── handoff-examples.md        # 常见工具交接命令速查
├── scripts/
│   ├── package-skill.sh               # 交叉编译并从 docs/ 组装 outsider-skill-<target>.tar.gz
│   ├── pep517_backend.py              # 零依赖 PEP 517 后端（将原生二进制打入 .data/scripts/）
│   └── build-wheels.sh                # 构建独立 outsider 与 outsider-relay 原生 wheel
├── protocol/
│   └── test-vectors.json              # Rust / Go / WebCrypto JS 三端共享一致性测试向量
├── cli/                               # 申请端 Rust 项目 (outsider)
│   ├── pyproject.toml                 # 独立 uvx 包: outsider（仅需 Rust）
│   ├── _pep517.py
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                    # clap 参数解析与子命令分发 (init/id/doctor/run)
│       ├── proto/                     # 协议实现模块
│       │   ├── mod.rs
│       │   ├── crypto.rs              # X25519 + HKDF-SHA256 + AES-256-GCM + Zeroize
│       │   ├── identity.rs            # Ed25519 签名/验签、8 位公钥指纹
│       │   ├── context.rs             # 定长前缀二进制 context_hash、name slug
│       │   └── api.rs                 # Request/Response/Envelope/Status DTO
│       ├── config.rs                  # config.toml 与 identity.key (0600) 加载与校验
│       ├── client.rs                  # 请求签名、HTTPS 客户端、分片长轮询、信号取消
│       ├── handoff/                   # 密钥交接实现模块
│       │   ├── mod.rs
│       │   ├── env.rs
│       │   ├── stdin.rs
│       │   ├── file.rs                # /dev/shm 0600 临时文件 + 覆写清理
│       │   ├── askpass.rs             # SSH/SUDO/GIT_ASKPASS 内部助手与一次性 IPC
│       │   └── arg.rs
│       └── redact.rs                  # 子进程 stdout/stderr 流式密钥脱敏
├── relay/                             # 中转端 Go 项目 (outsider-relay)
│   ├── pyproject.toml                 # 独立 uvx 包: outsider-relay（仅需 Go）
│   ├── _pep517.py
│   ├── cmd/
│   │   └── outsider-relay/
│   │       └── main.go                # 服务启动、relay.toml 加载、SIGHUP 热重载、优雅停机
│   └── internal/
│       ├── config/                    # relay.toml 解析、环境变量覆盖
│       ├── crypto/                    # 定长前缀 context_hash、Ed25519 白名单验签
│       ├── session/                   # 内存会话 Store (sync.Mutex + chan 唤醒)、seen_nonces、Reaper
│       ├── server/                    # net/http 路由、安全响应头 (CSP/no-store)、限流、embed 静态页
│       └── notifier/                  # Notifier 单向推送接口、shoutrrr、webhook 模板
└── web/                               # 批准端零依赖静态网页（构建时 embed 至 relay）
    ├── index.html                     # 语义化原生 HTML
    ├── app.js                         # WebCrypto Ed25519 验签 + TOFU 管理 + X25519 加密 + 表单控制
    └── style.css                      # 极简低 CSS 基础排版（无视觉设计，后续可扩展）
```

### 核心依赖

- **申请端（Rust）**：
  - CLI 与网络：`clap`、`tokio`、`reqwest`（`rustls-tls` 避免 OpenSSL 动态链接问题）、`serde` / `serde_json` / `toml`
  - 加密与签名：`x25519-dalek`、`ed25519-dalek`、`hkdf`、`sha2`、`aes-gcm`、`rand`、`zeroize`、`base64`
- **中转端（Go）**：
  - 标准库：`net/http`、`embed`、`crypto/ed25519`、`crypto/sha256`、`crypto/rand`、`encoding/base64`、`log/slog`、`text/template`、`os/signal`
  - 外部库（仅 2 个）：`github.com/nicholas-fedor/shoutrrr`、`github.com/BurntSushi/toml`
- **分发与打包（`uvx`）**：
  - 零外部构建依赖的纯标准库 PEP 517 后端（`scripts/pep517_backend.py`），将原生编译的 `outsider` 与 `outsider-relay` 二进制直接写入 wheel 的 `.data/scripts/`（保持原生进程模型、`current_exe()` 自调用及 `SIGHUP`/`SIGTERM` 信号投递）；同时提供独立包（`cli/` → `outsider`，`relay/` → `outsider-relay`）与仓库根目录统一包（`pyproject.toml`）。

---

## 7. 核心实现清单

1. **`protocol/test-vectors.json`**：固化定长前缀二进制 `context_hash`、`Ed25519` 签名输入与签名、`X25519 + HKDF-SHA256 + AES-256-GCM` 密文与 `AAD`、以及 8 位公钥指纹测试向量，供 Rust、Go、WebCrypto 三端自动化回归验证。
2. **`relay/`（Go 中转端）**：实现无数据库 `relay.toml` 白名单验签（支持 `SIGHUP` 热重载与环境变量覆盖）与 nonce 防重放、纯内存会话状态机（TTL 自动过期）与 `chan` 毫秒级唤醒、25 秒分片长轮询、`[[notifiers]]`（官方 `shoutrrr` + 可模板化 `webhook` + 可选 `redact_notification_metadata`），以及 `embed.FS` 内嵌静态审批页服务。
3. **`web/`（批准端）**：采用语义化原生 HTML + 极低 CSS（无视觉设计，后续再美化），实现原生 WebCrypto `Ed25519` 验签 + 浏览器本地 TOFU 信任表（同屏首次点击「信任并继续」保存、同名公钥突变告警阻断、原生 `<details>` 本地设备查看/移除）、表单与路径前缀 `/approve/<name_slug>/<approve_token>`（Bitwarden `autocomplete="current-password"`、单行/多行切换、粘贴按钮、纯文本倒计时）、WebCrypto 原生 `X25519` 加密与严格 CSP（`style-src 'self'; form-action 'none'`）。
4. **`cli/`（Rust 申请端）**：实现 `init`（直接输出可粘贴 `relay.toml` 片段）、`id`、`doctor`、`run`（由 `--name` 自动生成 URL slug 与 `stderr` 状态提示）及 5 种交接模式（`env`、`stdin`、`file`、`askpass`、`arg`）、`--redact` 子进程输出流式脱敏、内存 `zeroize` 与信号清理。
5. **`docs/SKILL.md`、`docs/references/` 与 `scripts/package-skill.sh`**：编写 Agent Skill 规范、交接示例文档与打包脚本，组装「静态二进制 + `SKILL.md`」Skill 分发包。
