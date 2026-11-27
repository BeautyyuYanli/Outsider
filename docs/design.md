# Outsider — 端到端加密带外密钥传输与交接系统设计方案

> **定位**：面向 AI Agent、自动化脚本与无头服务器环境的**带外（Out-of-Band）人工审批密钥传输系统**。实现「密钥不落盘、不进 LLM 上下文、中转端零知识、原生 SOPS（`age`）内存解密、移动端密码管理器一键填充」的安全密钥解锁与交接流程。
>
> 有关 Go CLI 重写、原生 SOPS（`age`）引擎、`[names.<slug>]` 校验登记表及 Web 端按需 `age` 私钥生成的完整细节，另见 [`docs/go-cli-sops-design.md`](go-cli-sops-design.md)。

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
    Agent["AI Agent / 宿主脚本"] -->|"调用 Skill CLI"| Req["申请端 Requester (Go CLI + 原生 SOPS)"]
    Req -->|"1. 生成临时 X25519 密钥对 (内存)\n2. 用长期 Ed25519 私钥对请求签名\n3. 提交请求并阻塞等待密文"| Relay["中转端 Relay (Go 单二进制 · 零知识)"]
    Relay -->|"4. 校验白名单公钥签名\n5. 推送通知 (含审批 URL)"| Notify["通知渠道 (Shoutrrr / Webhook)"]
    Notify -->|"6. 点击 URL 打开审批页"| App["批准端 Approver (内嵌浏览器 Web UI)"]
    PM["密码管理器 (Bitwarden / 1Password / Apple Passwords)"] -.->|"7. 自动识别表单并填充密钥"| App
    App -->|"8. 本地验签 (TOFU 已信任申请端公钥)\n9. 用申请端 X25519 公钥加密 (E2EE) 并上传密文"| Relay
    Relay -->|"10. 唤醒阻塞连接并一次性转发密文 (随即销毁)"| Req
    Req -->|"11. 内存解密并擦除私钥 (可选 SOPS 内存解密)\n12. 通过 env/env-all/stdin/file/askpass 交接"| Target["目标使用程序 (docker / psql / ssh / pytest...)"]
```

### 1.3 核心设计原则

- **中转端零知识与无数据库（Zero-Knowledge, DB-Free Relay）**：明文只在批准端浏览器和申请端 CLI 内存中存在；中转端仅通过静态配置文件（`relay.toml`）保存已信任申请端的公开 `Ed25519` 公钥列表，运行时会话与密文纯内存暂存、读后即焚、绝不落盘或记日志。
- **端到端身份真实性（Ed25519 + 浏览器 TOFU）**：每台申请端持有长期 `Ed25519` 身份密钥对每次解锁请求签名；批准端浏览器在首次审批点击「信任并继续」后，将申请端公钥持久化保存在浏览器本地，后续自动验签，防范中转端调包临时公钥或篡改申请上下文。
- **Agent 上下文隔离（LLM-Blind Handoff）**：申请端 CLI 仅通过 `outsider run` 作为父进程（或 Unix `exec` 直接替换进程）注入密钥，架构上不提供任何将明文打印到 `stdout` 的接口，并且子进程直接继承原生 TTY `stdout`/`stderr`，父进程完成交接即擦除内存、不在子进程运行期间持有明文副本。
- **原生 SOPS（`age`）与最小权限**：审批端仅下发 `SOPS_AGE_KEY`，由 `outsider` 内置纯 Go SOPS v3 引擎在内存中解密本地加密 YAML 并提取全部或指定子集 KV，随即擦除 `SOPS_AGE_KEY`（永不传给子进程），无需宿主机安装 `sops`/`age`。
- **密码管理器原生友好**：批准端统一采用基于密钥名 slug 的路径前缀 URL 与标准登录表单，严格适配 Bitwarden、1Password、Apple Passwords 等自动填充引擎的 URI 匹配与表单识别规则；SOPS 初始化场景下按需提供浏览器端零依赖 `age` 私钥生成辅助按钮。
- **跨代理与弱网鲁棒**：阻塞等待采用 25 秒分片长轮询（Long Polling），避免被 Nginx / Cloudflare / 企业代理的空闲超时切断。

---

## 2. 端到端加密、身份验签与安全模型

### 2.1 唯一锁定密码学协议（Protocol `v1`）

遵循「不提供运行时算法协商、通过协议版本隐式绑定唯一套件」原则，`v1` 协议唯一锁定以下组合（Go 与现代浏览器 `window.crypto.subtle` 全部原生支持，零第三方 JS 依赖）：

| 层级 | 锁定算法 | 生命周期与职责 |
| :--- | :--- | :--- |
| **申请端身份签名** | `Ed25519`（RFC 8032） | **长期密钥对**（`~/.config/outsider/identity.key`，`0600`）：仅用于对每次解锁请求签名，证明 `pk_req` 与上下文确由信任申请端发出（同时替代静态 `client_token`） |
| **密钥交换（ECDH）** | `X25519`（RFC 7748） | **一次性临时密钥对**（纯内存生成、解密即擦除）：公钥固定 32 字节（Base64URL 为 43 字符）；严格拒绝低阶点/全零共享密钥 |
| **密钥派生（KDF）** | `HKDF-SHA256`（RFC 5869） | 从共享秘密派生 32 字节一次性对称加密密钥，并将双方公钥绑定进 `info`（Transcript Binding） |
| **认证加密（AEAD）** | `AES-256-GCM` | 12 字节随机 Nonce + 16 字节认证标签；借助 `AAD` 绑定会话与上下文摘要 |

> **浏览器运行时要求**：批准端依赖现代浏览器原生 WebCrypto `X25519` 与 `Ed25519` 支持（Safari 17+ / iOS 17+、Chrome 133+、Firefox 130+），页面初始化时检测 `crypto.subtle` 能力并在极老旧环境中给出明确提示。

### 2.2 上下文哈希与请求身份签名

为彻底避免 Go / JS 跨端在 JSON 规范化上的差异坑，`context_hash` 采用**长度前缀二进制编码**（字节级零歧义）：

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
    participant CLI as 申请端 (Go CLI)
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
    Web->>Web: 渲染登录表单, Bitwarden 匹配路径前缀 URL 并自动填充密钥 (SOPS 初始化按需提供 age 生成)
    Web->>Web: 点击「加密并发送」: 生成临时 X25519 epk, HKDF 派生密钥, AES-256-GCM 加密
    Web->>Relay: POST /v1/approve/{approve_token} (v=1, epk, nonce, ciphertext)
    Web->>Web: 清空表单输入与内存变量
    Relay->>Relay: 校验一次性状态 -> 存入内存并 close(done) 唤醒等待方
    Relay-->>Web: 200 OK (已发送)

    Relay-->>CLI: 唤醒长轮询, 返回加密信封 (同时从内存彻底删除密文!)
    CLI->>CLI: 用 sk_req + 本地 AAD 解密; 立即擦除 sk_req (SOPS 模式内存解密并立即擦除 SOPS_AGE_KEY)
    CLI->>Target: 按指定模式注入密钥并执行目标程序 (env/env-all/stdin/file/askpass/arg)
    Target-->>CLI: 进程退出 (exit code)
    CLI->>CLI: 清理临时文件, 擦除明文切片, 透传 exit code
```

### 2.6 威胁模型与信任边界

| 威胁场景 | 防御机制 | 残余风险与说明 |
| :--- | :--- | :--- |
| **中转端被动窃听（Honest-but-Curious）** | E2EE（`sk_req` 永不离开申请端内存），密文阅后即焚不落盘 | 完全防御 |
| **中转端篡改请求上下文（Bait-and-Switch）** | 申请端 `Ed25519` 签名覆盖 `context_hash` + AEAD `AAD` 绑定 `context_hash` | 完全防御（审批端验签即阻断，申请端解密亦双保险失败） |
| **中转端主动 MITM（替换 `pk_req`）** | `Ed25519` 签名绑定 `pk_req`，批准端以浏览器本地已存的 `id_pk`（TOFU）验签，同名设备公钥突变触发红警阻断 | 审批页内嵌于自建中转单二进制，需信任自己维护的中转实例本身未被攻破 |
| **不可信 Notifier（窃听元数据 / 抢先提交假密文 / 钓鱼）** | 1. **防伪造提交**：推荐前置 **Cloudflare Access（Email OTP）** 保护 `/approve/*` 与 `/v1/approve/*`；<br>2. **防元数据泄露**：可开启 `redact_notification_metadata = true` 仅推送审批链接；<br>3. **防钓鱼**：Bitwarden 按真实域名+路径前缀匹配，假域名不会弹出自动填充 | 不可信 Notifier 仍可能扣留或延迟消息（纯可用性 DoS） |
| **恶意第三方刷通知轰炸（DoS）** | 中转端校验 `relay.toml` 中的 `trusted_clients` Ed25519 签名 + 时间戳/nonce 防重放 + 单设备并发与频率限制 | 有效缓解 |
| **AI Agent 偷窥或日志泄露明文** | 不提供明文 `stdout` 输出接口；`outsider run` 直接注入或 `exec` 替换目标进程；SOPS 模式下 `SOPS_AGE_KEY` 永不暴露给子进程；`SKILL.md` 规范约束 | 无法防御目标程序主动把密钥打印到 `stdout` 或发往外网（需靠审批者审核通知中的命令摘要） |

---

## 3. 申请端设计（Go CLI + 原生 SOPS + Agent Skill）

### 3.1 技术选型与进程加固

- **语言**：Go（与 Relay 统一单仓 `module outsider`，`CGO_ENABLED=0` 静态编译单文件二进制，复用 `internal/proto/`，二进制压缩 wheel ~3.4MB）。
- **进程与内存卫生**：
  - 启动即执行进程加固：Unix 设置 `RLIMIT_CORE = 0`（禁用 core dump），Linux 额外调用 `prctl(PR_SET_DUMPABLE, 0)`（阻断同 UID 非特权 `ptrace` 与 `/proc/<pid>/mem` 读取）。
  - 敏感切片（`id_sk`、`sk_req`、`SOPS_AGE_KEY`、解密后明文）使用后立即 `clear(...)` 覆写清零；在 Unix 上对 `--env` / `--env-all` / `--arg-placeholder` 使用 `syscall.Exec` 直接替换进程，零父进程滞留。
  - 注册 `SIGINT` / `SIGTERM` 信号处理，确保异常中断时清理临时文件并通知中转端取消请求（`DELETE /v1/requests/{id}`）。

### 3.2 命令行接口（CLI UX）

主命令：`outsider`

```bash
# 首次初始化：生成长期 Ed25519 身份密钥与 config.toml，
# 并直接输出可粘贴进 relay.toml 的 [[trusted_clients]] 片段与 8 位公钥指纹
outsider init --relay https://relay.example.com --name macbook-pro

# 查看当前设备公钥、TOML 片段与指纹；检查中转端连通性与签名白名单
outsider id
outsider doctor

# 校验登记表（统一管理 Direct 与 SOPS 审批名，仅经真实审批核验才能新增）
outsider name ls
outsider name add personal-sops --sops --desc "个人 SOPS 主私钥"
outsider name set personal-sops --desc "更新备注（纯本地）"
outsider name rm old-name

# 原生 SOPS 管理（无需外部 sops/age 二进制，100% 互通官方 SOPS v3）
outsider sops keys ~/.secrets.enc.yaml
outsider sops init ~/.secrets.enc.yaml --name personal-sops
outsider sops set ~/.secrets.enc.yaml GH_TOKEN db.password
outsider sops unset ~/.secrets.enc.yaml OLD_KEY

# SOPS 模式运行（自动反查 --name，内存解密并立即擦除 SOPS_AGE_KEY）
outsider run --sops ~/.secrets.enc.yaml --reason "Run tests" --env-all -- pytest
outsider run --sops ~/.secrets.enc.yaml --sops-key db.password --reason "Migrate DB" --env PGPASSWORD -- psql -h db.prod

# Direct 单密钥模式运行
outsider run --name "docker-pat" --reason "Push image v1.2.0" --stdin -- docker login -u myuser --password-stdin
```

> **等待期终端反馈（`stderr`）**：阻塞等待审批期间，CLI 仅向 `stderr` 打印简洁状态（例如 `[outsider] Waiting for approval: prod-db (120s) | Device FP: 7K4M-9P2X`），绝不污染 `stdout`。

### 3.3 密钥交接方式（Handoff Modes）

`outsider run` 解耦「密钥来源（Direct / SOPS）」与「交接方式」（架构上不提供将明文输出到 `stdout` 的模式）：

| 模式 | CLI 参数 | 底层实现机制 | 典型适用程序 | 安全性 |
| :--- | :--- | :--- | :--- | :---: |
| **1. 环境变量** | `--env VAR` <br> `--env VAR="prefix_{{secret}}"` <br> `--env-all`（SOPS 多键） | 直接注入子进程环境块（Unix 使用 `syscall.Exec` 直接替换进程），不污染父 Shell 环境 | `aws`、`curl`、`python`、`psql (PGPASSWORD)`、`gh (GH_TOKEN)`、`pytest`、绝大多数 SDK | 高 |
| **2. 标准输入** | `--stdin` <br> `--stdin-template "{{secret}}\n"` <br> `--no-stdin-newline` | 创建匿名管道写入明文后立即关闭写端，绑定为子进程 `stdin` | `docker login --password-stdin`、`sudo -S`、`rclone`、`openssl -pass stdin` | 极高 |
| **3. 临时内存文件** | `--file` <br> `--file-env KEY_FILE` <br> `--file-format dotenv\|json\|yaml` | 优先在 `/dev/shm`（Linux 内存盘）或系统临时目录创建 `0600` 随机临时文件，将路径注入 `{{file}}` 或环境变量；退出或收到信号时覆写清零并删除 | `ssh -i {{file}}`、`docker compose --env-file {{file}}`、`kubectl --kubeconfig {{file}}`、证书/JSON 凭证 | 高 |
| **4. ASKPASS 代理** | `--askpass` | 自动设置 `SSH_ASKPASS` / `SUDO_ASKPASS` / `GIT_ASKPASS` 指向 `outsider` 自身内部的 `askpass-helper`，通过父子进程间私有一次性 Unix Socket 传递密钥，无需暴露给环境或屏幕 | `ssh`、`ssh-add`、`git push/fetch`、`sudo -A` | 极高 |
| **5. 命令行参数替换** | `--arg-placeholder "{{secret}}"` | 将目标命令 `argv` 中的占位符替换为明文 | 仅接受 `--token <val>` / `-p<val>` 的遗留 CLI | 中（同机用户可能经 `ps` 看到，CLI 会打印警告） |

### 3.4 退出码约定

当目标程序正常拉起并退出时，直接透传目标程序的退出码；仅当 `outsider` 自身阶段失败时返回保留退出码：

- `0`：目标程序成功执行（或透传目标程序退出码）
- `100`：配置错误、参数无效或 SOPS 元数据校验失败
- `101`：无法连接中转端 / 设备公钥未授权或验签失败
- `102`：等待超时（Expired）或取消
- `103`：E2EE 密文或 SOPS 解密/完整性校验失败

### 3.5 本地配置结构

默认目录：`~/.config/outsider/`
- `identity.key`：申请端 `Ed25519` 长期私钥（强制校验权限 `0600`）
- `config.toml`：运行配置（`0600`，支持环境变量 `OUTSIDER_RELAY_URL`、`OUTSIDER_IDENTITY_KEY` 覆盖，历史 `default_redact` 字段静默兼容）：

```toml
relay_url = "https://relay.example.com"
identity_key_path = "~/.config/outsider/identity.key"
default_timeout_secs = 120

[names.personal-sops]
description = "个人 SOPS 主私钥"
sops_recipient = "age1..."

[names.github-pat]
description = "GitHub release token"
```

### 3.6 Agent Skill 分发结构

Skill 默认通过 `uvx` 直接基于 GitHub `main` 分支执行 `outsider`（无需在 Skill 内打包平台二进制），通过根目录 `scripts/package-skill.sh` 从 `docs/SKILL.md` 与 `docs/references/` 组装跨平台分发包 `dist/outsider-skill.tar.gz`：

```text
outsider/
├── SKILL.md                    # Agent 指令规范（默认通过 uvx 运行、SOPS 优先、安全红线）
└── references/
    └── handoff-examples.md     # 原生 SOPS、name 登记与 Direct 交接命令速查
```

---

## 4. 中转端设计（Go Zero-Knowledge Relay）

### 4.1 技术选型与极简配置（无数据库）

- **单静态二进制：Go（标准库 `net/http` + `embed.FS` + `crypto/ed25519` + 官方 `shoutrrr`）**
  - 中转端不涉及 X25519 / AES-GCM 加解密，核心职责仅为验签、内存路由阻塞与通知分发；与 Go CLI 共享 `internal/proto/` 协议实现，并与前端 JS 共享 `protocol/test-vectors.json` 跨语言测试向量，确保字节级一致。
  - 使用 `embed.FS` 将 `web/` 静态审批页直接内嵌进单二进制，可部署在任意 VPS、家庭服务器（搭配 Cloudflare Tunnel / Caddy 自动 HTTPS）或 Docker 容器中。
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

### 4.5 统一通知抽象（`shoutrrr` + `webhook`）

中转端定义极简 Go 单向推送接口：

```go
type Notifier interface {
    NotifyRequest(ctx context.Context, payload NotifyPayload) error
}
```

配置层仅暴露 **2 种标准 `type`**（`shoutrrr` 与 `webhook`），并支持 `redact_notification_metadata = true` 精简通知模式。

### 4.6 安全防护、限流与 Cloudflare Access 适配

- **推荐网关层保护（Cloudflare Zero Trust Access）**：`/approve/*` 与 `/v1/approve/*` 启用 Email OTP 保护；`/v1/requests` 与 `/v1/requests/*` 设为 Bypass（已由 `Ed25519` 签名鉴权）。
- **防通知轰炸与防重放**：按申请端 `id_pk` 限制最大同时 `PENDING` 会话数（默认 3）与滑动窗口速率限制（每分钟最多 10 次）；内存维护 60 秒 `seen_nonces` 集合拦截重放请求。
- **零日志泄露与定时清道夫**：HTTP Access Log 脱敏 `approve_token` 与 `session_id`；后台 goroutine 每 5 秒扫描过期会话与过期 nonce 并清零释放。

---

## 5. 批准端设计（内嵌 Web UI + 密码管理器自动填充）

批准端是由 Go `embed.FS` 直接内嵌进中转端的**零第三方脚本依赖极简单页应用（SPA）**，采用语义化原生 HTML + 极低 CSS，核心聚焦：

1. **浏览器端前置 `Ed25519` 验签 + 本地 TOFU 信任表**（`localStorage` `outsider_trusted_clients_v1`；支持首次点击「信任并继续」、同名公钥突变红警阻断、`<details>` 本地设备查看与移除）。
2. **路径前缀 `/approve/<name_slug>/<approve_token>` 匹配密码管理器**（加载后通过 `history.replaceState` 抹去地址栏 token，保留 `/approve/<name_slug>/` 供 Bitwarden/1Password/Apple Passwords 精准自动填充）。
3. **按需零依赖 `age` 私钥生成**：仅当已签名 `context.command_summary` 以 `[sops:init ` 或 `[register-sops-key] ` 开头时显示「生成新 age 私钥」按钮；采用浏览器原生 `crypto.getRandomValues(32)` + 纯 JS BIP-173 Bech32 编码生成标准 `AGE-SECRET-KEY-1...`，并强制勾选「我已将生成的私钥保存到密码管理器」后才解锁提交。
4. **严格 CSP**：`default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'`。

---

## 6. 项目代码架构（统一 Go Monorepo）

采用统一 Go Monorepo 组织（Go 单一工具链同时构建 CLI 与 Relay）：

```text
Outsider/
├── go.mod                             # 统一 Go 模块根 (module outsider)
├── go.sum
├── pyproject.toml                     # 统一 uvx 包（同时提供 outsider 与 outsider-relay）
├── cmd/
│   ├── outsider/main.go               # CLI 入口（askpass-helper、进程加固、子命令分发）
│   └── outsider-relay/main.go         # Relay 入口（relay.toml、SIGHUP 热重载、优雅停机）
├── internal/
│   ├── proto/                         # CLI 与 Relay 共享协议单源（context_hash、Ed25519、X25519+HKDF+AES-GCM、API DTO）
│   ├── sopsage/                       # 轻量纯 Go SOPS v3 (age) 引擎（与官方 sops 双向互通）
│   ├── cli/                           # CLI 实现（init/id/doctor/name/sops/run、5 种交接与进程加固）
│   └── relay/                         # Relay 实现（config/session/server/notifier）
├── web/                               # 批准端零依赖静态网页（构建时 embed 至 relay）
│   ├── embed.go
│   ├── index.html
│   ├── app.js                         # WebCrypto Ed25519/X25519 + TOFU + 按需 BIP-173 age keygen
│   ├── app.test.mjs                   # Node 原生测试（含 protocol/test-vectors.json 与 age keygen）
│   └── style.css
├── cli/                               # 独立 uvx 包: outsider（仅需 Go）
│   ├── pyproject.toml
│   └── _pep517.py
├── relay/                             # 独立 uvx 包: outsider-relay（仅需 Go）
│   ├── pyproject.toml
│   ├── _pep517.py
│   └── relay.example.toml
├── protocol/
│   └── test-vectors.json              # Go / WebCrypto JS 跨语言共享一致性测试向量
├── docs/
│   ├── design.md                      # 本文档
│   ├── go-cli-sops-design.md          # Go CLI 重写与原生 SOPS 集成详细设计
│   ├── SKILL.md                       # Agent Skill 指令规范模板
│   └── references/
│       └── handoff-examples.md        # 交接与 SOPS 命令速查
└── scripts/
    ├── package-skill.sh               # 从 docs/ 组装纯 uvx 跨平台 outsider-skill.tar.gz
    ├── pep517_backend.py              # 零依赖 PEP 517 后端（将 Go 静态二进制打入 .data/scripts/）
    └── build-wheels.sh                # 构建独立 outsider 与 outsider-relay 原生 wheel
```

### 核心依赖

- **Go 模块（CLI + Relay 共享）**：
  - 标准库：`crypto/ed25519`、`crypto/ecdh`、`crypto/hkdf`、`crypto/aes`、`crypto/cipher`、`crypto/sha256`、`crypto/sha512`、`net/http`、`embed`、`syscall`
  - 外部库：`filippo.io/age`、`gopkg.in/yaml.v3`、`github.com/BurntSushi/toml`、`github.com/spf13/pflag`、`github.com/nicholas-fedor/shoutrrr`
- **分发与打包（`uvx`）**：
  - 零外部构建依赖的纯标准库 PEP 517 后端（`scripts/pep517_backend.py`），将 `CGO_ENABLED=0` 编译的 Go 二进制直接写入 wheel 的 `.data/scripts/`；支持独立包（`cli/` → `outsider`，`relay/` → `outsider-relay`）与根目录统一包（`pyproject.toml`）。
