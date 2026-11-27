# Outsider Go CLI 重写与原生 SOPS 集成设计方案

> 状态：**已实施完成**

## 1. 目标与背景

将原 Rust 申请端 CLI（`cli/`）使用 Go 重写，并把 SOPS（`age` 后端）作为一等能力纳入 `outsider` 产品方案：

1. **统一技术栈与协议单源**：CLI 与 Relay 合并到同一 Go 模块，共享 `internal/proto/`（`context_hash`、`Ed25519`、`X25519 + HKDF-SHA256 + AES-256-GCM`、API DTO），与 `web/` 继续共享 `protocol/test-vectors.json`；`uvx` 源码构建从 Rust ~22s 降至 Go ~2s，且仅需 Go 单一工具链。
2. **原生 SOPS 集成与最小权限**：审批端仅下发 `SOPS_AGE_KEY`，由 `outsider` 在进程内存中解密本地 SOPS 文件并提取全部或指定子集 KV，随后立即擦除 `SOPS_AGE_KEY`（永不传给子进程），并通过原有 5 种交接方式安全传递给子进程。
3. **精简安全边界（移除 `--redact`）**：不截获子进程 `stdout`/`stderr` 做流式脱敏，避免父进程在子进程运行期间长期滞留明文副本，同时完整保留原生 TTY 与进程直通语义。
4. **克制零新文件**：不发明 `catalog.toml`、`.outsider.toml` 等额外配置体系；仅在现有 `~/.config/outsider/config.toml` 中增加唯一的可选表 `[names.<slug>]`（统一存放 Direct 与 SOPS 审批名、备注及可选 `sops_recipient`），其余全部复用标准 SOPS YAML 文件本身。
5. **零破坏性兼容**：Relay HTTP/E2EE 协议、`relay.toml`、`~/.config/outsider/config.toml`（解析时宽容忽略历史 `default_redact` 字段）、`~/.config/outsider/identity.key` 及现有设备指纹完全保持兼容，无需重新初始化；`web/` 仅按需增加极简零依赖的前端 `age` 私钥生成辅助按钮。

### 已确认关键决策

| 决策项 | 结论 |
| :--- | :--- |
| SOPS 底层引擎 | **方案 A（轻量纯 Go 自实现）**：基于 `filippo.io/age` + `gopkg.in/yaml.v3` + Go 标准库 `AES-256-GCM` 与 MAC 校验，零云厂商 SDK 依赖，二进制体积 ~8–10MB，与官方 `sops` CLI 100% 互通 |
| `outsider sops` 管理子命令 | **纳入**：内置纯粹的 4 个文件/键操作——`keys`、`init`（复用已登记公钥时 0 审批）、`set`（先收新值最后解锁主私钥，支持多键与 `--stdin`）、`unset`（支持多键）；**不设 CLI `keygen`**，改在 Web 审批页按需提供纯前端零依赖 `age` 私钥生成 |
| `config.toml` 默认 SOPS 路径 | **不新增 `default_sops_file`**：每次显式通过 `--sops <file>` 指定路径，语义透明无隐式状态 |
| `--name` 与 `[names.<slug>]` | 在 `config.toml` 维护统一命名空间 `[names.<slug>]`（仅 `description` 与可选 `sops_recipient`，不记录文件路径）：**新增条目只能经真实审批核验**（`name add` / 首次 `sops init` / `run --save-name`），`sops_recipient` 仅由真实 `SOPS_AGE_KEY` 密码学推导且全局唯一；`name set` 仅纯本地维护已有条目的 `description`；`run` 默认只读 `config.toml` |
| 输出流式脱敏（`--redact`） | **删除**：移除 `redact` 模块、`--no-redact` 参数与 `default_redact` 行为；父进程交接完成即擦除内存，子进程直接继承原生 `stdout`/`stderr`（TTY 无损） |

---

## 2. 核心架构：解耦「密钥来源」与「交接方式」

```text
[经 Relay 端到端加密审批]
            │
            ▼
┌────────────────────────────────────────────────────────┐
│  Stage 1: Secret Source（密钥解析层）                   │
├────────────────────────────────────────────────────────┤
│ • Direct 模式（默认，无 --sops）                        │
│   --name = 目标密钥本身的 Bitwarden 标识                │
│   审批明文 ──► 单值 Secret ([]byte)                     │
│                                                        │
│ • SOPS 模式（--sops <file> [--sops-key K]...）          │
│   1. 审批前本地 Fail-Fast 校验文件存在性与明文键名      │
│   2. 从文件 sops.age[].recipient 反查 config.toml 的    │
│      [names.*].sops_recipient 自动解析 --name          │
│      （显式传参优先）                                   │
│   3. 审批明文 = SOPS_AGE_KEY                           │
│   4. 进程内解出 Data Key、校验全文件 MAC、解密目标键值  │
│   5. 立即 clear(SOPS_AGE_KEY) 与 Data Key              │
│   6. SOPS_AGE_KEY 永不进入子进程环境                    │
│   7. 产出：单值（1 个 --sops-key）或 KV Map（多键/全量） │
└──────────────────────────┬─────────────────────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│  Stage 2: Handoff（交接层，传递方式不变，原生 stdio）   │
├────────────────────────────────────────────────────────┤
│ • 单值交接（Direct 或单个 --sops-key）：                │
│   --stdin / --askpass / --env VAR / --env VAR=tpl      │
│   / --file / --file-env VAR / --arg-placeholder        │
│   （单键 SOPS 亦可用 --env-all 直接按原 key 名注入）    │
│                                                        │
│ • 多键 / 全量交接（SOPS 多个或零个 --sops-key）：       │
│   --env-all（按原键名批量注入子进程环境变量）           │
│   --file / --file-env VAR（按 --file-format 序列化到   │
│   /dev/shm 0600 临时文件，退出即覆零删除）              │
└──────────────────────────┬─────────────────────────────┘
                           │ 交接完成即 clear() 擦除父进程内全部明文缓冲
                           ▼
              [目标子进程直接继承 stdout/stderr]
```

### `--name` 语义与统一 `[names.<slug>]` 表

`--name` 在整个协议中统一锚定 **「审批人（及 Bitwarden `/approve/<name-slug>/`）要填写的那条凭证标识」**：

- **Direct 模式**：审批人直接填写业务密钥本身，因此 `--name` 必填，表示业务密钥标识（如 `prod-db`、`prod-ssh-passphrase`）。
- **SOPS 模式**：审批人填写的是解锁 SOPS 文件的 `age` 私钥，因此 `--name` 表示这把 `age` 私钥的标识（如 `personal-sops`）。同一把 `age` 私钥可加密多个 SOPS 文件（1:N 关系）。
- **在现有 `~/.config/outsider/config.toml` 中统一维护 `[names.<slug>]`**（不含任何私钥，零新文件，因 slug 仅含 `a-z0-9-` 故天然为合法 TOML 裸键）：
  ```toml
  [names.personal-sops]
  description = "个人通用 SOPS 私钥"
  sops_recipient = "age1v7dusep9qvmzkatum2y2jrgpqvz5qmk94rjhs9suhnz8uja3s4csrlvmn7"

  [names.prod-ssh-passphrase]
  description = "生产服务器 SSH 私钥口令"

  [names.prod-db]
  description = "生产数据库密码"
  ```
  - **字段严格保持极简**：仅 `description`（描述该审批名 / 私钥本身，不硬塞文件路径）与可选 `sops_recipient`（存在表示 SOPS `age` 私钥，缺省表示 Direct 业务密钥）。
  - **强不变量（仅真实审批可新增，公钥不可手填）**：
    - `config.toml` 中每一条 `[names.<slug>]` 都必须通过一次**真实人类审批**产生，杜绝本地凭空伪造未配置的审批名；
    - `sops_recipient` 只能由真实审批下发的 `SOPS_AGE_KEY` 在进程内存中密码学推导写入，不提供手填/手改公钥的入口；
    - **全局唯一约束**：同一 `age1...` 公钥在 `[names.*]` 中最多绑定一个 `<slug>`；若写入时该公钥已被其他 `<slug>` 占用，报错退出 `100`，从源头消除反查歧义。
  - **CRUD 边界清晰**：
    - **增（必须经真实审批）**：
      - `outsider name add <slug> [--sops] [--desc "..."]`：专门的端到端核验式登记（不拉起子进程，核验即擦除）；
      - `outsider sops init <file> --name <slug> [--desc "..."]`：若 `<slug>` 尚未登记，经一次真实审批推导 `sops_recipient`、建文件并入表；若 `<slug>` 已存在且带 `sops_recipient`，则直接复用本地公钥 0 审批初始化新文件（支持 1:N 多文件，跨类型冲突报 `100`）；
      - `outsider run ... --name <slug> --save-name`：执行业务命令且审批成功后顺手登记（未传 `--save-name` 时 `run` 对 `config.toml` **严格只读**）。
    - **查（纯本地只读）**：`outsider name ls`。
    - **改（纯本地仅改元数据）**：`outsider name set <slug> --desc "..."`（`<slug>` 必须已存在，否则报 `100`；不改动 `sops_recipient`）。
    - **删（纯本地）**：`outsider name rm <slug>`（不影响已有 SOPS 文件或 Bitwarden；若需更换某名称对应的 `age` 私钥，先 `rm` 再经真实审批重新登记）。
  - **文件发现解耦**：`config.toml` 不记录 SOPS 文件路径，避免文件移动/删除导致的脏路径问题；具体 SOPS 文件按文件系统位置发现（全局 `~/.secrets.enc.yaml`、项目目录内 `*.enc.yaml` 等），再通过 `outsider sops keys <file>` 查看明文键名、通过 `sops_recipient` 自动反查 `--name`。
- **审批页清晰展示实际解锁范围**：SOPS 模式下构造受 `Ed25519` 签名的 `context.command` 时自动附带范围前缀（无需改动 Relay 协议），例如：
  - 单键：`[sops:~/.secrets.enc.yaml keys=GH_TOKEN] gh release list`
  - 多键：`[sops:~/.secrets.enc.yaml keys=DB_HOST,DB_PASS] ./migrate`
  - 全量：`[sops:~/.secrets.enc.yaml keys=*] pytest`
  - 初始化 / 登记：`[sops:init ~/.secrets.enc.yaml]`、`[register-sops-key] personal-sops`（触发 Web 审批页按需展示「生成新 age 私钥」按钮）

### 审批前 Fail-Fast 校验

在调用 Relay 发送任何审批通知之前，CLI 必须先在本地完成以下检查，不通过直接退出 `100`：

1. `--sops <file>` 指定的文件可读且为合法 SOPS YAML 文档（含 `sops.age` 元数据）。
2. 若指定了 `--sops-key K`（可重复），所有请求的键路径（支持点分叶子路径如 `db.password`）必须在 SOPS YAML 的明文键结构中存在且为标量叶子节点。
3. `--name` 可成功解析（显式传入，或 SOPS 模式下由 `[names.*].sops_recipient` 唯一命中）。
4. 若解析结果包含多个键（未传 `--sops-key` 且文件键数 > 1，或传了多个 `--sops-key`），仅允许搭配 `--env-all`、`--file`、`--file-env`；若误用 `--stdin`、`--askpass`、`--arg-placeholder`、`--env VAR`（单值模式），立即报错退出 `100`。
5. 使用 `--env-all` 时，所有待注入的键必须为合法 POSIX 环境变量名（`^[A-Za-z_][A-Za-z0-9_]*$`）的标量叶子键；若遇到嵌套对象或含 `.` 的路径（如 `db.password`），立即报错退出 `100`（提示改用 `--file --file-format yaml|json` 或 `--sops-key db.password --env DB_PASSWORD`）。

---

## 3. CLI 接口规范

### 3.1 原有子命令（保持兼容）

- `outsider init --relay <URL> --name <NAME> [--force]`
- `outsider id`
- `outsider doctor`
- `outsider run [OPTIONS] [--name <NAME>] -- <TARGET>...`（Direct 模式 `--name` 必填；SOPS 模式命中 `sops_recipient` 时可省略；移除 `--no-redact`）

### 3.2 `outsider run` 新增参数

| 参数 | 类型 | 说明 |
| :--- | :--- | :--- |
| `--sops <FILE>` | string | 启用 SOPS 模式，显式指定本地加密 YAML 文件路径 |
| `--sops-key <KEY>` | []string（可重复） | 提取指定标量叶子字段（与 `sops keys`/`set`/`unset` 统一使用点分路径如 `GH_TOKEN`、`db.password`）；省略时提取全部键值对 |
| `--env-all` | bool | 将提取出的 SOPS 键值对直接按原键名注入子进程环境变量（要求全部目标键为合法 POSIX 环境变量名标量叶子，否则审批前 Fail-Fast 退出 `100`） |
| `--file-format <FMT>` | string | 多键 SOPS 搭配 `--file` / `--file-env` 时的序列化格式：`dotenv`（默认）、`yaml`、`json` |
| `--save-name` | bool | 审批成功后显式将 `--name`（规范化 slug）登记到 `config.toml` 的 `[names.<slug>]`（Direct 记 `--reason` 为初始备注；SOPS 记推导出的 `sops_recipient`；若已存在且类型/公钥兼容则保留原备注，冲突则报错；不传此 flag 时 `run` 对 `config.toml` 严格只读） |

**使用示例**（假设 `[names.personal-sops]` 已在 `config.toml` 登记）：

```bash
# 1. 单键提取 + 原有 5 种交接方式（任意组合，无需重复写 --name）
outsider run --sops ~/.secrets.enc.yaml --sops-key GH_TOKEN --env GH_TOKEN -- gh release list
outsider run --sops ~/.secrets.enc.yaml --sops-key GH_TOKEN --env-all -- gh release list
outsider run --sops ~/.secrets.enc.yaml --sops-key SSH_KEY --file -- ssh -i {{file}} -o IdentitiesOnly=yes ops@host
outsider run --sops ~/.secrets.enc.yaml --sops-key GIT_PASS --askpass -- git push origin main
outsider run --sops ~/.secrets.enc.yaml --sops-key BACKUP_PASS --stdin -- openssl enc -d -aes-256-cbc -pbkdf2 -pass stdin -in a.enc -out a
outsider run --sops ~/.secrets.enc.yaml --sops-key CF_TOKEN --env AUTH="Bearer {{secret}}" -- sh -c 'curl -fsS -H "$AUTH" ...'

# 2. 多键提取 → 批量注入环境变量
outsider run --sops ~/.secrets.enc.yaml \
  --sops-key DB_HOST --sops-key DB_PASSWORD --env-all \
  -- ./migrate

# 3. 全量提取 → 注入环境变量 或 生成 /dev/shm 0600 临时 .env 文件
outsider run --sops ~/.secrets.enc.yaml --env-all -- pytest
outsider run --sops ~/.secrets.enc.yaml --file -- docker compose --env-file {{file}} up -d
```

### 3.3 新增 `outsider name` 名称管理子命令（统一管理 Direct 与 SOPS）

1. **`outsider name add <NAME> [--sops] [--desc <TEXT>] [--reason <TEXT>] [--timeout <SECS>]`**
   - **经真实审批核验新增**（本地先校验 `<NAME>` 经 `SlugifyName` 规范化后尚未存在于 `[names.*]`，已存在直接退出 `100`）；
   - 发送审批请求（审批页 `context.command` 清晰展示 `[register-name] <slug>` 或 `[register-sops-key] <slug>`；`--sops` 时 Web 审批页按需显示「生成新 age 私钥」辅助按钮），不拉起任何子进程；
   - 收到并解密载荷后：
     - Direct 模式：校验非空即完成端到端核验；
     - `--sops` 模式：解析 `AGE-SECRET-KEY-1...`（兼容多行 `age-keygen` 输出），推导 `age1...` 公钥并校验 `sops_recipient` 全局唯一性（冲突退出 `100`）；
   - 立即 `clear()` 擦除内存中的明文 / 私钥，将 `[names.<slug>]`（含 `--desc` 与可选 `sops_recipient`）写入 `config.toml`，输出规范化后的 `name`、Bitwarden 匹配前缀 `/approve/<slug>/`（以及 SOPS 模式下的 `age1...` 公钥）。
2. **`outsider name ls`**
   - 纯本地只读列出 `config.toml` 中全部 `[names.*]`（显示 `name`、类型 `direct`/`sops`、`description` 与 `sops_recipient` 摘要），作为人和 Agent 发现已核验名称的统一入口。
3. **`outsider name set <NAME> --desc <TEXT>`**
   - 纯本地**仅维护已有条目的元数据**（当前仅 `description`）；若 `[names.<slug>]` 不存在则直接报错退出 `100`（不可用于新增）；不提供修改 `sops_recipient` 的参数，确保公钥始终经真实审批推导。
4. **`outsider name rm <NAME>`**
   - 纯本地从 `config.toml` 移除 `[names.<slug>]`（不影响任何已有 SOPS 文件或 Bitwarden 条目；密钥轮换时先 `rm` 再重新通过真实审批登记）。

### 3.4 新增 `outsider sops` 管理子命令

无需外部 `sops`、`age`、`age-keygen` 或 `python3`；`keys`、`set`、`unset` 与 `run --sops-key` **统一使用点分叶子路径语义**（如 `GH_TOKEN`、`db.password`）：

1. **`outsider sops keys <FILE>`**
   - 纯本地解析 YAML 明文键结构并逐行输出全部叶子键路径（不触发审批，不接触私钥）。
2. **`outsider sops init <FILE> --name <APPROVAL_NAME> [--desc <TEXT>] [--reason <TEXT>] [--timeout <SECS>]`**
   - 校验 `<FILE>` 尚不存在；
   - **已登记公钥免审批（0 次审批）**：若 `[names.<slug>]` 已在 `config.toml` 中存在合法 `sops_recipient`（公钥已由历史真实审批核验过），直接使用本地公钥生成随机 Data Key 并创建带合法 MAC 的 SOPS YAML 文件（`0600`），不触发任何审批（若同时显式传了 `--desc` 则同步更新备注；若 `<slug>` 已存在但为 Direct 条目则报 `100`）；
   - **首次登记（1 次审批，支持在 Web 审批页直接生成新 `age` 私钥）**：若 `[names.<slug>]` 尚不存在，经 Outsider 审批获取 `SOPS_AGE_KEY`（`context.command` 为 `[sops:init <FILE>]`，审批页自动提供「生成新 age 私钥」按钮，兼容粘贴多行 `age-keygen` 输出），进程内推导 `age1...` 公钥并校验全局唯一性（冲突退出 `100`），创建 `0600` SOPS 文件并验证往返解密通过，将 `sops_recipient` 写入 `[names.<slug>]`（未传 `--desc` 时留空，不把单个 `<FILE>` 拼入 `description`）；
   - 成功后打印文件路径与 `age1...` 公钥。
3. **`outsider sops set <FILE> <KEY>... [--name <APPROVAL_NAME>] [--secret-name <SLUG>] [--stdin] [--reason <TEXT>] [--timeout <SECS>]`**
   - 支持单键或一次设置多键（多键时禁用 `--secret-name` 与 `--stdin`，每个 `<KEY>` 自动按 `SlugifyName(<KEY>)` 生成审批名）；审批前先在本地 Fail-Fast 校验 `<FILE>` 合法性、`--name` 可解析及 `<KEY>` 路径合法性；
   - **先收新值、最后解锁主私钥（最小化 `SOPS_AGE_KEY` 内存驻留期）**：
     - 第 1 步（获取新值）：
       - 默认模式：按顺序逐个审批获取各 `<KEY>` 的新明文值（单键支持 `--secret-name` 覆盖审批名）；
       - `--stdin` 模式（仅单键）：直接从 `stdin` 读取新值，跳过新值审批（适合写入 `DB_HOST` 等伴生非敏感配置或 `openssl rand -hex 32` 刚生成的随机令牌）；
     - 第 2 步（最后一步，仅 1 次审批）：审批获取 `SOPS_AGE_KEY`（`--name` 可从 `[names.*].sops_recipient` 自动解析；审批页明确展示 `[sops:set <file> keys=K1,K2]` 或 `[sops:set <file> key=K (from stdin)]`）；
   - 毫秒级完成：进程内解出文件 Data Key 与现有明文树、以原 Data Key 加密全部新值（保留未变更字段原密文与 IV，减少 git diff 噪音）、更新 `lastmodified`、重算一次全文件 `sops.mac`；
   - 同目录创建 `0600` 临时文件、`fsync` 后原子 `os.Rename` 覆盖 `<FILE>`；立即 `clear()` 擦除 `SOPS_AGE_KEY`、Data Key 与全部新明文值。
4. **`outsider sops unset <FILE> <KEY>... [--name <APPROVAL_NAME>] [--reason <TEXT>] [--timeout <SECS>]`**
   - 支持单键或一次删除多键；本地先 Fail-Fast 确认所有请求的 `<KEY>` 路径均存在（任一不存在即退出 `100`）；
   - 经 1 次 `SOPS_AGE_KEY` 审批（`--name` 可自动解析；审批页展示 `[sops:unset <file> keys=K1,K2]`），批量删除对应键，重算全文件 `sops.mac` 并原子写回。

> **克制边界（明确不提供）**：不提供 `sops keygen`（私钥生成闭环在 Web 审批页完成，不进入宿主机终端历史或 LLM 上下文）；不提供 `sops get`（严守不向 stdout 输出明文密钥红线）；不内置 `sops rotate` / `add-recipient` 等低频运维命令，需要时直接使用 100% 互通的官方 `sops` CLI。

### 3.5 Web 审批页按需 `age` 私钥生成（零依赖、零协议改动）

- **触发条件**：仅当验签通过展示的 `context.command` 以 `[sops:init ` 或 `[register-sops-key] ` 开头时，审批页才在密钥输入框旁显示「生成新 age 私钥」按钮；所有普通审批页保持零干扰极简界面。
- **实现方式**：纯前端 `crypto.getRandomValues(new Uint8Array(32))` + ~35 行零依赖 BIP-173 Bech32 编码（HRP `"age-secret-key-"` 转大写得到 `AGE-SECRET-KEY-1...`），经原有 WebCrypto E2EE 加密发送，Relay 全程不可见明文；纳入 `web/app.test.mjs` 与 Go `filippo.io/age` 交叉兼容测试。
- **防丢失保护**：点击「生成新 age 私钥」后，私钥填入输入框并显示「复制」按钮与防丢确认勾选（「我已保存到密码管理器」，勾选后才解锁提交按钮），同时保持标准表单提交语义以便 Bitwarden 等密码管理器自动提示保存 `/approve/<slug>/` 条目。

### 3.6 退出码规范（保持不变）

- `0` / 子进程退出码：目标命令或管理子命令已执行。
- `100`：本地配置、参数、SOPS 文件格式、名称/公钥冲突或键不存在错误。
- `101`：Relay 不可达或设备公钥未在 `relay.toml` 白名单中。
- `102`：审批超时或被取消。
- `103`：E2EE 解密、AAD 校验、SOPS `age` 解密、私钥公钥不匹配或 SOPS MAC 完整性校验失败。

---

## 4. `internal/sopsage` 轻量 SOPS-Age 引擎设计

严格遵循官方 SOPS v3（`age` + `AES256_GCM`）格式规范，确保与官方 `sops` CLI **双向 100% 互通**（不发明自定义明文注释规则，避免与官方 `sops` 注释加密产生 warning）：

1. **Data Key 封装（`sops.age[]`）**：
   - 使用 `filippo.io/age` + `filippo.io/age/armor`；
   - 解密时遍历 `sops.age` 列表，用 `age.ParseX25519Identity(ageKey)` 解出 32 字节 AES-256 Data Key；
   - 新建文件时用 `crypto/rand` 生成 32 字节 Data Key，按 `sops.age[].recipient`（支持多公钥）使用 `age.ParseX25519Recipient` 加密为 ASCII Armor 写入 `enc`。
2. **字段值加密格式**：
   - `ENC[AES256_GCM,data:<b64>,iv:<b64>,tag:<b64>,type:<str|int|float|bool|bytes>]`
   - 使用 Go 标准库 `crypto/aes` + `cipher.NewGCMWithNonceSize(block, 32)`（SOPS 默认 32 字节 IV，解密时按解码后的 `len(iv)` 动态选择以兼容 12/32 字节 IV）；
   - AAD 严格按 SOPS 规范构造：将从根到当前值的路径键拼接为 `"k1:k2:"`（数组元素跳过索引，仅累加对象键名 + 冒号）。
3. **全文件完整性校验（`sops.mac`）**：
   - 按 SOPS 规范深度遍历文档（排除 `sops` 元数据子树），将所有叶子节点的明文序列化值按文档顺序写入 `SHA-512` 哈希，得到 128 字符大写十六进制摘要；
   - 以 `lastmodified`（RFC3339 字符串）作为 AAD、使用 Data Key 以 `AES256_GCM` 加密/验证该摘要，读写 `sops.mac`；
   - 解密时若 MAC 校验失败，直接返回退出码 `103`，拒绝使用任何解密数据。
4. **序列化与格式支持**：
   - 使用 `gopkg.in/yaml.v3` 的 `yaml.Node` 保留键顺序与未修改字段的原始密文；
   - 多键交接 `--file-format`：
     - `dotenv`：输出标准 `KEY=VALUE`（对包含空格/换行/引号的值自动做转义）；
     - `yaml`：标准 YAML 映射；
     - `json`：标准 JSON 对象。
5. **双向互操作测试**：
   - 单元测试覆盖：自加密 → 自解密、`sops` CLI 加密 → `sopsage` 解密、`sopsage` 加密/set/unset → `sops` CLI 解密与 MAC 验证、MAC 篡改拒绝、错私钥拒绝。

---

## 5. 统一 Go Monorepo 结构与 `uvx` 打包

```text
Outsider/
├── go.mod / go.sum                    # 统一 Go 模块（cli + relay + web embed）
├── cmd/
│   ├── outsider/main.go               # Go CLI 入口（含首行 --askpass 自调用分支）
│   └── outsider-relay/main.go         # Go Relay 入口
├── internal/
│   ├── proto/                         # CLI & Relay 共享协议层
│   │   ├── context.go                 # 定长前缀 context_hash、SlugifyName
│   │   ├── identity.go                # Ed25519 签名/验签、8 位指纹
│   │   ├── crypto.go                  # X25519 + HKDF-SHA256 + AES-256-GCM + AAD
│   │   ├── api.go                     # Request / Response / Envelope / Doctor DTO
│   │   └── protocol_test.go           # 对齐 protocol/test-vectors.json 全量校验
│   ├── sopsage/                       # 轻量纯 Go SOPS v3 (age) 引擎
│   │   ├── codec.go                   # AES256_GCM 字段加解密、AAD、MAC
│   │   ├── store.go                   # YAML Node 遍历、LoadKeys / Decrypt / Init / Set / Unset
│   │   └── sopsage_test.go            # 单元 + 官方 sops CLI 双向互通测试
│   ├── cli/                           # CLI 业务层
│   │   ├── config.go                  # ~/.config/outsider/config.toml ([names.*]) & identity.key (0600)
│   │   ├── client.go                  # HTTPS 客户端、请求签名、25s 分片长轮询、信号取消
│   │   ├── source.go                  # Direct / SOPS 密钥源解析与审批前 Fail-Fast
│   │   ├── handoff.go                 # env / env-all / stdin / file / file-env / askpass / arg
│   │   └── cmd_*.go                   # init / id / doctor / run / name / sops 子命令
│   └── relay/                         # 原 relay/internal/{config,session,server,notifier}
├── web/                               # 零依赖前端 + embed.go（按需增加 age 私钥生成按钮）
├── protocol/test-vectors.json         # Go + WebCrypto JS 共享测试向量（保持不变）
├── pyproject.toml                     # 根目录统一 uvx 包（同时打 outsider + outsider-relay）
├── cli/
│   ├── pyproject.toml                 # 独立 outsider uvx 包（纯 Go 构建，不再需要 Rust）
│   └── _pep517.py
├── relay/
│   ├── pyproject.toml                 # 独立 outsider-relay uvx 包（纯 Go 构建）
│   └── _pep517.py
├── docs/
│   ├── design.md
│   ├── go-cli-sops-design.md          # 本文档
│   ├── SKILL.md
│   └── references/handoff-examples.md
└── scripts/
    ├── pep517_backend.py              # 移除 Cargo 逻辑，统一 CGO_ENABLED=0 go build
    ├── build-wheels.sh
    └── package-skill.sh
```

> **依赖清单（全仓库）**：
> - Relay：`github.com/BurntSushi/toml`、`github.com/nicholas-fedor/shoutrrr`
> - CLI：`filippo.io/age`、`gopkg.in/yaml.v3`、`golang.org/x/crypto`（HKDF，已为 `age` 间接依赖）
> - CLI 参数解析：可用零依赖标准库分层解析或轻量 `github.com/spf13/pflag`（支持标准 POSIX `--flag` 与 `--` 分隔符）。

---

## 6. Go 版安全不变量

1. **进程防转储加固**：CLI 启动即设置 `RLIMIT_CORE = 0`，并在 Linux 上调用 `prctl(PR_SET_DUMPABLE, 0)`，防止崩溃产生 core dump 落盘或同 UID 非 root 进程通过 `ptrace` / `/proc/<pid>/mem` 读取内存。
2. **显式内存擦除与最短驻留期**：
   - 所有私钥（Ed25519 seed、X25519 ephemeral secret、HKDF key、AES key、`SOPS_AGE_KEY`、SOPS Data Key、解密后的明文 secret）全程以 `[]byte` 持有，在 `defer` 中用 `clear(buf)` 覆零；
   - `sops set` 采用「先收新值、最后解锁 `SOPS_AGE_KEY`」顺序，将主私钥在内存中的驻留期压至毫秒级；
   - 因已移除 `--redact`，交接完成（如 `--env` / `--env-all` / `--arg-placeholder` 在 Unix 上可直接 `syscall.Exec` 替换进程，或在 `--stdin` / `--file` 写完后立即 `clear()`）父进程内存中**不再保留任何明文密钥**；
   - 子进程直接继承原生 `stdout` / `stderr`，保留 TTY 语义且不引入额外的管道扫描攻击面。
3. **`--file` / `--file-env` 零痕迹清理**：优先写入 `/dev/shm`（`O_CREATE|O_EXCL|O_WRONLY`，`0600`），写完立即擦除内存缓冲，在正常退出及 `SIGINT`/`SIGTERM` 时先全量覆写 `0x00` 再 `os.Remove`。
4. **`--askpass` 自调用助手**：保留 `main()` 入口第一时间检测 `_OUTSIDER_ASKPASS_SOCK` 与 `_OUTSIDER_ASKPASS_TOKEN` 的设计，Unix Socket 放 `0700` 临时目录、单次消费 token，送出后立即擦除内存中的 secret 缓冲。
5. **无明文 stdout 接口 & 浏览器端闭环建钥**：继续坚持安全红线，CLI 不提供任何输出密钥明文的子命令或开关；新建 `age` 私钥仅在人类浏览器端本地生成并配合防丢确认存入密码管理器，永不进入终端历史或 LLM 上下文。

---

## 7. 实施与验收计划（待启动时按步执行）

1. **阶段 1 — 共享协议层 `internal/proto/`**：合并并补齐 X25519 + HKDF-SHA256 + AES-256-GCM 加解密，跑通 `protocol/test-vectors.json` 全量测试。
2. **阶段 2 — `internal/sopsage/` 引擎**：实现 `age` Data Key 封装、`AES256_GCM` 字段加解密、MAC 校验、`LoadKeys`/`Decrypt`/`Init`/`Set`/`Unset`，并通过与官方 `sops 3.13.3` 的双向互操作测试。
3. **阶段 3 — Go CLI (`internal/cli/` + `cmd/outsider/`)**：实现 `init`/`id`/`doctor`/`run`（Direct + SOPS 模式、`[names.*]` 反查、`--save-name`、5 种单值交接 + 多键 `--env-all`/`--file`，不含 `redact`）、`name {add,ls,set,rm}` 与 `sops {keys,init,set,unset}`，并加上 `RLIMIT_CORE=0` / `PR_SET_DUMPABLE=0` 加固。
4. **阶段 4 — 清理 Rust 代码 & 更新 `uvx` 打包**：移除原 Rust `cli/src` 与 `Cargo.toml`，更新 `scripts/pep517_backend.py`、`cli/_pep517.py`、`relay/_pep517.py`，验证 `uv build` 与 `uvx` 秒级构建。
5. **阶段 5 — Web 按需建钥、更新 Skill 文档与端到端实测**：在 `web/` 增加按需零依赖 `age` 私钥生成与防丢确认（补齐 `web/app.test.mjs` 及 Go `filippo.io/age` 交叉测试）；简化 `docs/SKILL.md` 与 `docs/references/handoff-examples.md`，重新打包刷新 `~/.agents/skills/outsider`，跑全套 `go test -race ./...`、`node --test web/app.test.mjs` 及实机 Telegram/Cloudflare Access 端到端联调。
