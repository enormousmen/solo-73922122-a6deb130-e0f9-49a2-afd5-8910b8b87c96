# 出站探测 API（Egress Probe）

运维人员在启用外部回调（webhook）前，需要确认回调地址**可达**且**不会访问禁区**。
本服务提供两类 FastAPI 出站探测接口：

- `POST /api/v1/probe`：多跳 GET/HEAD 探测，逐跳跟随跳转（最多 3 次）；
- `POST /api/v1/probe/head`：**单跳 HTTP/HTTPS HEAD 探测**，用于频繁检查同一回调
  地址。每次都重新解析域名并全量校验白名单；同源且对端仍在本次获准地址中时
  复用空闲连接，减少重复 TCP 建连与 TLS 握手。遇到跳转只返回 `Location`，不跟随。

两类接口都返回**逐跳/单跳状态、DNS 解析地址、实际连接地址与拒绝原因**，用于调整
出口白名单。

## 安全模型（核心保证）

每一跳都完整执行下列流程，跳转目标也不例外：

```
URL 静态校验（不产生流量）
   └─ DNS A 记录查询（只问配置的解析器，绝不用系统 getaddrinfo）
        └─ 全部解析地址逐个过 IPv4 CIDR 白名单
             └─ 全部获准才连接；任一地址在禁区 → 整体拒绝（不返回部分结果）
                  └─ 仅向“检查时已批准的 IP”建 TCP，运行时不再解析 DNS
                       └─ HTTPS 用原域名做 SNI 并验证证书（不可关闭校验）
                            └─ 发送一次请求、读取响应
                                 └─ 3xx 跳转：对 Location 重复整套流程（最多 3 次）
```

由此满足：

| 要求 | 实现方式 |
| --- | --- |
| 仅支持 IPv4 | IPv6 字面量、IPv6 CIDR、AAAA 均拒绝；策略层只接受 `IPv4Address` |
| 启动时配置允许的 CIDR | 环境变量 `ALLOWED_CIDRS`（逗号分隔），非法配置直接拒绝启动 |
| 每跳全部解析地址均获准才连接 | `AddressPolicy.check_resolved` 对完整 A 记录列表做“全或无”判定 |
| 最多跟随 3 次跳转 | `MAX_REDIRECTS=3`（硬上限，启动配置仅允许 0..3） |
| DNS 检查后变化不能进入禁区 | 连接目标固定为校验通过的 IP 字面量，连接阶段不触发任何 DNS |
| 连接重试不能进入禁区 | 重试只在**已批准**的地址集合内逐个尝试，绝不重新解析 |
| 跳转不能进入禁区 | 每个跳转目标重新走“解析→全量校验→连接”，被拒即停 |
| 被拒目标收不到探测请求 | 拒绝发生在任何 socket 创建之前；集成测试与目标访问日志双向验证 |
| HTTPS 按原域名验证证书 | `check_hostname=True`、`CERT_REQUIRED`，SNI/校验均用原域名，无关闭开关 |
| 慢探测不阻塞其他请求 | 全异步 + 单事件循环；并发信号量，满额立即返回 429；单请求总超时 |

### 单跳 HEAD 探测与连接复用（`/api/v1/probe/head`）

| 要求 | 实现方式 |
| --- | --- |
| 减少重复建连与 TLS 握手 | 进程内按 `scheme+host+port` 维护空闲连接池 |
| 每次探测都重新解析域名 | 每次请求都调用 DNS 客户端，不复用旧解析结果 |
| 全部地址通过 CIDR 白名单才发请求 | 沿用 `AddressPolicy.check_resolved` 的“全或无”判定 |
| 空闲连接必须同源 | 池键为 `(scheme, hostname, port)`，跨源、跨端口一律不匹配 |
| 实际对端仍在本次获准地址中才复用 | `acquire` 同时校验记录的对端与 socket 实时 `peername` |
| 新连接只用本次获准地址 | `open_tcp` 的远端固定为已批准 IP 字面量 |
| HTTPS 按原域名验证证书 | 复用的连接在建立时已按原域名握手；新建连接同 HTTPS 多跳探测 |
| 每条连接同时只处理一次探测 | 取用即从池中移除并置 `busy`，独占使用 |
| 收齐最终响应头且允许保活才归还 | 读到最终响应头（跳过 1xx）、`Connection` 未声明 close、且无残留数据 |
| 每进程最多 8 条空闲连接 | `MAX_IDLE_CONNECTIONS`（仅允许 0..8），超出关闭最旧一条 |
| 每条最多空闲 15 秒 | `IDLE_TIMEOUT`（仅允许 (0, 15]），定时器到点主动关闭 |
| 读写失败/超时/取消时关闭连接 | `discard` 立即关闭；`CancelledError` 同样关闭并向上传播 |
| 请求可能已发出则不补发 | 从 `write` 起视为已发出；此后失败只标记 error，不再换地址重试 |
| 沿用总超时与并发上限 | 与 `/api/v1/probe` 共用 `PROBE_OVERALL_TIMEOUT` 与 `MAX_CONCURRENCY` 信号量 |

## 目录结构

```
app/
  probe/            探测服务
    policy.py       IPv4 CIDR 白名单与 URL 静态校验（所有连接决策的唯一入口）
    dns_wire.py     自研 DNS 线协议（RFC1035 子集，查询/应答/压缩指针防护）
    dns_client.py   异步 DNS 客户端（仅向配置的解析器发 A 查询）
    connection.py   固定到已批准 IP 的 TCP 连接 + 强制校验的 TLS
    connection_pool.py  空闲连接池（同源 + 对端复核、容量 8、空闲 15 秒）
    head_probe.py   单跳 HEAD 探测（复用/新建、不跟随跳转、失败不补发）
    http_probe.py   逐跳 HTTP/1.1 探测引擎、跳转规范化与上限
    config.py       环境变量配置（启动时校验）
    main.py         FastAPI 应用（/api/v1/probe、/docs）
  dns_service/      本地可切换解析的 DNS（UDP/53 + HTTP 控制面 profile 热切换）
  targets/          演示目标（HTTP/8080、HTTPS/8443，含各类跳转与访问记录）
  certinit/         生成演示 CA、服务器证书、合并 CA bundle
dns-profiles/       DNS 场景：allowed / swapped / mixed / loop / reuse-b
compose.yaml        一键启动的完整演示环境
tests/              87 个测试（策略、DNS 协议、TLS、跳转、连接复用、并发、API 全链路）
scripts/demo.sh     演示脚本
```

## 快速开始

```bash
docker compose up -d --build
# 探测 API（仅绑定本机回环）
open http://127.0.0.1:8000/docs
```

演示环境网络拓扑（全部 IPv4，静态地址）：

| 网络 | 网段 | 用途 |
| --- | --- | --- |
| `net_dns` | 172.31.0.0/24 | 本地 DNS（172.31.0.53），探测服务唯一使用的解析器 |
| `net_allowed` | 172.31.10.0/24 | 允许目标（172.31.10.10 与 172.31.10.11）——**白名单唯一放行的网段** |
| `net_denied` | 172.31.20.0/24 | 禁止目标（172.31.20.10） |

目标服务同时监听标准端口 `80/443`（供跳转 URL 直接使用）与演示端口
`8080/8443`，HTTP 与 HTTPS 行为一致；可用环境变量
`TARGET_HTTP_PORTS` / `TARGET_HTTPS_PORTS` 覆盖监听端口。

> probe 容器**同时接入** `net_denied`（路由层可达），但白名单不含该网段。
> 这证明拦截来自应用层白名单策略，而不是网络隔离。

### 一键演示

```bash
./scripts/demo.sh
```

## API

### `POST /api/v1/probe`

请求体：

```json
{ "url": "https://example.com/path", "method": "GET" }
```

响应（关键字段）：

```json
{
  "outcome": "blocked",
  "summary": "第 1 跳被策略拒绝: 解析结果包含未获准网段的地址: 172.31.20.10；...",
  "allowed_cidrs": ["172.31.10.0/24"],
  "dns_server": "172.31.0.53:53",
  "max_redirects": 3,
  "hops": [
    {
      "hop": 1,
      "url": "http://forbidden.demo.test/secret",
      "hostname": "forbidden.demo.test",
      "resolved_addresses": ["172.31.20.10"],
      "approved_addresses": [],
      "connected_peer": null,
      "request_sent": false,
      "outcome": "blocked",
      "reject_reason": "解析结果包含未获准网段的地址: 172.31.20.10；..."
    }
  ]
}
```

每跳字段含义：

- `resolved_addresses`：DNS 实际返回的全部 A 记录；
- `approved_addresses`：通过白名单的地址（被整体拒绝时为空）；
- `connected_peer`：**实际**建立 TCP 连接的 `ip:port`（固定为已批准 IP）；
- `tls`：TLS 版本、套件、证书 subject/SAN（HTTPS 时）；
- `request_sent`：是否真的发出了 HTTP 请求（被策略拒绝时恒为 `false`）；
- `outcome`：`ok` / `redirected` / `blocked` / `error`；
- `reject_reason` / `error`：拒绝或失败的具体原因。

辅助接口：`GET /api/v1/policy`（当前白名单、超时与连接池配置）、`GET /healthz`。

### `POST /api/v1/probe/head`

单跳 HEAD 探测，用于高频检查同一回调地址。请求体：

```json
{ "url": "https://www.allowed.demo.test/" }
```

响应：

```json
{
  "requested_url": "http://www.allowed.demo.test/",
  "method": "HEAD",
  "outcome": "ok",
  "summary": "HEAD 探测完成，状态码 200，复用空闲连接（实际对端 172.31.10.10:80）",
  "hop": {
    "hop": 1,
    "url": "http://www.allowed.demo.test/",
    "scheme": "http",
    "hostname": "www.allowed.demo.test",
    "port": 80,
    "resolved_addresses": ["172.31.10.10"],
    "approved_addresses": ["172.31.10.10"],
    "connected_peer": "172.31.10.10:80",
    "connection_reused": true,
    "connection_kept_alive": true,
    "tls": null,
    "request_sent": true,
    "status_code": 200,
    "reason": "OK",
    "location": null,
    "redirect_count": 0,
    "outcome": "ok",
    "reject_reason": null,
    "error": null
  },
  "allowed_cidrs": ["172.31.10.0/24"],
  "dns_server": "172.31.0.53:53",
  "elapsed_ms": 3,
  "pool": { "idle_connections": 1, "max_idle_connections": 8,
            "idle_timeout_seconds": 15.0 }
}
```

单跳字段补充说明：

- `connection_reused`：是否复用了空闲连接（`false` 表示新建 TCP，HTTPS 还包含握手）；
- `connection_kept_alive`：本次连接是否已收齐最终响应头并归还连接池；
- `location`：3xx 响应的 `Location`；**不跟随**，仅单跳返回；
- `outcome`：`ok` / `redirected` / `blocked` / `error`（总超时返回 HTTP 408）；
- 请求可能已发出后的读写失败不会补发，错误信息中会注明“按策略不补发”。

## 演示场景与 DNS profile 切换

本地 DNS 的解析数据按 profile 组织，可热切换：

```bash
# 查看当前 profile 与全部解析数据
curl http://127.0.0.1:8053/profiles
# 切换
curl -X POST http://127.0.0.1:8053/profiles/switch \
  -H 'Content-Type: application/json' -d '{"profile":"swapped"}'
```

| profile | 演示点 |
| --- | --- |
| `allowed` | 正常解析到允许网段 |
| `swapped` | 同名域名从允许地址换到禁止地址（**检查后换址 / DNS rebinding**） |
| `mixed` | 一次应答同时含允许与禁止地址，验证“全部获准才连接” |
| `loop` | 连环 307 跳转，验证 3 次跳转上限 |
| `reuse-b` | `www.allowed.demo.test` 从 172.31.10.10 切到另一台获准目标 172.31.10.11，演示**同址复用 / 换址重连** |

### 连接复用演示（HEAD）

`scripts/demo.sh` 末尾会自动演示，也可手动执行：

```bash
# profile=allowed：首次新建连接，第二次复用同一空闲连接
curl -sS -X POST http://127.0.0.1:8000/api/v1/probe/head \
  -H 'Content-Type: application/json' -d '{"url":"http://www.allowed.demo.test/"}'
# profile=reuse-b：同名域名换到 172.31.10.11，必须重新建连
curl -sS -X POST http://127.0.0.1:8053/profiles/switch \
  -H 'Content-Type: application/json' -d '{"profile":"reuse-b"}'
curl -sS -X POST http://127.0.0.1:8000/api/v1/probe/head \
  -H 'Content-Type: application/json' -d '{"url":"http://www.allowed.demo.test/"}'
```

预期：两次响应 `hop.connected_peer` 分别为 `172.31.10.10:80` 与
`172.31.10.11:80`，`connection_reused` 从 `true` 变为 `false`（换址后旧连接不会
被错用），随后再探测同一新地址又变为 `true`。

## 配置项（探测服务环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `ALLOWED_CIDRS` | （必填） | 逗号分隔的 IPv4 CIDR 白名单 |
| `DNS_SERVER` / `DNS_PORT` | 127.0.0.1 / 53 | 唯一允许使用的解析器（IP 字面量） |
| `DNS_TIMEOUT` / `DNS_RETRIES` | 3.0 / 1 | DNS 单次超时与重试次数 |
| `CA_BUNDLE` | 系统信任库 | 信任 CA 文件（演示环境为系统 CA + 演示 CA 合并） |
| `CONNECT_TIMEOUT` / `TLS_TIMEOUT` / `READ_TIMEOUT` | 5 / 8 / 10 秒 | 各阶段超时 |
| `MAX_REDIRECTS` | 3 | 跳转上限，仅允许 0..3 |
| `MAX_CONCURRENCY` | 64 | 在飞探测并发上限（两类探测共用），超出返回 429 |
| `PROBE_OVERALL_TIMEOUT` | 30 | 单请求总超时，超时返回 408 |
| `MAX_IDLE_CONNECTIONS` | 8 | 每进程空闲连接上限，仅允许 0..8 |
| `IDLE_TIMEOUT` | 15 | 每条空闲连接最长空闲秒数，仅允许 (0, 15] |

## 测试

```bash
pip install -r requirements.txt pytest pytest-asyncio httpx
pytest -q
```

87 个测试覆盖：CIDR/URL 策略、DNS 编解码与压缩指针环路、全链路探测、
混合解析整体拒绝、检查后换址、跳转上限/跳禁区/非 HTTP 协议、HTTPS 证书
主机名校验与不受信证书拒绝、慢探测并发非阻塞、429 保护、API 层。

其中 `test_head_probe.py` / `test_api_head.py` 覆盖单跳 HEAD：同源复用、跨源/
跨端口不复用、DNS 换址后重连、跳转仅返回 Location、`Connection: close` 不入池、
超时/取消关闭连接、请求已发出不补发、空闲容量 8 与 15 秒过期。

## 设计边界与说明

- 探测只实现 GET/HEAD、HTTP/1.1，读取响应体有 64KB 上限，仅用于连通性判断；
- 单跳 HEAD 探测不跟随跳转；连接池只保存 HTTP/1.1 keep-alive 连接，不复用 HTTP/2；
- 空闲连接以 `(scheme, hostname, port)` 为键，跨源绝不复用；HTTPS 复用同一连接时
  SNI 与证书校验仍针对该源的原域名（证书在首次握手时已按原域名验证）；
- 不跟随 cookie、不发送请求体、不执行任何页面脚本；
- DNS 仅做 A 记录查询（AAAA 不存在即天然 IPv4-only）；
- 演示 CA 与证书仅用于本地/compose 演示，生产环境应使用真实 PKI 并通过
  `CA_BUNDLE` 指定信任根。
