# 数据面用户、限速、流量与追踪设计

本文档定义数据面中动态用户、用户级限速、流量计量和会话追踪的设计。控制面负责远端 HTTP API 拉取、节点注册、持久化、重试和上报传输；数据面负责进程内高速查表、认证结果、限速状态、字节计数和连接生命周期事件。

## 目标

- 不重启监听器即可更新用户列表。
- 所有入站协议都接入同一套用户模型做认证。
- 按用户粒度跨连接、跨协议施加限制。
- 生成流量增量，由控制面批量上报。
- 给每条连接日志和事件附加稳定的 `session_id` 与 `user_id`。

## 非目标

- 数据面不调用主控 HTTP API。
- 数据面不持久化计费状态。
- 数据面不决定套餐、账期或配额重置规则。
- 数据面不拥有 Tokio runtime。

## 运行时边界

控制面嵌入本 crate，并通过少量 API 驱动数据面：

```rust
let mut data_plane = shoes::DataPlane::start(configs).await?;

data_plane.update_users(users, revision)?;

let deltas = data_plane.traffic_collector().snapshot_and_reset();

data_plane.reload(new_configs).await?;
data_plane.shutdown().await;
```

推荐的控制面循环：

1. 从主控 API 拉取节点配置和用户列表。
2. 把远端模型转换为 `Vec<UserProfile>` 和 `Vec<Config>`。
3. 调用 `DataPlane::update_users(users, revision)`。
4. 只有监听器或协议配置变化时才调用 `DataPlane::reload(configs)`。
5. 每隔几秒 flush `TrafficDelta`，失败时由控制面重试。

用户更新和监听器重载刻意分开。大多数用户变更不应该重启监听 socket。

## 用户模型

`UserProfile` 是面向控制面的用户对象：

- `id`：来自主控的稳定计费和统计 key。
- `name`：可选展示名，用于日志。
- `enabled`：禁用用户会拒绝新认证。
- `credentials`：按协议区分的凭据集合。
- `limits`：用户级带宽和连接限制。
- `tags`：控制面可选标签。

凭据会规范化为查表 key：

- VLESS/VMess：UUID。
- Trojan/Hysteria2/AnyTLS/Snell/Shadowsocks：密码或派生服务端 key。
- TUIC：UUID 加密码。
- HTTP/SOCKS/Mixed/NaiveProxy：用户名加密码。

第一版会把凭据以字符串形式保存在内存中，因为当前协议 handler 已经按字符串处理凭据。后续加固时，应在协议允许的情况下把明文密码索引替换成协议特定 hash。

## 动态快照

数据面维护一个近似原子替换的快照：

```text
UserRegistry
  -> Arc<UserSnapshot>
       revision
       users: user_id -> UserRuntime
       credentials: CredentialKey -> user_id
```

更新时先完整构建新快照，再替换旧快照。新连接看到最新 revision；老连接继续持有自己的 `AuthenticatedUser`，直到连接结束。除非后续控制面策略明确要求踢下线，否则不主动杀老连接。

构建快照时会拒绝重复凭据 key，避免认证结果歧义，并让用户列表错误在影响流量前暴露出来。

## 认证契约

每个协议 handler 最终都应该返回：

```rust
AuthenticatedUser {
    user_id,
    revision,
    runtime,
}
```

协议模块不应该持有用户策略。它只负责解析客户端凭据，然后查询：

```rust
registry.authenticate(ProtocolKind::Vless, uuid)
```

过渡期内，可以先把 YAML 里的静态凭据转换成监听器局部的一用户快照；等各协议完成改造后，再统一切到动态用户查表。

## 限速

默认使用用户级限制：

- `uplink`：客户端到远端。
- `downlink`：远端到客户端。
- `max_connections`：该用户活跃会话数。
- `quota_bytes`：可选硬配额，先由控制面根据上报量封禁或调整策略，后续也可在数据面内强制。

第一版限速器是按方向区分的 token bucket。它与协议无关，可用于 TCP stream、UDP message stream、XUDP、UoT 和 QUIC handler。后续 stream wrapper 应在转发字节前调用限速器。

推荐执行顺序：

1. 认证成功，得到 `AuthenticatedUser`。
2. `AuthenticatedUser::open_session()` 检查 `enabled` 和 `max_connections`。
3. 转发层用计量和限速 adapter 包装 stream/message。
4. session guard 在 drop 时递减活跃连接数。

## 流量计量

数据面只记录计数器：

- 上传字节
- 下载字节
- 新建连接数
- 活跃连接数

控制面周期性调用 `snapshot_and_reset()` 获取增量。远端 HTTP 上报、失败重试、本地 WAL、幂等 key 都由控制面负责。

建议上报间隔为 5 到 10 秒。高流量节点建议按节点批量上报，每个活跃用户一条 item。

## 会话追踪

每条入站连接都应该创建一个 `SessionContext`：

- `session_id`：进程内单调递增 ID。
- `user_id`：认证成功前为空。
- `protocol`：入站协议。
- `client_addr`：可用时记录对端 socket 地址。
- `target`：协议解析后的目标地址。
- `started_at_ms`：连接开始的 wall-clock 时间戳。

当前项目仍使用 `log`。目标状态是迁移到 `tracing` span：

```text
session_id=123 user_id=u_1 protocol=vless client=1.2.3.4 target=example.com:443
```

迁移到 `tracing` 之前，先把 session 数据附着到结构化事件对象，并在关键生命周期点通过现有 `log` 输出。

## 实施阶段

### 第一阶段：运行时基础设施

- 新增 `account` 模块：用户 profile、凭据索引、快照和认证结果。
- 新增 `telemetry` 模块：流量计数器和 delta。
- 新增 `session` 模块：session id 和上下文。
- 让 `DataPlane` 持有 `DataPlaneRuntime`，并暴露用户更新和流量快照 API。

### 第二阶段：TCP 公共路径

- 把 `DataPlaneRuntime` 传入 TCP server handler factory。
- 在 `process_stream` 中附加 `SessionContext`。
- 在 TCP 公共 copy 路径外包一层 metered stream wrapper。
- 上报连接打开和关闭增量。

当前状态：

- `DataPlaneRuntime` 已贯穿 `DataPlane -> start_servers -> TCP/QUIC server -> create_tcp_server_handler`。
- TCP accept 后已经创建 `SessionContext`。
- `TcpServerSetupResult` 已预留 `authenticated_user`，普通 TCP VLESS/VMess 已开始填充认证用户。
- TCP 转发路径已能在存在 `AuthenticatedUser` 时自动创建用户 session guard、连接计数 guard，并用 metered stream 记录 upload/download。
- 下一步需要继续把 HTTP、SOCKS5/Mixed、Trojan 等协议接入同一套认证结果。

### 第三阶段：协议认证接入

按认证逻辑隔离程度逐步把静态认证替换成 registry lookup：

当前状态：

- 已从 VLESS 和 VMess 开始接入动态用户认证。
- `UserSnapshot` 已支持 UUID 凭据规范化、按协议判断是否存在动态凭据、按协议枚举候选凭据。
- 普通 TCP VLESS：如果用户快照中存在 VLESS 凭据，则只查动态用户表；如果没有动态 VLESS 凭据，则回退原 YAML 静态 UUID，保持旧配置可用。
- 普通 TCP VMess：如果用户快照中存在 VMess 凭据，则遍历动态 VMess UUID 候选解 AEAD auth id；认证成功后把对应 `AuthenticatedUser` 返回给 TCP 公共路径。
- 普通 TCP Shadowsocks：如果用户快照中存在 Shadowsocks 凭据，则为每个启用用户构造候选 key；标准 AEAD 用首个加密长度块试 key，AEAD2022 用加密固定请求头试 key。认证成功后连接固定使用该用户 key。
- 普通 TCP VLESS/VMess/Shadowsocks 认证成功后，TCP 公共路径已经可以按用户创建 session guard、连接计数 guard，并记录上传/下载字节。

剩余限制：

- Vision VLESS 仍走 TLS/Reality 内部的静态 UUID 路径，尚未接入动态用户表。
- VLESS/VMess/Shadowsocks 命中 h2mux 后会返回 `AlreadyHandled` 并在协议内启动 h2mux session，暂时不会经过 TCP 公共计量 wrapper。
- QUIC server 已能拿到 `DataPlaneRuntime`，但 QUIC stream 还没有把 `authenticated_user` 接到 session、限速和流量计量。
- UDP/XUDP/UoT 当前只在连接级打开用户 session，逐包/逐 message 的字节计量和限速留到第四阶段。

后续接入顺序：

1. HTTP
2. SOCKS5 和 Mixed
3. Trojan
4. Vision VLESS
5. AnyTLS 和 NaiveProxy
6. Hysteria2 和 TUIC
7. Snell

### 第四阶段：UDP 与多路复用

- 计量并限速 `AsyncMessageStream`、targeted UDP、session UDP、XUDP 和 UoT。
- 把认证用户传播到 h2mux session 和 QUIC stream。

### 第五阶段：控制面集成

- 新控制面 crate 轮询主控 HTTP API。
- 控制面把用户转换成 `UserProfile`，把节点配置转换成 `Config`。
- 控制面周期性 flush 流量增量。
- 控制面负责持久化重试和节点健康上报。
