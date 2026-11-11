# 对外 TLS 验证服务（供其它 APK / 外机连接）

日期：2026-11-11
状态：已批准

## 目标

有些客户端自带信任证书库。把本机变成固定的 TLS 验证端点：其它应用或外机用自己的
TrustManager/CA bundle 连接，如果握手成功，说明客户端接受了由已泄露 eMudhra 中间 CA
签发的链（即其信任配置未阻断）；握手因证书失败则说明客户端拒绝。

## 端口与链

- 固定 8 个端口：`18443 … 18450`，顺序与 8 个中间 CA 一一对应（DV G3B/G3C、EV G3B/G3C、
  OV CS G3B/G3C、OV TLS G3B/G3C）。
- 每个端口用对应中间 CA 私钥签发临时叶子证书（P-256 叶子密钥，SHA-384 with ECDSA），
  链为 `[叶子, 中间 CA, 根]`，有效期 7 天，服务启动时重新签发。
- 叶子 SAN 固定为：`localhost`、`127.0.0.1`、`::1` + 服务启动时本机所有非 link-local
  网卡地址（IPv4/IPv6）。**不支持任意域名、CSR、密钥导出**；网络变化后需重启服务刷新 SAN。

## 服务行为与安全边界

- 默认绑定 `127.0.0.1`，供同机其它 APK 使用；UI 中显式开启“允许局域网访问”后才绑定
  所有接口。
- 前台 Service 常驻，通知栏显示监听状态与“停止服务”；API 33 请求通知权限，
  API 34+ 声明 `specialUse` 类型。
- 局域网模式仅接受回环、私有地址（RFC1918 / ULA / link-local）来源；每个端口串行处理
  连接，握手超时 8 秒、HTTP 请求读取超时 2 秒，完成后立即关闭。
- 握手成功 → 返回最小 HTTP/1.1 200 文本（CA 名称、端口、判定说明）；随后关闭。
  客户端必须使用自己的信任库，不能使用 `curl -k` 等跳过校验的方式。
- 不记录私钥；不写入外部存储；不提供任意签发能力。
- 计数为服务端视角的“握手成功/失败/来源拒绝”，仅作参考；TLS 1.3 下客户端可能在服务端
  握手完成后才拒绝证书，最终结论以客户端为准。

## 结果语义与前提

- 握手成功 ⇒ 客户端信任库接受了该已泄露 CA 签发的链，客户端配置有问题。
- 握手失败（证书类）⇒ 客户端拒绝。但失败也可能是客户端根本不信任 `AAA Certificate
  Services` 根，或客户端没有配置该根；这不是中间 CA 被阻断的证据。使用前应确认客户端
  信任库包含该根。
- 浏览器可能使用自身根库与 CRLSet，与应用自带信任库结论可能不同。

## 组件

| 组件 | 职责 |
| --- | --- |
| `LocalAddresses` | 收集 DNS/IP SAN、展示用地址、来源地址过滤 |
| `ExposedTlsServer` | 纯 Java：签发 8 张叶子证书、绑定端口、串行 accept/握手/HTTP 响应、计数 |
| `ExposedServerState` | 运行状态、绑定模式、端口状态、原子计数（进程内共享） |
| `ExposedVerificationService` | Android 前台 Service，启停服务器与通知 |
| `ExposedServiceActivity` | 启停、LAN 开关、地址/端口/计数展示、复制服务地址 |
| `TlsContexts` | 复用服务端 SSLContext 构建（内存 PKCS12 KeyStore） |
| `LeafCertificateIssuer` | 扩展为可传入 SAN 列表与有效期 |

## UI

- MainActivity 增加“对外验证服务”入口。
- 新页面：启动/停止按钮、LAN 开关（运行中禁用）、当前 IP、8 行端口状态与计数、
  “复制服务地址”、根信任前提与安全警告。

## 测试与验收

- JVM 单测：
  - 固定根客户端握手成功并收到 200/CA 名称；拒绝型客户端握手失败并计数；
  - SAN 含 localhost 与 127.0.0.1；
  - 端口占用时该端口标记错误、其余端口继续；
  - 停止后所有监听关闭。
- 真机（Android 13）：
  - `adb forward` 后从 Mac 连 `127.0.0.1:18443`，`openssl s_client -CAfile aaa.pem`
    成功，错误根/无根失败；
  - LAN 模式从 Mac 连设备 IP，`curl --cacert` 成功、无 CA 失败；
  - 前台通知、停止操作、UI 计数正常。
- 全量 `testDebugUnitTest assembleDebug lintDebug` 通过。
