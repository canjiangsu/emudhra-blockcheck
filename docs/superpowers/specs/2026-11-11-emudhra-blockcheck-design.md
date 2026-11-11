# 单机闭环验证 Android 是否阻断 8 个 eMudhra 中间 CA 公钥

日期：2026-11-11
状态：已批准（方案 A）

## 目标

在一台 Android 设备上，不依赖外网、不需要第二台机器，验证本机 Android 系统默认 TLS 信任路径是否拒绝由 8 个已泄露 eMudhra 中间 CA 签发的证书链。

对每个中间 CA：

1. 在本机 `127.0.0.1` 上启动临时 TLS 服务端；
2. 用该中间 CA 私钥签发一张 `CN=localhost` 叶子证书，链为 `[叶子, 中间 CA, 根]`；
3. 用**未设置自定义 TrustManager** 的客户端握手；
4. 再用一个**只信任对应根证书**的对照组客户端握手，证明证书链和本机 TLS 栈本身可用；
5. 汇总判定：阻断生效 / 未阻断 / 根证书不受信任 / 网络或内部错误。

## 关键决策

- **零第三方依赖**：自实现 PEM 解析、SEC1→PKCS#8 转换、最小 DER 编码器与 X.509 叶子证书签发；仅测试依赖 JUnit。
- **对照组是闭环的核心**：系统拒绝且对照组成功，才判“阻断生效”；两者都失败判内部错误，避免把自身缺陷误报为系统阻断。
- **对照组必须绕过平台黑名单**：Android 的 Conscrypt `TrustManagerImpl` 会查询 `CertBlocklistImpl`。若对照组使用平台 `TrustManagerFactory`，系统因黑名单拒绝时对照组也会拒绝，无法区分“阻断生效”和“内部错误”。因此对照组使用自实现 `X509TrustManager` + `CertPathValidator("PKIX")`，只信任指定根。
- 纯 Java、`android.app.Activity` + `ListView`，无 AndroidX；minSdk 21，compileSdk/targetSdk 34。
- 独立 git 仓库；证书/私钥内置 assets，来源 <https://github.com/Fluepke/emudrahahahahaha.git>。

## 组件

| 组件 | 职责 |
| --- | --- |
| `Pem` | 按 `-----BEGIN X-----` 分块，纯 Java Base64 解码 |
| `Der` | 最小 ASN.1 DER 写入/读取（SEQUENCE、INTEGER、OID、字符串、上下文标签等） |
| `PemKeys` | 解析 `PRIVATE KEY`（PKCS#8）与 `EC PRIVATE KEY`（SEC1），SEC1 包装为 PKCS#8 后交给 `KeyFactory("EC")` |
| `LeafCertificates` | 生成 P-256 叶子密钥，用中间 CA 私钥按 `SHA-384 with ECDSA` 签发叶子证书并自检签名 |
| `ChainTrust` | 系统根信任检查（`getAcceptedIssuers` 字节比对）；用指定根构建纯 PKIX 对照组 `SSLContext`（不经过平台`TrustManagerImpl`，绕过黑名单） |
| `LocalTlsServer` | 仅绑定 `127.0.0.1` 的临时 `SSLServerSocket`，接受一次握手后关闭 |
| `TlsClient` | 用给定 `SSLContext` 连接，记录协议/套件或异常 |
| `ExceptionClassifier` | 遍历 cause 链，识别证书类失败 |
| `VerificationRunner` | 逐个 CA 编排系统/对照两次握手并分类 |
| `ResultFormatter` | 生成可复制/分享的纯文本结果 |
| `AssetsCaLoader` | 读取 assets，按 issuer/subject 动态匹配根并校验中间 CA 签名 |
| `MainActivity` | 简单 UI、后台串行执行、进度与结果颜色 |

## 叶子证书内容

- Subject: `CN=localhost`
- Issuer: 中间 CA 证书的 subject DER（逐字节复用，保证链匹配）
- 有效期：当前时间前 1 小时 至 后 1 天
- SAN: `dNSName=localhost`、`iPAddress=127.0.0.1`
- 扩展：`BasicConstraints critical CA:FALSE`、`KeyUsage critical digitalSignature`、`ExtendedKeyUsage serverAuth`
- 签名算法：`1.2.840.10045.4.3.3`（ecdsa-with-SHA384）

## 判定规则

UI 只展示四种状态：`BLOCKED`（阻断生效）、`NOT_BLOCKED`（未阻断）、`ROOT_UNTRUSTED`（根证书不受信任）、`ERROR`（网络或内部错误）。后两种为 `ERROR` 的子原因，写入详情。

1. 系统信任库不包含对应根证书 → `ROOT_UNTRUSTED`，不计入阻断统计。
2. 系统默认握手成功 → `NOT_BLOCKED`。
3. 系统握手失败、cause 链含 `CertificateException` / `CertPathValidatorException` / `CertificateRevokedException`（按类名识别，兼容 API 21），且对照组成功 → `BLOCKED`。
4. 上述证书失败但对照组也失败 → `ERROR`（子原因：内部错误）。
5. 非证书类失败 → `ERROR`（子原因：网络错误，含对照结果说明）。

## 安全

- 私钥仅从 assets 读取用于本机签名，不写外部存储、不打日志、不监听非回环地址。
- APK 内含已泄露的测试私钥，README 明确禁止公开分发或用于任何真实服务。
- 所有 socket、SSLContext 在 finally 中释放；单次 accept/connect/handshake 均有超时（5 秒级）。

## 测试与验收

- JVM 单元测试（使用真实 8 组证书/私钥）：
  - 每个私钥可签名且能被对应中间 CA 公钥验签；
  - 每张叶子证书签名有效、SAN、有效期、扩展正确；
  - `PKIX` 证书路径校验通过（根为 TrustAnchor）；
  - 运行器在“信任根 / 恶意拒绝 / 根不受信任”三种环境下的分类正确；
  - 异常分类器覆盖证书类与非证书类。
- `./gradlew testDebugUnitTest assembleDebug` 成功，产出 APK。
- 不启动模拟器（用户选择）；由用户安装到目标设备实测。
- 交付 README：证书放置、构建、安装、结果解读与限制。

## 系统黑名单集成（2026-11-11 更新）

- AOSP 中 `external/conscrypt/Android.bp` 的 `conscrypt_java_files` 实际编译
  `repackaged/common` + `repackaged/platform`；设备 APEX 的 `CertBlocklistImpl` 来自
  `external/conscrypt/repackaged/platform/...`，而不是 `external/conscrypt/platform/...`。
- 8 个 hash 为 `SHA-1(PublicKey.getEncoded())`（SPKI DER），40 位十六进制，与
  `CertBlocklistImpl.isPublicKeyBlockListed` 一致。
- 运行时补充路径：`/data/misc/keychain/pubkey_blacklist.txt`（逗号分隔，0644，
  SELinux 标签 `keychain_data_file`），用于不重建镜像的快速验证。
- Android 10+ Conscrypt 在 `com.android.conscrypt` APEX；重建后必须连同 APEX 刷入，
  设备上的 `/apex/com.android.conscrypt/javalib/conscrypt.jar` 必须包含新 hash。
- 真机验证（Android 13 userdebug，2026-11-11）：写入动态黑名单后，系统握手抛出
  `CertificateException: Certificate blocklisted by public key`；修复对照组后 APK 显示
  8 项全部“阻断生效”。

## 结果解读限制

本应用验证的是 Android 平台默认 `X509TrustManager` 路径，不等同于浏览器（Chrome 的 CRLSet/Revocation 检查）。系统不默认做 CRL/OCSP 检查时，“未阻断”只代表本机系统 TLS 栈当前接受该链。README 将明确说明。
