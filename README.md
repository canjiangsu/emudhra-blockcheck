# eMudhra CA 阻断验证

在一台 Android 设备内**闭环**验证：Android 系统默认 TLS 信任路径是否会拒绝由 8 个已泄露
eMudhra 中间 CA 签发的证书链。

> ⚠️ **仅用于经授权的安全测试。** 本工程与生成的 APK 内含已泄露的中间 CA 私钥
> （弱整数私钥，已公开）。它们只应用于你自己拥有或获得明确许可的设备/环境，
> **不得**用于任何真实服务、冒充、公开分发或生产用途。请勿把 APK 上传到公开应用商店。

---

## 原理

对每个中间 CA 执行两次本机回环 TLS 握手：

1. 生成一次性 P-256 叶子密钥，用该中间 CA 私钥签发 `CN=localhost` 叶子证书
   （签名算法 `SHA-384 with ECDSA`，适应 P-384 中间 CA）。
2. 在本机 `127.0.0.1` 的随机端口启动 `SSLServerSocket`，链为
   `[叶子证书, 中间 CA, 根证书]`。
3. **系统测试**：客户端使用 `SSLContext.getInstance("TLS")` 且**不设置自定义
   TrustManager**，完全依赖系统默认信任库。
4. **对照组**：同一张叶子证书，客户端只信任对应根证书，走**自实现的纯 PKIX 校验**
   （`CertPathValidator`），**刻意绕开 Conscrypt 的 `TrustManagerImpl`，因此不受系统证书
   黑名单影响**。

判定规则：

| 状态 | 条件 | 含义 |
| --- | --- | --- |
| 阻断生效（绿） | 系统握手因证书原因失败，且对照组成功 | 系统层确实拒绝该链 |
| 未阻断（红） | 系统默认握手成功 | 本机系统 TLS 栈当前接受该链 |
| 根证书不受信任（橙） | 系统 `getAcceptedIssuers()` 不含对应根 | 无法据此判断中间 CA，不计入阻断 |
| 错误（灰） | 非证书失败，或系统与对照组都失败 | 本机链/算法/网络问题，绝不误报为阻断 |

**为什么需要对照组**：如果叶子证书、签名算法或本机 TLS 栈本身有问题，系统握手也会失败。
只有对照组成功时，才能把系统失败归因为“系统层阻断”。

**为什么对照组不能用系统 TrustManager**：Android 的 Conscrypt 在 `TrustManagerImpl` 里
查询证书公钥黑名单（`CertBlocklistImpl`）。如果对照组也走平台 `TrustManagerFactory`，
系统因黑名单拒绝时对照组会同样拒绝，工具只能报“错误”，无法得出“阻断生效”。因此
`PinnedTrust` 直接调用 `CertPathValidator`（PKIX）并只信任指定根，刻意不查询平台黑名单。

---

## 工程结构

```
emudhra-blockcheck/
├── app/src/main/
│   ├── assets/
│   │   ├── certs/                  # 8 组中间 CA 证书 (.pem) + 私钥 (.key)
│   │   └── roots/                  # AAA Certificate Services / emSign ECC Root CA - G3
│   ├── java/com/example/emudhracheck/
│   │   ├── crypto/                 # PEM 解析、DER、SEC1→PKCS#8、叶子证书签发
│   │   ├── tls/                    # 本机 TLS 服务端/客户端、系统信任、对照组、异常分类
│   │   ├── verify/                 # 资产加载、批量编排、结果模型与文本导出
│   │   ├── MainActivity.java       # 单 Activity UI
│   │   └── ResultAdapter.java
│   └── res/
├── app/src/test/                   # JVM 单元测试（使用真实 8 组证书）
├── docs/superpowers/specs/         # 设计规格
└── gradle/wrapper/                 # Gradle 8.5
```

**零第三方运行时依赖**：自实现 PEM/Base64、最小 ASN.1 DER、SEC1 转 PKCS#8 与
X.509 v3 叶子证书签发；TLS 使用原生 `SSLSocket`/`SSLServerSocket`，无 AndroidX。

---

## 证书与私钥来源

8 组中间 CA 证书/私钥与两个根证书已内置在 `app/src/main/assets/`，来源：

<https://github.com/Fluepke/emudrahahahahaha.git>

assets 中的文件名已改为无空格的 slug；根文件 `75680d2e.0` →
`roots/aaa-certificate-services.pem`（本批 8 个中间 CA 的实际签发根），`b74d2bd5.0` →
`roots/emsign-ecc-root-ca-g3.pem`（保留用于 issuer/subject 动态匹配）。

程序不写死中间 CA 与根的对应关系：按“中间 CA 的 issuer == 根的 subject”匹配，并用根公钥
验证中间 CA 签名。

---

## 构建

要求：Android SDK Platform 34、Build-Tools 34、JDK 17+（本仓库使用 Android Studio 的
JBR 21 验证）、Gradle 8.5（wrapper 已包含）。

### Android Studio

直接 `Open` 本目录，等待 Gradle Sync，选择设备后运行 `app`。

### 命令行

```bash
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
./gradlew assembleDebug
```

产物：`app/build/outputs/apk/debug/app-debug.apk`。

如果本机到 Google Maven / Maven Central 的网络受限，但依赖已缓存，可加 `--offline`：

```bash
./gradlew --offline assembleDebug
```

`local.properties` 中的 `sdk.dir` 指向本机 Android SDK，已被 `.gitignore` 忽略。

---

## 安装与使用

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

1. 打开 “eMudhra CA 阻断验证”；
2. 点击 **开始验证**（对 8 个中间 CA 串行执行，通常数秒内完成）；
3. 结果列表每行显示 CA 名称、状态（颜色区分）与简短原因；
4. **复制结果** / **分享** 导出纯文本，包含时间、设备型号、Android 版本、安全补丁、
   TLS 协议/套件、异常链与对照组结果。

应用只连接 `127.0.0.1`，不访问外部网络；`INTERNET` 权限仅用于回环 socket。

---

## 结果解读

- **阻断生效**：系统默认 TrustManager 在证书校验阶段拒绝该链，且仅信任该根的对照组成功。
  说明当前系统（系统信任库/Conscrypt/ROM 更新）确实阻断或不再信任该中间 CA。
- **未阻断**：系统默认信任接受了该链。**注意**：Android 默认 TrustManager 默认不做
  CRL/OCSP 检查；浏览器（Chrome CRLSet）仍可能吊销该 CA。“未阻断”只代表本机系统 TLS
  栈的结论，不等同于浏览器结论。
- **根证书不受信任**：系统信任库不含对照组根证书（如 AAA 根被移除/定制 ROM），
  连接会先在根环节失败，无法归因到中间 CA，因此单独标记、不计入阻断统计。
- **错误**：网络/超时/本机证书链构建失败，或系统与对照组都失败。详情会同时给出两次
  握手的结果，便于排查，避免误报。

底部脚注与导出文本都会再次提示“结果不代表浏览器 CRLSet/吊销检查结论”。

---

## 测试

```bash
./gradlew testDebugUnitTest
```

17 个 JVM 单元测试，全部使用 `app/src/main/assets` 中的**真实** 8 组证书/私钥：

- `PemTest`：带注释的 `.0` 根文件、多 PEM 块、SEC1 私钥块解析；
- `CaMaterialTest`：8 个中间 CA 与根匹配、根验签通过；每个 SEC1 私钥签名可被对应
  中间 CA 公钥验签（证明私钥与证书匹配）；
- `LeafCertificateTest`：对每个 CA 签发叶子证书，校验签名、issuer/subject、SAN
  （`localhost` + `127.0.0.1`）、有效期、BasicConstraints/KeyUsage/EKU，并执行
  `PKIX` 证书路径校验；
- `VerificationRunnerTest`：真实本地 TLS 握手下，验证“系统信任 / 系统拒绝+对照成功 /
  根不受信任 / 本地链错误”四种判定，以及 JVM 默认系统 TrustManager 代码路径；
- `ExceptionClassifierTest`：`CertificateException`、`CertPathValidatorException`、
  `CertificateRevokedException`、深层 cause 链、网络/主机名异常；
- `ResultFormatterTest`：汇总与导出文本。

已验证（本机，JBR 21 + Gradle 8.5 + AGP 8.2.2）：

```text
./gradlew --offline testDebugUnitTest assembleDebug lintDebug
# 17 tests passed, BUILD SUCCESSFUL, lint issues: 0
```

> 本项目按需求仅做构建与 JVM 单元测试，未启动模拟器；真机结果取决于该设备的系统
> 版本与信任库更新状态。

---

## 关键实现说明

- **PEM/私钥**：Android 5.0 没有 `java.util.Base64`（API 26 才加入），因此自带
  Base64 解码；`EC PRIVATE KEY`（SEC1）被包进 PKCS#8 `PrivateKeyInfo` 后交给
  `KeyFactory("EC")`，兼容 PKCS#8 与 SEC1 两种 PEM。
- **叶子证书**：issuer 直接复用中间 CA 证书 subject 的 DER，保证链逐字节匹配；
  SAN 同时包含 DNS 与 IP；签发后立即用中间 CA 公钥验签，DER 编码错误会立即暴露。
- **TLS 服务端**：只 bind `127.0.0.1`，端口 0 由系统随机分配，只 accept 一次，
  握手后立即关闭；accept/连接/握手均有超时。
- **系统测试**：`SSLContext.init(null, null, null)`，不设置自定义 TrustManager。
- **对照组**：自实现 `X509TrustManager`，用 `CertPathValidator("PKIX")` 只信任对应根；
  刻意不经过 Conscrypt `TrustManagerImpl`，从而不受系统证书黑名单影响。
- **异常判定**：遍历 cause 链寻找 `CertificateException` /
  `CertPathValidatorException` / `CertificateRevokedException`（按类名识别，兼容 API 21）。
- **资源释放**：socket 在 `finally` 中关闭；Activity 销毁时中断后台任务。

---

## 在定制 Android 系统上启用证书公钥黑名单

如果是要在系统镜像里内置阻断（本工具的目标场景），注意 AOSP 的 Conscrypt 有两份源码：

| 路径 | 作用 |
| --- | --- |
| `external/conscrypt/platform/.../CertBlocklistImpl.java` | 上游源码，供 `srcgen/generate_android_src.sh` 生成 `repackaged/` |
| `external/conscrypt/repackaged/platform/.../CertBlocklistImpl.java` | **Android.bp 实际编译的副本**（`com.android.conscrypt` APEX） |

因此 8 个公钥 hash 必须加在 **`repackaged/platform/...`** 这份里；只改 `platform/...`
不会进入设备镜像（除非之后重新跑 srcgen）。hash 格式为
`SHA-1(PublicKey.getEncoded())`，即 SPKI DER 的 SHA-1，40 位小写十六进制，与
`CertBlocklistImpl.isPublicKeyBlockListed` 的实现一致。

快速验证（不重建镜像，userdebug + root）：

```bash
# 文件不存在时创建；逗号分隔；0644；SELinux 标签 keychain_data_file
adb root
adb shell 'echo "<hash1>,<hash2>,..." > /data/misc/keychain/pubkey_blacklist.txt'
adb shell 'chmod 644 /data/misc/keychain/pubkey_blacklist.txt'
adb shell 'chcon u:object_r:keychain_data_file:s0 /data/misc/keychain/pubkey_blacklist.txt'
```

`CertBlocklistImpl.getDefault()` 会把该文件内容追加到内置列表，进程重启后生效。
系统镜像内置验证时应删除该文件：

```bash
adb root && adb shell rm /data/misc/keychain/pubkey_blacklist.txt
```

Android 10+ 的 Conscrypt 位于 `com.android.conscrypt` APEX 中；重建后必须把更新后的
APEX 一起刷入（通常在 system/super 镜像内），仅 `adb sync` framework 或只重编
`conscrypt` 模块而未刷机不会改变设备上的运行时代码。可在设备上拉取
`/apex/com.android.conscrypt/javalib/conscrypt.jar` 并检查其中是否出现新 hash 来确认。

## 已知限制

- 只验证平台默认 `X509TrustManager`，不覆盖浏览器专用 CRLSet、CT、OCSP 等机制。
- 对照组绕过平台黑名单是刻意设计，只证明证书链在密码学/时间/用途上有效，不代表
  平台没有其他策略（如 CT）会拒绝。
- Android 默认不做吊销检查时，“未阻断”可能只是系统栈未检查，不代表证书仍然可信。
- 根信任预检查以字节匹配为主，subject + 公钥匹配为兜底；定制系统可能有特殊行为。
- `targetSdk 34`，Android 7+ 默认不信任用户安装的 CA；本工具反映的是系统信任库，
  不是用户 CA 或 Magisk 模块注入后的环境。
- 叶子证书每次运行重新生成（P-256 密钥、1 天有效期），不复用、不落盘。
- APK 内包含泄露私钥，任何人解包均可提取；仅限授权测试使用。

---

## 参考

- Cloudflare：<https://blog.cloudflare.com/emudhra-certificate-compromise/>
- 社区测试站：<https://emudhra.we-have-a-problem.com/>
