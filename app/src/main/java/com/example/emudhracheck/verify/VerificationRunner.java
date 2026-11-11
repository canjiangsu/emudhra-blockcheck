package com.example.emudhracheck.verify;

import com.example.emudhracheck.crypto.LeafCertificateIssuer;
import com.example.emudhracheck.tls.ExceptionClassifier;
import com.example.emudhracheck.tls.LocalTlsServer;
import com.example.emudhracheck.tls.PinnedTrust;
import com.example.emudhracheck.tls.TlsClient;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLContext;

/**
 * 逐个 CA 编排「系统默认握手 + 仅信任根的对照组握手」并给出判定。
 *
 * <p>阻断判定必须同时满足：系统握手因证书原因失败，且对照组成功。
 * 若对照组也失败，说明问题出在本机证书链/签名算法/TLS 栈，归类为错误，绝不误报为系统阻断。</p>
 */
public final class VerificationRunner {

    public interface ClientContextFactory {
        SSLContext create(CaEntry entry) throws GeneralSecurityException;
    }

    public interface RootTrustChecker {
        boolean isTrusted(X509Certificate root) throws GeneralSecurityException;
    }

    public interface Listener {
        void onResult(VerificationResult result, int completed, int total);
    }

    private final ClientContextFactory systemContextFactory;
    private final RootTrustChecker rootTrustChecker;
    private final int handshakeTimeoutMs;
    private final SecureRandom random = new SecureRandom();

    public VerificationRunner(ClientContextFactory systemContextFactory,
            RootTrustChecker rootTrustChecker) {
        this(systemContextFactory, rootTrustChecker, 5000);
    }

    public VerificationRunner(ClientContextFactory systemContextFactory,
            RootTrustChecker rootTrustChecker, int handshakeTimeoutMs) {
        this.systemContextFactory = systemContextFactory;
        this.rootTrustChecker = rootTrustChecker;
        this.handshakeTimeoutMs = handshakeTimeoutMs;
    }

    public List<VerificationResult> run(List<CaEntry> entries, Listener listener) {
        List<VerificationResult> results = new ArrayList<>();
        int total = entries.size();
        for (int i = 0; i < total; i++) {
            if (Thread.currentThread().isInterrupted()) {
                break;
            }
            VerificationResult result = runOne(entries.get(i));
            results.add(result);
            if (listener != null) {
                listener.onResult(result, i + 1, total);
            }
        }
        return results;
    }

    private VerificationResult runOne(CaEntry entry) {
        long started = System.currentTimeMillis();

        boolean rootTrusted;
        try {
            rootTrusted = rootTrustChecker.isTrusted(entry.root);
        } catch (Exception e) {
            return result(entry, VerificationResult.Status.ERROR,
                    "无法读取系统信任库：" + ExceptionClassifier.describe(e),
                    false, false, false, null, null, started);
        }

        X509Certificate leaf;
        PrivateKey leafKey;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"), random);
            KeyPair pair = generator.generateKeyPair();
            leafKey = pair.getPrivate();
            leaf = LeafCertificateIssuer.issue(
                    entry.intermediate, entry.key, pair.getPublic(), random);
        } catch (Exception e) {
            return result(entry, VerificationResult.Status.ERROR,
                    "叶子证书签发/自检失败：" + ExceptionClassifier.describe(e),
                    rootTrusted, false, false, null, null, started);
        }

        TlsClient.Outcome system;
        try {
            system = handshake(leaf, leafKey, entry, systemContextFactory.create(entry));
        } catch (Exception e) {
            system = TlsClient.Outcome.failure(e);
        }

        TlsClient.Outcome control;
        try {
            control = handshake(leaf, leafKey, entry, PinnedTrust.contextTrusting(entry.root));
        } catch (Exception e) {
            control = TlsClient.Outcome.failure(e);
        }

        if (!rootTrusted) {
            String detail = "系统信任库不包含根证书「" + rootName(entry.root)
                    + "」，不据此判定中间 CA 状态。系统握手：" + outcome(system)
                    + "；仅信任该根的对照组：" + outcome(control) + "。";
            return result(entry, VerificationResult.Status.ROOT_UNTRUSTED, detail,
                    false, system.success, control.success, system.protocol, system.cipher, started);
        }

        if (system.success) {
            String detail = "系统默认信任接受了该证书链（" + system.protocol + " / "
                    + system.cipher + "）；对照组同样成功。";
            return result(entry, VerificationResult.Status.NOT_BLOCKED, detail,
                    true, true, control.success, system.protocol, system.cipher, started);
        }

        Throwable certificateCause = ExceptionClassifier.findCertificateCause(system.failure);
        if (certificateCause != null && control.success) {
            String detail = "系统默认信任拒绝证书链：" + ExceptionClassifier.describe(system.failure)
                    + "；仅信任该根的对照组成功（" + control.protocol + " / " + control.cipher
                    + "），可判定为系统层阻断。";
            return result(entry, VerificationResult.Status.BLOCKED, detail,
                    true, false, true, null, null, started);
        }

        if (certificateCause != null) {
            String detail = "系统与对照组都拒绝证书链，无法归因于系统阻断。系统："
                    + ExceptionClassifier.describe(system.failure)
                    + "；对照组：" + ExceptionClassifier.describe(control.failure) + "。";
            return result(entry, VerificationResult.Status.ERROR, detail,
                    true, false, false, null, null, started);
        }

        String detail = "系统握手失败但不属于证书验证错误（网络/内部错误）："
                + ExceptionClassifier.describe(system.failure)
                + "；对照组：" + outcome(control) + "。";
        return result(entry, VerificationResult.Status.ERROR, detail,
                true, false, control.success, null, null, started);
    }

    private TlsClient.Outcome handshake(X509Certificate leaf, PrivateKey leafKey,
            CaEntry entry, SSLContext clientContext) {
        LocalTlsServer.Handle handle = null;
        try {
            handle = LocalTlsServer.start(
                    new X509Certificate[]{leaf, entry.intermediate, entry.root}, leafKey);
            TlsClient.Outcome outcome = TlsClient.handshake(
                    clientContext, handle.port(), handshakeTimeoutMs);
            // 等服务器线程退出，避免后台握手线程残留。
            handle.await(handshakeTimeoutMs);
            return outcome;
        } catch (Exception e) {
            return TlsClient.Outcome.failure(e);
        } finally {
            if (handle != null) {
                handle.close();
            }
        }
    }

    private static String outcome(TlsClient.Outcome outcome) {
        if (outcome.success) {
            return "成功（" + outcome.protocol + " / " + outcome.cipher + "）";
        }
        return "失败：" + ExceptionClassifier.describe(outcome.failure);
    }

    private static String rootName(X509Certificate root) {
        return root.getSubjectX500Principal().getName();
    }

    private static VerificationResult result(CaEntry entry, VerificationResult.Status status,
            String detail, boolean rootTrusted, boolean systemSuccess, boolean controlSuccess,
            String protocol, String cipher, long started) {
        return new VerificationResult(entry.name, status, detail, rootTrusted,
                systemSuccess, controlSuccess, protocol, cipher,
                System.currentTimeMillis() - started);
    }
}
