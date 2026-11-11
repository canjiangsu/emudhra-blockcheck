package com.example.emudhracheck;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.example.emudhracheck.crypto.Pem;
import com.example.emudhracheck.tls.PinnedTrust;
import com.example.emudhracheck.tls.SystemTrust;
import com.example.emudhracheck.verify.CaEntry;
import com.example.emudhracheck.verify.VerificationResult;
import com.example.emudhracheck.verify.VerificationRunner;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.junit.Test;

/** 端到端驱动真实的本地 TLS 握手，验证四种判定的分类逻辑。 */
public class VerificationRunnerTest {

    @Test
    public void reportsNotBlockedWhenSystemTrustAcceptsChain() throws Exception {
        VerificationRunner runner = new VerificationRunner(
                entry -> PinnedTrust.contextTrusting(entry.root),
                root -> true);

        List<VerificationResult> results = runner.run(twoEntries(), null);

        assertEquals(2, results.size());
        for (VerificationResult result : results) {
            assertEquals(VerificationResult.Status.NOT_BLOCKED, result.status);
            assertTrue(result.systemSuccess);
            assertTrue(result.controlSuccess);
            assertNotNull(result.protocol);
            assertTrue(result.detail.contains("系统默认信任接受"));
        }
    }

    @Test
    public void reportsBlockedWhenSystemRejectsButControlSucceeds() throws Exception {
        VerificationRunner runner = new VerificationRunner(
                entry -> rejectingContext(),
                root -> true);

        List<VerificationResult> results = runner.run(twoEntries(), null);

        for (VerificationResult result : results) {
            assertEquals(VerificationResult.Status.BLOCKED, result.status);
            assertFalse(result.systemSuccess);
            assertTrue("对照组应成功：" + result.name, result.controlSuccess);
            assertTrue(result.detail.contains("系统默认信任拒绝证书链"));
            assertTrue(result.detail.contains("可判定为系统层阻断"));
        }
    }

    @Test
    public void reportsRootUntrustedSeparately() throws Exception {
        VerificationRunner runner = new VerificationRunner(
                entry -> PinnedTrust.contextTrusting(entry.root),
                root -> false);

        List<VerificationResult> results = runner.run(twoEntries(), null);

        for (VerificationResult result : results) {
            assertEquals(VerificationResult.Status.ROOT_UNTRUSTED, result.status);
            assertFalse(result.rootTrusted);
            assertTrue(result.controlSuccess);
            assertTrue(result.detail.contains("不据此判定"));
        }
    }

    @Test
    public void reportsErrorWhenLocalChainSetupIsInvalid() throws Exception {
        CaEntry entry = TestAssets.entries().get(0);
        // 8 个中间 CA 共用 AAA 根；故意换成 emSign 根，本地 TLS 服务端无法装载该链。
        // 关键行为：系统也拒绝时，绝不能判成「系统阻断」。
        X509Certificate unrelatedRoot = loadCertificate("roots/emsign-ecc-root-ca-g3.pem");
        CaEntry mismatched = new CaEntry("mismatched pair",
                entry.intermediate, entry.key, unrelatedRoot);

        VerificationRunner runner = new VerificationRunner(
                entry1 -> rejectingContext(),
                root -> true);

        VerificationResult result = runner.run(
                Collections.singletonList(mismatched), null).get(0);

        assertEquals(VerificationResult.Status.ERROR, result.status);
        assertFalse(result.controlSuccess);
        assertTrue(result.detail, result.detail.contains("对照组：失败"));
        assertFalse(result.detail.contains("可判定为系统层阻断"));
    }

    private static X509Certificate loadCertificate(String assetPath) throws Exception {
        Pem.Block block = Pem.findFirst(TestAssets.reader().read(assetPath), "CERTIFICATE");
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(block.der));
    }

    @Test
    public void systemTrustApisAreUsable() throws Exception {
        // 在 JVM 上跑一遍真正的系统默认 TrustManager 代码路径。
        // JDK cacerts 是否包含 AAA 根因环境而异，因此只要求两种合法结果之一，
        // 且对照组（自行提供根）必须成功。
        VerificationRunner runner = new VerificationRunner(
                entry -> SystemTrust.defaultClientContext(),
                SystemTrust::isTrustedRoot);

        VerificationResult result = runner.run(
                Collections.singletonList(TestAssets.entries().get(0)), null).get(0);

        assertTrue(result.status == VerificationResult.Status.NOT_BLOCKED
                || result.status == VerificationResult.Status.ROOT_UNTRUSTED);
        assertTrue(result.controlSuccess);
    }

    private static List<CaEntry> twoEntries() throws Exception {
        return TestAssets.entries().subList(0, 2);
    }

    private static SSLContext rejectingContext() throws GeneralSecurityException {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                throw new CertificateException("test: reject client");
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                throw new CertificateException("test: simulated system block");
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }}, null);
        return context;
    }
}
