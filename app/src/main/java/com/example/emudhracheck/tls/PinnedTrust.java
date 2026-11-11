package com.example.emudhracheck.tls;

import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * 对照组信任设置：只信任指定根证书，用标准 PKIX 校验证书链。
 *
 * <p><b>关键点</b>：不能使用平台的 {@code TrustManagerFactory}。Android 的 Conscrypt 在
 * {@code TrustManagerImpl} 中会查询系统证书黑名单（{@code CertBlocklistImpl}），而本工具的
 * 目标恰恰是检测该黑名单。如果对照组也走平台 TrustManager，系统因黑名单拒绝时对照组也会
 * 拒绝，从而被误判为“内部错误”。因此这里直接使用 {@link CertPathValidator} 做纯 PKIX 路径
 * 校验，只信任固定根证书，不查询平台黑名单。</p>
 *
 * <p>当系统默认 TrustManager 拒绝、而此对照组成功时，说明叶子证书、证书链、签名算法和
 * TLS 栈本身都正常，失败来自系统层信任决策（例如证书公钥黑名单）。</p>
 */
public final class PinnedTrust {

    private PinnedTrust() {
    }

    public static SSLContext contextTrusting(X509Certificate root) throws GeneralSecurityException {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{new PinnedPkixTrustManager(root)}, null);
        return context;
    }

    private static final class PinnedPkixTrustManager implements X509TrustManager {
        private final X509Certificate root;
        private final TrustAnchor trustAnchor;

        PinnedPkixTrustManager(X509Certificate root) {
            this.root = root;
            this.trustAnchor = new TrustAnchor(root, null);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            throw new CertificateException("对照组仅用于校验服务端证书");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            if (chain == null || chain.length == 0) {
                throw new CertificateException("服务端返回了空证书链");
            }
            try {
                // CertPath 不应包含信任锚；服务端通常会把根证书也发下来，这里剔除。
                List<X509Certificate> pathCertificates = new ArrayList<>();
                for (X509Certificate certificate : chain) {
                    if (!certificate.equals(root)) {
                        pathCertificates.add(certificate);
                    }
                }
                if (pathCertificates.isEmpty()) {
                    throw new CertificateException("证书链只包含根证书");
                }

                CertPath path = CertificateFactory.getInstance("X.509")
                        .generateCertPath(pathCertificates);
                PKIXParameters parameters = new PKIXParameters(
                        Collections.singleton(trustAnchor));
                parameters.setRevocationEnabled(false);
                CertPathValidator.getInstance("PKIX").validate(path, parameters);
            } catch (CertificateException e) {
                throw e;
            } catch (GeneralSecurityException e) {
                throw new CertificateException("对照组 PKIX 校验失败：" + e.getMessage(), e);
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[]{root};
        }
    }
}
