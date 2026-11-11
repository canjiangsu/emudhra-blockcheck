package com.example.emudhracheck.tls;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * 对照组信任设置：只信任指定根证书，仍然走标准 PKIX 证书路径校验。
 *
 * <p>用途：当系统默认 TrustManager 拒绝证书链时，若此对照组能成功握手，
 * 说明叶子证书、证书链、签名算法、TLS 栈本身都正常，失败确实来自系统层信任决策。</p>
 */
public final class PinnedTrust {

    private PinnedTrust() {
    }

    public static SSLContext contextTrusting(X509Certificate root) throws GeneralSecurityException {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("root", root);

            TrustManagerFactory factory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            factory.init(keyStore);

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, factory.getTrustManagers(), null);
            return context;
        } catch (IOException e) {
            throw new GeneralSecurityException("无法创建对照组信任库", e);
        }
    }
}
