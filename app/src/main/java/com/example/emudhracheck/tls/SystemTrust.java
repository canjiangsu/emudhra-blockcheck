package com.example.emudhracheck.tls;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/** 系统默认信任路径。客户端不设置任何自定义 TrustManager。 */
public final class SystemTrust {

    private SystemTrust() {
    }

    public static SSLContext defaultClientContext() throws GeneralSecurityException {
        SSLContext context = SSLContext.getInstance("TLS");
        // 两个参数传 null：使用平台默认 KeyManager 与 TrustManager（系统信任库）。
        context.init(null, null, null);
        return context;
    }

    /**
     * 检查系统信任库是否包含指定根证书。
     *
     * <p>如果根都不受信任，连接必然在根证书环节失败，不能据此判断中间 CA 是否被阻断。</p>
     */
    public static boolean isTrustedRoot(X509Certificate root) throws GeneralSecurityException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);

        X509TrustManager manager = null;
        for (TrustManager trustManager : factory.getTrustManagers()) {
            if (trustManager instanceof X509TrustManager) {
                manager = (X509TrustManager) trustManager;
                break;
            }
        }
        if (manager == null) {
            throw new GeneralSecurityException("系统未提供 X509TrustManager");
        }

        byte[] encoded = root.getEncoded();
        byte[] subjectPublicKey = root.getPublicKey().getEncoded();
        for (X509Certificate candidate : manager.getAcceptedIssuers()) {
            if (Arrays.equals(encoded, candidate.getEncoded())) {
                return true;
            }
            // 某些系统实现会对同一根证书重新编码；subject + 公钥相同也视为同一信任锚。
            if (root.getSubjectX500Principal().equals(candidate.getSubjectX500Principal())
                    && subjectPublicKey != null
                    && Arrays.equals(subjectPublicKey, candidate.getPublicKey().getEncoded())) {
                return true;
            }
        }
        return false;
    }
}
