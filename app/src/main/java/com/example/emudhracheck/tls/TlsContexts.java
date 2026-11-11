package com.example.emudhracheck.tls;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/** 服务端 SSLContext 构建：内存 KeyStore + 随机密码，复用给回环探针和对外服务。 */
public final class TlsContexts {

    private TlsContexts() {
    }

    public static SSLContext serverContext(X509Certificate[] chain, PrivateKey leafKey)
            throws GeneralSecurityException, IOException {
        KeyStore keyStore = newKeyStore();
        char[] password = randomPassword();
        try {
            keyStore.setKeyEntry("leaf", leafKey, password, chain);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, password);

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagerFactory.getKeyManagers(), null, null);
            return context;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static KeyStore newKeyStore() throws GeneralSecurityException, IOException {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            return keyStore;
        } catch (Exception ignored) {
            // 少数老系统/实现不支持内存 PKCS12，回退到平台默认类型。
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            return keyStore;
        }
    }

    private static char[] randomPassword() {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom random = new SecureRandom();
        char[] password = new char[24];
        for (int i = 0; i < password.length; i++) {
            password[i] = alphabet.charAt(random.nextInt(alphabet.length()));
        }
        return password;
    }
}
