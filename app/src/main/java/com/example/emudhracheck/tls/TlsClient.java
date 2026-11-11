package com.example.emudhracheck.tls;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/** 一次性 TLS 客户端握手。TrustManager 由调用方提供的 SSLContext 决定。 */
public final class TlsClient {

    private static final String LOOPBACK = "127.0.0.1";

    private TlsClient() {
    }

    public static final class Outcome {
        public final boolean success;
        public final String protocol;
        public final String cipher;
        public final Exception failure;

        private Outcome(boolean success, String protocol, String cipher, Exception failure) {
            this.success = success;
            this.protocol = protocol;
            this.cipher = cipher;
            this.failure = failure;
        }

        public static Outcome success(String protocol, String cipher) {
            return new Outcome(true, protocol, cipher, null);
        }

        public static Outcome failure(Exception failure) {
            return new Outcome(false, null, null, failure);
        }
    }

    /**
     * 主机名不匹配属于测试实现错误，不能算「证书链被阻断」。
     * 因此该异常故意不继承 CertificateException。
     */
    public static final class HostnameMismatchException extends Exception {
        public HostnameMismatchException(String message) {
            super(message);
        }

        public HostnameMismatchException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static Outcome handshake(SSLContext context, int port, int timeoutMs) {
        Socket raw = null;
        SSLSocket ssl = null;
        try {
            raw = new Socket();
            raw.connect(new InetSocketAddress(InetAddress.getByName(LOOPBACK), port), timeoutMs);
            raw.setSoTimeout(timeoutMs);

            ssl = (SSLSocket) context.getSocketFactory()
                    .createSocket(raw, LOOPBACK, port, true);
            raw = null; // 所有权移交给 SSLSocket
            ssl.setSoTimeout(timeoutMs);
            ssl.startHandshake();

            SSLSession session = ssl.getSession();
            // 默认 TrustManager 不做主机名检查；这里按 HTTPS 语义补做一次。
            verifyHostname((X509Certificate) session.getPeerCertificates()[0], LOOPBACK);
            return Outcome.success(session.getProtocol(), session.getCipherSuite());
        } catch (Exception e) {
            return Outcome.failure(e);
        } finally {
            closeQuietly(ssl);
            closeQuietly(raw);
        }
    }

    private static void verifyHostname(X509Certificate certificate, String host)
            throws HostnameMismatchException {
        try {
            Collection<List<?>> names = certificate.getSubjectAlternativeNames();
            if (names != null) {
                for (List<?> name : names) {
                    if (name == null || name.size() < 2 || !(name.get(0) instanceof Integer)) {
                        continue;
                    }
                    int type = (Integer) name.get(0);
                    Object value = name.get(1);
                    if (type == 2 && host.equals(value)) { // dNSName
                        return;
                    }
                    if (type == 7 && isLoopbackIp(host, value)) { // iPAddress
                        return;
                    }
                }
            }
        } catch (CertificateParsingException e) {
            throw new HostnameMismatchException("无法解析证书 SAN：" + e.getMessage(), e);
        }
        throw new HostnameMismatchException("证书 SAN 不包含 " + host);
    }

    private static boolean isLoopbackIp(String host, Object value) {
        if (host.equals(value)) {
            return true;
        }
        if (value instanceof byte[]) {
            byte[] ip = (byte[]) value;
            return ip.length == 4
                    && (ip[0] & 0xFF) == 127
                    && ip[1] == 0
                    && ip[2] == 0
                    && ip[3] == 1;
        }
        return false;
    }

    private static void closeQuietly(Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // 忽略关闭异常。
            }
        }
    }
}
