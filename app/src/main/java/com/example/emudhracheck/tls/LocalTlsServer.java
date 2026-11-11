package com.example.emudhracheck.tls;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * 仅在 127.0.0.1 上监听一次的临时 TLS 服务端。
 *
 * <p>端口由系统随机分配（bind port 0），accept 一次并完成握手后立即关闭；
 * accept 与握手均有超时，避免资源长期占用。</p>
 */
public final class LocalTlsServer {

    private static final String LOOPBACK = "127.0.0.1";
    private static final int ACCEPT_TIMEOUT_MS = 5000;
    private static final int HANDSHAKE_TIMEOUT_MS = 8000;

    private LocalTlsServer() {
    }

    public static final class ServerResult {
        public final boolean success;
        public final String protocol;
        public final String cipher;
        public final Exception error;

        private ServerResult(boolean success, String protocol, String cipher, Exception error) {
            this.success = success;
            this.protocol = protocol;
            this.cipher = cipher;
            this.error = error;
        }

        static ServerResult success(String protocol, String cipher) {
            return new ServerResult(true, protocol, cipher, null);
        }

        static ServerResult failure(Exception error) {
            return new ServerResult(false, null, null, error);
        }
    }

    public static final class Handle implements Closeable {
        private final SSLServerSocket serverSocket;
        private final Thread thread;
        private final int port;
        private final AtomicReference<ServerResult> result;

        Handle(SSLServerSocket serverSocket, Thread thread, int port,
                AtomicReference<ServerResult> result) {
            this.serverSocket = serverSocket;
            this.thread = thread;
            this.port = port;
            this.result = result;
        }

        public int port() {
            return port;
        }

        public ServerResult await(long timeoutMs) {
            try {
                thread.join(timeoutMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return result.get();
        }

        @Override
        public void close() {
            try {
                serverSocket.close();
            } catch (IOException ignored) {
                // 已经关闭。
            }
            thread.interrupt();
        }
    }

    public static Handle start(X509Certificate[] chain, PrivateKey leafKey)
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

            SSLServerSocket serverSocket = (SSLServerSocket) context.getServerSocketFactory()
                    .createServerSocket(0, 1, InetAddress.getByName(LOOPBACK));
            serverSocket.setSoTimeout(ACCEPT_TIMEOUT_MS);
            serverSocket.setNeedClientAuth(false);

            int port = serverSocket.getLocalPort();
            AtomicReference<ServerResult> result = new AtomicReference<>();
            Thread thread = new Thread(() -> serveOnce(serverSocket, result), "local-tls-server");
            thread.setDaemon(true);
            thread.start();
            return new Handle(serverSocket, thread, port, result);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static void serveOnce(SSLServerSocket serverSocket,
            AtomicReference<ServerResult> result) {
        ServerResult serverResult;
        try (Socket socket = serverSocket.accept()) {
            socket.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            SSLSocket sslSocket = (SSLSocket) socket;
            sslSocket.startHandshake();
            SSLSession session = sslSocket.getSession();
            serverResult = ServerResult.success(session.getProtocol(), session.getCipherSuite());
        } catch (Exception e) {
            serverResult = ServerResult.failure(e);
        } finally {
            try {
                serverSocket.close();
            } catch (IOException ignored) {
                // 已经关闭。
            }
        }
        result.set(serverResult);
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
