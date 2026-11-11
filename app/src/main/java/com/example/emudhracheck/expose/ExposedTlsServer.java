package com.example.emudhracheck.expose;

import com.example.emudhracheck.crypto.LeafCertificateIssuer;
import com.example.emudhracheck.tls.TlsContexts;
import com.example.emudhracheck.verify.CaEntry;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * 对外 TLS 验证端点：每个 CA 一个固定端口，只签发覆盖本机地址的临时叶子证书。
 *
 * <p>客户端用自己的 TrustManager/CA bundle 连接：握手成功说明它接受了这条已泄露 CA
 * 签发的链；握手因证书失败说明客户端拒绝。服务端不做任意域名签发，也不导出私钥。</p>
 */
public final class ExposedTlsServer {

    private static final int ACCEPT_TIMEOUT_MS = 1000;
    private static final int HANDSHAKE_TIMEOUT_MS = 8000;
    private static final int HTTP_READ_TIMEOUT_MS = 2000;
    private static final int BACKLOG = 8;
    private static final long LEAF_VALIDITY_MS = LeafCertificateIssuer.SEVEN_DAYS_MS;
    private static final String LOOPBACK = "127.0.0.1";

    private final ExposedServerState state;
    private final List<SSLServerSocket> serverSockets = new CopyOnWriteArrayList<>();
    private final List<Thread> threads = new CopyOnWriteArrayList<>();
    private volatile boolean running = true;

    private ExposedTlsServer(ExposedServerState state) {
        this.state = state;
    }

    public static ExposedTlsServer start(List<CaEntry> entries, boolean lanEnabled,
            int basePort, ExposedServerState state, SecureRandom random) throws Exception {
        ExposedTlsServer server = new ExposedTlsServer(state);
        try {
            server.launch(entries, lanEnabled, basePort, random);
            return server;
        } catch (Exception e) {
            server.stop();
            throw e;
        }
    }

    private void launch(List<CaEntry> entries, boolean lanEnabled, int basePort,
            SecureRandom random) throws Exception {
        List<String> names = new ArrayList<>();
        for (CaEntry entry : entries) {
            names.add(entry.name);
        }
        state.reset(names, lanEnabled, basePort);

        LocalAddresses.SanSet san = LocalAddresses.collect();
        state.setLocalAddresses(san.displayAddresses);

        int started = 0;
        for (int i = 0; i < entries.size(); i++) {
            CaEntry entry = entries.get(i);
            ExposedServerState.PortStatus status = state.port(i);
            SSLServerSocket serverSocket = null;
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec("secp256r1"), random);
                KeyPair leafKeyPair = generator.generateKeyPair();
                X509Certificate leaf = LeafCertificateIssuer.issue(
                        entry.intermediate, entry.key, leafKeyPair.getPublic(),
                        san.dnsNames, san.ipAddresses, LEAF_VALIDITY_MS, random);
                SSLContext context = TlsContexts.serverContext(
                        new X509Certificate[]{leaf, entry.intermediate, entry.root},
                        leafKeyPair.getPrivate());

                serverSocket = createServerSocket(context, lanEnabled, status.requestedPort);
                status.port = serverSocket.getLocalPort();
                status.listening = true;
                serverSockets.add(serverSocket);

                final SSLServerSocket listener = serverSocket;
                Thread thread = new Thread(() -> serveLoop(listener, entry, status),
                        "emudhra-expose-" + status.port);
                thread.setDaemon(true);
                thread.start();
                threads.add(thread);
                started++;
            } catch (Exception e) {
                status.listening = false;
                status.error = shortError(e);
                closeQuietly(serverSocket);
            }
        }

        state.setRunning(started > 0);
        state.setStarting(false);
        if (started == 0) {
            state.setLastError("没有端口启动成功（18443-18450 可能被占用）");
            throw new IOException(state.getLastError());
        }
        if (started < entries.size()) {
            state.setLastError("部分端口启动失败：" + (entries.size() - started)
                    + "/" + entries.size());
        }
    }

    private static SSLServerSocket createServerSocket(SSLContext context, boolean lanEnabled,
            int requestedPort) throws IOException {
        SSLServerSocket serverSocket = (SSLServerSocket) context.getServerSocketFactory()
                .createServerSocket();
        serverSocket.setReuseAddress(true);
        InetSocketAddress bindAddress = lanEnabled
                ? new InetSocketAddress(requestedPort)
                : new InetSocketAddress(InetAddress.getByName(LOOPBACK), requestedPort);
        try {
            serverSocket.bind(bindAddress, BACKLOG);
        } catch (IOException e) {
            closeQuietly(serverSocket);
            throw e;
        }
        serverSocket.setSoTimeout(ACCEPT_TIMEOUT_MS);
        serverSocket.setNeedClientAuth(false);
        return serverSocket;
    }

    private void serveLoop(SSLServerSocket serverSocket, CaEntry entry,
            ExposedServerState.PortStatus status) {
        while (running) {
            Socket socket = null;
            boolean handshakeDone = false;
            try {
                socket = serverSocket.accept();
                if (!LocalAddresses.isAllowedSource(socket.getInetAddress())) {
                    status.filtered.incrementAndGet();
                    continue;
                }
                socket.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
                SSLSocket sslSocket = (SSLSocket) socket;
                sslSocket.startHandshake();
                handshakeDone = true;
                status.accepted.incrementAndGet();
                sendHttpResponse(sslSocket, entry, status.port);
            } catch (SocketTimeoutException e) {
                if (socket != null && !handshakeDone && running) {
                    status.rejected.incrementAndGet();
                }
            } catch (SocketException e) {
                if (!running) {
                    break;
                }
                if (socket != null && !handshakeDone) {
                    status.rejected.incrementAndGet();
                }
            } catch (Exception e) {
                if (socket != null && !handshakeDone && running) {
                    status.rejected.incrementAndGet();
                }
            } finally {
                closeQuietly(socket);
            }
        }
        status.listening = false;
    }

    private static void sendHttpResponse(SSLSocket socket, CaEntry entry, int port) {
        try {
            socket.setSoTimeout(HTTP_READ_TIMEOUT_MS);
            readRequestLine(socket.getInputStream());
        } catch (Exception ignored) {
            // 原始 TLS 客户端可能不发 HTTP 请求；仍然返回说明并关闭。
        }

        String body = responseBody(entry, port);
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        String header = "HTTP/1.1 200 OK\r\n"
                + "Content-Type: text/plain; charset=utf-8\r\n"
                + "Content-Length: " + bodyBytes.length + "\r\n"
                + "Connection: close\r\n\r\n";
        try {
            OutputStream out = socket.getOutputStream();
            out.write(header.getBytes(StandardCharsets.US_ASCII));
            out.write(bodyBytes);
            out.flush();
        } catch (Exception ignored) {
            // 客户端可能只做握手后立即断开。
        }
    }

    private static void readRequestLine(InputStream input) {
        try {
            int count = 0;
            while (count < 2048) {
                int value = input.read();
                if (value == -1 || value == '\n') {
                    return;
                }
                count++;
            }
        } catch (IOException ignored) {
            // 读超时/断开均不影响握手结果。
        }
    }

    private static String responseBody(CaEntry entry, int port) {
        return "OK: " + entry.name + "\n"
                + "TLS handshake completed on port " + port + ".\n"
                + "The client trust store ACCEPTED this certificate chain signed by the leaked "
                + "intermediate CA.\n"
                + "If this CA is supposed to be blocked, the client's trust configuration is "
                + "not blocking it.\n\n"
                + "Root: " + entry.root.getSubjectX500Principal().getName() + "\n"
                + "Note: a handshake failure can also mean the client does not trust this root; "
                + "verify root trust separately.\n";
    }

    public synchronized void stop() {
        running = false;
        for (SSLServerSocket serverSocket : serverSockets) {
            closeQuietly(serverSocket);
        }
        serverSockets.clear();
        for (Thread thread : threads) {
            thread.interrupt();
            try {
                thread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        threads.clear();
        for (ExposedServerState.PortStatus status : state.snapshot()) {
            status.listening = false;
        }
        state.setRunning(false);
        state.setStarting(false);
    }

    private static void closeQuietly(ServerSocket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // 已关闭。
            }
        }
    }

    private static void closeQuietly(Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // 已关闭。
            }
        }
    }

    private static String shortError(Throwable throwable) {
        String message = throwable.getMessage();
        String text = throwable.getClass().getSimpleName()
                + (message == null || message.isEmpty() ? "" : ": " + message);
        return text.length() <= 160 ? text : text.substring(0, 160) + "…";
    }
}
