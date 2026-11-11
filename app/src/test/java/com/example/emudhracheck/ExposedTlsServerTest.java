package com.example.emudhracheck;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.example.emudhracheck.expose.ExposedServerState;
import com.example.emudhracheck.expose.ExposedTlsServer;
import com.example.emudhracheck.expose.LocalAddresses;
import com.example.emudhracheck.tls.PinnedTrust;
import com.example.emudhracheck.verify.CaEntry;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.junit.Test;

public class ExposedTlsServerTest {

    @Test
    public void servesAllCasAndReportsSuccessForPinnedClient() throws Exception {
        List<CaEntry> entries = TestAssets.entries();
        ExposedServerState state = new ExposedServerState();
        ExposedTlsServer server = ExposedTlsServer.start(
                entries, false, 0, state, new SecureRandom());
        try {
            List<ExposedServerState.PortStatus> ports = state.snapshot();
            assertEquals(8, ports.size());
            for (int i = 0; i < entries.size(); i++) {
                ExposedServerState.PortStatus portStatus = ports.get(i);
                assertTrue(portStatus.name + " 未监听：" + portStatus.error,
                        portStatus.listening);
                assertTrue(portStatus.port > 0);

                ClientResult result = fetch(portStatus.port,
                        PinnedTrust.contextTrusting(entries.get(i).root), "127.0.0.1");

                assertTrue(result.body, result.body.startsWith("HTTP/1.1 200"));
                assertTrue(result.body, result.body.contains("OK: " + entries.get(i).name));
                assertEquals(entries.get(i).intermediate.getSubjectX500Principal(),
                        result.peer.getIssuerX500Principal());
                assertSan(result.peer, 2, "localhost");
                assertSan(result.peer, 7, "127.0.0.1");
                assertEquals(1, portStatus.accepted.get());
                assertEquals(0, portStatus.rejected.get());
            }
        } finally {
            server.stop();
        }
        assertFalse(state.isRunning());
        for (ExposedServerState.PortStatus portStatus : state.snapshot()) {
            assertFalse(portStatus.listening);
        }
    }

    @Test
    public void countsRejectedHandshakes() throws Exception {
        List<CaEntry> entries = TestAssets.entries().subList(0, 1);
        ExposedServerState state = new ExposedServerState();
        ExposedTlsServer server = ExposedTlsServer.start(
                entries, false, 0, state, new SecureRandom());
        try {
            ExposedServerState.PortStatus portStatus = state.snapshot().get(0);
            assertTrue(portStatus.listening);
            try {
                fetch(portStatus.port, rejectingContext(), "127.0.0.1");
                fail("客户端本应拒绝证书");
            } catch (Exception expected) {
                // 预期：证书验证失败
            }
            waitForCounter(portStatus.rejected, 1);
            assertTrue("rejected=" + portStatus.rejected.get(), portStatus.rejected.get() >= 1);
            assertEquals(0, portStatus.accepted.get());
        } finally {
            server.stop();
        }
    }

    @Test
    public void portConflictMarksOnlyFailingPort() throws Exception {
        ServerSocket blocker = new ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"));
        int base = blocker.getLocalPort();
        ExposedServerState state = new ExposedServerState();
        ExposedTlsServer server = null;
        try {
            server = ExposedTlsServer.start(
                    TestAssets.entries(), false, base, state, new SecureRandom());
            List<ExposedServerState.PortStatus> ports = state.snapshot();
            assertFalse(ports.get(0).listening);
            assertNotNull(ports.get(0).error);

            int listening = 0;
            for (int i = 1; i < ports.size(); i++) {
                if (ports.get(i).listening) {
                    listening++;
                }
            }
            assertTrue("其余端口应继续监听", listening > 0);
            assertTrue(state.isRunning());
            assertNotNull(state.getLastError());
        } finally {
            if (server != null) {
                server.stop();
            }
            blocker.close();
        }
    }

    @Test
    public void sourceFilterAllowsOnlyPrivateAndLoopback() throws Exception {
        assertTrue(LocalAddresses.isAllowedSource(InetAddress.getByName("127.0.0.1")));
        assertTrue(LocalAddresses.isAllowedSource(InetAddress.getByName("192.168.1.10")));
        assertTrue(LocalAddresses.isAllowedSource(InetAddress.getByName("10.0.0.1")));
        assertTrue(LocalAddresses.isAllowedSource(InetAddress.getByName("fc00::1")));
        assertFalse(LocalAddresses.isAllowedSource(InetAddress.getByName("8.8.8.8")));
    }

    private static final class ClientResult {
        final String body;
        final X509Certificate peer;

        ClientResult(String body, X509Certificate peer) {
            this.body = body;
            this.peer = peer;
        }
    }

    private static ClientResult fetch(int port, SSLContext context, String host)
            throws Exception {
        Socket raw = new Socket();
        SSLSocket ssl = null;
        try {
            raw.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 3000);
            raw.setSoTimeout(5000);
            ssl = (SSLSocket) context.getSocketFactory().createSocket(raw, host, port, true);
            raw = null;
            ssl.setSoTimeout(5000);
            ssl.startHandshake();

            X509Certificate peer = (X509Certificate) ssl.getSession().getPeerCertificates()[0];
            OutputStream output = ssl.getOutputStream();
            output.write(("GET / HTTP/1.1\r\nHost: " + host
                    + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            output.flush();

            InputStream input = ssl.getInputStream();
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[1024];
            int count;
            while ((count = input.read(chunk)) != -1) {
                buffer.write(chunk, 0, count);
            }
            return new ClientResult(
                    new String(buffer.toByteArray(), StandardCharsets.UTF_8), peer);
        } finally {
            if (ssl != null) {
                try {
                    ssl.close();
                } catch (Exception ignored) {
                    // 已关闭。
                }
            }
            if (raw != null) {
                try {
                    raw.close();
                } catch (Exception ignored) {
                    // 已关闭。
                }
            }
        }
    }

    private static SSLContext rejectingContext() throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                throw new CertificateException("reject");
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                throw new CertificateException("reject");
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }}, null);
        return context;
    }

    private static void waitForCounter(AtomicLong counter, long target)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + 3000;
        while (counter.get() < target && System.currentTimeMillis() < deadline) {
            Thread.sleep(20);
        }
    }

    private static void assertSan(X509Certificate certificate, int type, String value)
            throws Exception {
        for (List<?> san : certificate.getSubjectAlternativeNames()) {
            if ((Integer) san.get(0) == type && value.equals(String.valueOf(san.get(1)))) {
                return;
            }
        }
        fail("证书缺少 SAN 类型 " + type + " 值 " + value);
    }
}
