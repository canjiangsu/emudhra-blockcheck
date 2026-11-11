package com.example.emudhracheck;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.example.emudhracheck.tls.ExceptionClassifier;
import com.example.emudhracheck.tls.TlsClient;
import java.net.SocketTimeoutException;
import java.security.cert.CRLReason;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateRevokedException;
import java.util.Collections;
import java.util.Date;
import javax.net.ssl.SSLHandshakeException;
import javax.security.auth.x500.X500Principal;
import org.junit.Test;

public class ExceptionClassifierTest {

    @Test
    public void detectsCertificateExceptionCause() {
        SSLHandshakeException handshake = new SSLHandshakeException("handshake");
        handshake.initCause(new CertificateException("blocked"));

        assertTrue(ExceptionClassifier.isCertificateFailure(handshake));
        assertNotNull(ExceptionClassifier.findCertificateCause(handshake));
    }

    @Test
    public void detectsCertPathValidatorExceptionCause() {
        SSLHandshakeException handshake = new SSLHandshakeException("handshake");
        handshake.initCause(new CertPathValidatorException("path invalid"));

        assertTrue(ExceptionClassifier.isCertificateFailure(handshake));
    }

    @Test
    public void detectsCertificateRevokedException() {
        CertificateRevokedException revoked = new CertificateRevokedException(
                new Date(), CRLReason.KEY_COMPROMISE,
                new X500Principal("CN=Test"), Collections.emptyMap());

        assertTrue(ExceptionClassifier.isCertificateFailure(revoked));
        assertTrue(ExceptionClassifier.describe(revoked).contains("CertificateRevokedException"));
    }

    @Test
    public void detectsDeepCauseChain() {
        SSLHandshakeException handshake = new SSLHandshakeException("handshake");
        RuntimeException middle = new RuntimeException("middle");
        CertPathValidatorException rootCause = new CertPathValidatorException("deep");
        middle.initCause(rootCause);
        handshake.initCause(middle);

        assertTrue(ExceptionClassifier.isCertificateFailure(handshake));
    }

    @Test
    public void ignoresNetworkAndHostnameErrors() {
        assertFalse(ExceptionClassifier.isCertificateFailure(new SocketTimeoutException("timeout")));
        assertFalse(ExceptionClassifier.isCertificateFailure(
                new TlsClient.HostnameMismatchException("host")));
        assertFalse(ExceptionClassifier.isCertificateFailure(null));
        assertEquals("无异常", ExceptionClassifier.describe(null));
    }
}
