package com.example.emudhracheck;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.example.emudhracheck.crypto.Pem;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.junit.Test;

public class PemTest {

    @Test
    public void parsesCertificateFromFileWithComments() throws Exception {
        String text = TestAssets.reader().read("roots/aaa-certificate-services.pem");

        Pem.Block block = Pem.findFirst(text, "CERTIFICATE");

        assertNotNull(block);
        assertTrue(block.der.length > 100);
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(block.der));
        assertTrue(certificate.getSubjectX500Principal().getName()
                .contains("AAA Certificate Services"));
    }

    @Test
    public void parsesSec1PrivateKeyBlock() throws Exception {
        String text = TestAssets.reader().read("certs/em-dv-tls-ca-g3b-nl.key");

        Pem.Block block = Pem.findFirst(text, "EC PRIVATE KEY");

        assertNotNull(block);
        assertTrue(block.der.length > 100);
    }

    @Test
    public void parsesMultipleBlocks() {
        String text = "junk\n"
                + "-----BEGIN FOO-----\n"
                + "AQID\n"
                + "-----END FOO-----\n"
                + "-----BEGIN BAR-----\n"
                + "BAUG\n"
                + "-----END BAR-----\n";

        assertEquals(2, Pem.parseAll(text).size());
        assertEquals("FOO", Pem.parseAll(text).get(0).type);
        assertEquals(3, Pem.parseAll(text).get(0).der.length);
    }
}
