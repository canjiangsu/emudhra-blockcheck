package com.example.emudhracheck;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.example.emudhracheck.verify.CaEntry;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.List;
import org.junit.Test;

public class CaMaterialTest {

    @Test
    public void loadsEightCasWithMatchingRoots() throws Exception {
        List<CaEntry> entries = TestAssets.entries();

        assertEquals(8, entries.size());
        for (CaEntry entry : entries) {
            assertNotNull(entry.name);
            assertNotNull(entry.key);
            assertEquals("EC", entry.key.getAlgorithm());
            assertTrue(entry.intermediate.getIssuerX500Principal()
                    .equals(entry.root.getSubjectX500Principal()));
            assertTrue(entry.root.getSubjectX500Principal().getName()
                    .contains("AAA Certificate Services"));
            // 中间 CA 证书必须确实由该根签发。
            entry.intermediate.verify(entry.root.getPublicKey());
        }
    }

    @Test
    public void eachSec1PrivateKeyMatchesItsCertificatePublicKey() throws Exception {
        byte[] message = "emudhra-blockcheck".getBytes(StandardCharsets.US_ASCII);

        for (CaEntry entry : TestAssets.entries()) {
            Signature signer = Signature.getInstance("SHA384withECDSA");
            signer.initSign(entry.key);
            signer.update(message);
            byte[] signature = signer.sign();

            Signature verifier = Signature.getInstance("SHA384withECDSA");
            verifier.initVerify(entry.intermediate.getPublicKey());
            verifier.update(message);

            assertTrue("私钥与证书公钥不匹配：" + entry.name, verifier.verify(signature));
        }
    }
}
