package com.example.emudhracheck;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.example.emudhracheck.crypto.LeafCertificateIssuer;
import com.example.emudhracheck.verify.CaEntry;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.junit.Test;

public class LeafCertificateTest {

    @Test
    public void issuesValidLeafForEveryLeakedCa() throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), random);
        KeyPair leafKeyPair = generator.generateKeyPair();

        for (CaEntry entry : TestAssets.entries()) {
            X509Certificate leaf = LeafCertificateIssuer.issue(
                    entry.intermediate, entry.key, leafKeyPair.getPublic(), random);

            leaf.verify(entry.intermediate.getPublicKey());
            assertEquals(entry.intermediate.getSubjectX500Principal(),
                    leaf.getIssuerX500Principal());
            assertEquals(new X500Principal("CN=localhost"),
                    leaf.getSubjectX500Principal());
            leaf.checkValidity(new Date());

            assertEquals(-1, leaf.getBasicConstraints());
            boolean[] keyUsage = leaf.getKeyUsage();
            assertNotNull(keyUsage);
            assertTrue("缺少 digitalSignature：" + entry.name, keyUsage[0]);
            List<String> extended = leaf.getExtendedKeyUsage();
            assertNotNull(extended);
            assertTrue("缺少 serverAuth：" + entry.name,
                    extended.contains("1.3.6.1.5.5.7.3.1"));

            assertSan(leaf, 2, "localhost");
            assertSan(leaf, 7, "127.0.0.1");

            validatePkix(leaf, entry);
        }
    }

    @Test
    public void issuesLeafWithExplicitSanList() throws Exception {
        CaEntry entry = TestAssets.entries().get(0);
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), random);
        KeyPair pair = generator.generateKeyPair();

        X509Certificate leaf = LeafCertificateIssuer.issue(
                entry.intermediate, entry.key, pair.getPublic(),
                Arrays.asList("localhost", "device.test"),
                Arrays.asList(new byte[]{127, 0, 0, 1}, new byte[]{10, 0, 0, 1}),
                LeafCertificateIssuer.ONE_DAY_MS, random);

        assertSan(leaf, 2, "localhost");
        assertSan(leaf, 2, "device.test");
        assertSan(leaf, 7, "127.0.0.1");
        assertSan(leaf, 7, "10.0.0.1");
        leaf.verify(entry.intermediate.getPublicKey());
    }

    private static void validatePkix(X509Certificate leaf, CaEntry entry) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        CertPath path = factory.generateCertPath(Arrays.asList(leaf, entry.intermediate));

        PKIXParameters parameters = new PKIXParameters(
                Collections.singleton(new TrustAnchor(entry.root, null)));
        parameters.setRevocationEnabled(false);

        CertPathValidator.getInstance("PKIX").validate(path, parameters);
    }

    private static void assertSan(X509Certificate certificate, int expectedType,
            String expectedValue) throws Exception {
        for (List<?> san : certificate.getSubjectAlternativeNames()) {
            if ((Integer) san.get(0) == expectedType
                    && expectedValue.equals(String.valueOf(san.get(1)))) {
                return;
            }
        }
        throw new AssertionError("SAN 缺少类型 " + expectedType + " 的值 " + expectedValue);
    }
}
