package com.example.emudhracheck.crypto;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

/**
 * 用中间 CA 私钥签发一张仅用于本机回环测试的 localhost 叶子证书。
 *
 * <p>证书链构建要点：</p>
 * <ul>
 *   <li>issuer 直接复用中间 CA 证书 subject 的 DER 编码，保证客户端构建链时名称逐字节匹配；</li>
 *   <li>签名算法与 P-384 中间 CA 匹配：ecdsa-with-SHA384（1.2.840.10045.4.3.3）；</li>
 *   <li>SAN 同时包含 DNS {@code localhost} 与 IP {@code 127.0.0.1}；</li>
 *   <li>签发后立即用中间 CA 公钥验签，若 DER 编码有误则立即失败。</li>
 * </ul>
 */
public final class LeafCertificateIssuer {

    public static final String SIGNATURE_ALGORITHM = "SHA384withECDSA";
    private static final String ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3";
    private static final long NOT_BEFORE_SKEW_MS = 60 * 60 * 1000L;
    private static final long VALIDITY_MS = 24 * 60 * 60 * 1000L;

    private LeafCertificateIssuer() {
    }

    public static X509Certificate issue(X509Certificate intermediate, PrivateKey intermediateKey,
            PublicKey leafPublicKey, SecureRandom random) throws GeneralSecurityException {
        long now = System.currentTimeMillis();

        // 外层与 TBS 内部必须使用完全相同的签名 AlgorithmIdentifier。
        byte[] signatureAlgorithm = Der.seq(Der.oid(ECDSA_WITH_SHA384));

        byte[] serialBytes = new byte[8];
        random.nextBytes(serialBytes);
        BigInteger serial = new BigInteger(1, serialBytes);
        if (serial.signum() == 0) {
            serial = BigInteger.ONE;
        }

        // [3] EXPLICIT Extensions
        byte[] extensions = Der.explicit(3, Der.seq(
                extension("2.5.29.19", true, Der.seq()), // BasicConstraints: CA=false
                extension("2.5.29.15", true, Der.bitString(new byte[]{(byte) 0x80}, 7)), // KeyUsage: digitalSignature
                extension("2.5.29.37", false, Der.seq(Der.oid("1.3.6.1.5.5.7.3.1"))), // EKU: serverAuth
                extension("2.5.29.17", false, Der.seq(
                        // GeneralName: dNSName [2] 与 iPAddress [7]（隐式标签，primitive）
                        Der.tlv(0x82, "localhost".getBytes(StandardCharsets.US_ASCII)),
                        Der.tlv(0x87, new byte[]{127, 0, 0, 1})))));

        byte[] tbsCertificate = Der.seq(
                Der.explicit(0, Der.integer(2)), // version: v3
                Der.integer(serial),
                signatureAlgorithm,
                intermediate.getSubjectX500Principal().getEncoded(), // issuer = 中间 CA subject
                Der.seq(
                        Der.utcTime(new Date(now - NOT_BEFORE_SKEW_MS)),
                        Der.utcTime(new Date(now + VALIDITY_MS))),
                new X500Principal("CN=localhost").getEncoded(),
                leafPublicKey.getEncoded(), // SubjectPublicKeyInfo
                extensions);

        Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
        signer.initSign(intermediateKey, random);
        signer.update(tbsCertificate);
        byte[] signature = signer.sign();

        byte[] certificateDer = Der.seq(tbsCertificate, signatureAlgorithm, Der.bitString(signature, 0));
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate leaf = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(certificateDer));

        // 自检签名：DER 构造错误会在这里暴露，运行器随后会把它归类为内部错误而非系统阻断。
        leaf.verify(intermediate.getPublicKey());
        return leaf;
    }

    private static byte[] extension(String oid, boolean critical, byte[] valueDer) {
        if (critical) {
            return Der.seq(Der.oid(oid), Der.bool(true), Der.octetString(valueDer));
        }
        return Der.seq(Der.oid(oid), Der.octetString(valueDer));
    }
}
