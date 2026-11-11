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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;

/**
 * 用中间 CA 私钥签发一张仅用于本地测试的叶子证书。
 *
 * <p>证书链构建要点：</p>
 * <ul>
 *   <li>issuer 直接复用中间 CA 证书 subject 的 DER 编码，保证客户端构建链时名称逐字节匹配；</li>
 *   <li>签名算法与 P-384 中间 CA 匹配：ecdsa-with-SHA384（1.2.840.10045.4.3.3）；</li>
 *   <li>SAN 由调用方给出：本机回环测试固定为 localhost + 127.0.0.1；对外服务额外包含
 *       本机网卡 IP，但绝不接受任意域名；</li>
 *   <li>签发后立即用中间 CA 公钥验签，若 DER 编码有误则立即失败。</li>
 * </ul>
 */
public final class LeafCertificateIssuer {

    public static final String SIGNATURE_ALGORITHM = "SHA384withECDSA";
    public static final long ONE_DAY_MS = 24L * 60 * 60 * 1000;
    public static final long SEVEN_DAYS_MS = 7L * ONE_DAY_MS;

    private static final String ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3";
    private static final long NOT_BEFORE_SKEW_MS = 60 * 60 * 1000L;
    private static final long DEFAULT_VALIDITY_MS = ONE_DAY_MS;

    private LeafCertificateIssuer() {
    }

    /** 兼容原有本机回环测试：SAN = localhost + 127.0.0.1，有效期 1 天。 */
    public static X509Certificate issue(X509Certificate intermediate, PrivateKey intermediateKey,
            PublicKey leafPublicKey, SecureRandom random) throws GeneralSecurityException {
        return issue(intermediate, intermediateKey, leafPublicKey,
                Collections.singletonList("localhost"),
                Collections.singletonList(new byte[]{127, 0, 0, 1}),
                DEFAULT_VALIDITY_MS, random);
    }

    /**
     * 签发指定 SAN 与有效期的叶子证书。
     *
     * @param dnsNames    仅允许本机名称（如 localhost），不能来自不可信输入
     * @param ipAddresses 4 或 16 字节的 IP 地址，最多覆盖本机所有网卡地址
     */
    public static X509Certificate issue(X509Certificate intermediate, PrivateKey intermediateKey,
            PublicKey leafPublicKey, List<String> dnsNames, List<byte[]> ipAddresses,
            long validityMs, SecureRandom random) throws GeneralSecurityException {
        if (validityMs <= 0) {
            throw new IllegalArgumentException("有效期必须大于 0");
        }
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
                extension("2.5.29.17", false,
                        subjectAlternativeName(dnsNames, ipAddresses))));

        byte[] tbsCertificate = Der.seq(
                Der.explicit(0, Der.integer(2)), // version: v3
                Der.integer(serial),
                signatureAlgorithm,
                intermediate.getSubjectX500Principal().getEncoded(), // issuer = 中间 CA subject
                Der.seq(
                        Der.utcTime(new Date(now - NOT_BEFORE_SKEW_MS)),
                        Der.utcTime(new Date(now + validityMs))),
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

    private static byte[] subjectAlternativeName(List<String> dnsNames,
            List<byte[]> ipAddresses) {
        List<byte[]> entries = new ArrayList<>();
        for (String dnsName : dnsNames) {
            if (dnsName == null || dnsName.isEmpty()) {
                continue;
            }
            // GeneralName: dNSName [2]（隐式标签，primitive，IA5String）
            entries.add(Der.tlv(0x82, dnsName.getBytes(StandardCharsets.US_ASCII)));
        }
        for (byte[] ip : ipAddresses) {
            if (ip == null) {
                continue;
            }
            if (ip.length != 4 && ip.length != 16) {
                throw new IllegalArgumentException("IP SAN 必须是 4 或 16 字节");
            }
            // GeneralName: iPAddress [7]（隐式标签，primitive，OCTET STRING）
            entries.add(Der.tlv(0x87, ip));
        }
        if (entries.isEmpty()) {
            throw new IllegalArgumentException("SAN 不能为空");
        }
        return Der.seq(entries.toArray(new byte[0][]));
    }

    private static byte[] extension(String oid, boolean critical, byte[] valueDer) {
        if (critical) {
            return Der.seq(Der.oid(oid), Der.bool(true), Der.octetString(valueDer));
        }
        return Der.seq(Der.oid(oid), Der.octetString(valueDer));
    }
}
