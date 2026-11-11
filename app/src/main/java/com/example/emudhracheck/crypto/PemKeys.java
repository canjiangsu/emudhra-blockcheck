package com.example.emudhracheck.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

/**
 * 把 PEM 私钥解析为 Java PrivateKey。
 *
 * <p>本批 eMudhra 中间 CA 的私钥是 SEC1 的 {@code EC PRIVATE KEY}（P-384）。Android 的
 * {@code KeyFactory("EC")} 只接受 PKCS#8，因此这里把 SEC1 DER 原样包进 PKCS#8 PrivateKeyInfo：
 * {@code SEQUENCE { INTEGER 0, SEQUENCE { id-ecPublicKey, curveOID }, OCTET STRING(sec1) }}。
 * 若密钥本身已经是 {@code PRIVATE KEY}（PKCS#8），直接交给 KeyFactory。</p>
 */
public final class PemKeys {

    private static final String ID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
    private static final String SECP384R1 = "1.3.132.0.34";

    private PemKeys() {
    }

    public static PrivateKey parseEcPrivateKey(String pemText, X509Certificate intermediate)
            throws GeneralSecurityException {
        Pem.Block pkcs8 = Pem.findFirst(pemText, "PRIVATE KEY");
        if (pkcs8 != null) {
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8.der));
        }

        Pem.Block sec1 = Pem.findFirst(pemText, "EC PRIVATE KEY");
        if (sec1 == null) {
            throw new GeneralSecurityException("未找到 EC 私钥块（支持 PRIVATE KEY / EC PRIVATE KEY）");
        }

        String curveOid = extractCurveOidFromSec1(sec1.der);
        if (curveOid == null && intermediate != null) {
            curveOid = extractCurveOidFromCertificate(intermediate);
        }
        if (curveOid == null) {
            // 8 把已泄露私钥均为 P-384；仅在参数缺失且证书不可读时回退。
            curveOid = SECP384R1;
        }

        byte[] algorithm = Der.seq(Der.oid(ID_EC_PUBLIC_KEY), Der.oid(curveOid));
        byte[] privateKeyInfo = Der.seq(Der.integer(0), algorithm, Der.octetString(sec1.der));
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo));
    }

    /** 从 SEC1 ECPrivateKey 的可选 [0] parameters 中读取命名曲线 OID。 */
    static String extractCurveOidFromSec1(byte[] sec1) {
        try {
            Der.Tlv outer = Der.read(sec1, 0);
            if (outer.tag != Der.TAG_SEQUENCE) {
                return null;
            }
            for (Der.Tlv child : Der.children(sec1, outer)) {
                if (child.tag == 0xA0) {
                    List<Der.Tlv> params = Der.children(sec1, child);
                    if (!params.isEmpty() && params.get(0).tag == Der.TAG_OID) {
                        return Der.decodeOid(sec1, params.get(0));
                    }
                }
            }
        } catch (RuntimeException ignored) {
            // 交给调用方回退到证书中的曲线参数。
        }
        return null;
    }

    /** 从证书 SubjectPublicKeyInfo 的 AlgorithmIdentifier 中读取曲线 OID。 */
    static String extractCurveOidFromCertificate(X509Certificate certificate) {
        byte[] spki = certificate.getPublicKey().getEncoded();
        if (spki == null) {
            return null;
        }
        try {
            Der.Tlv outer = Der.read(spki, 0);
            List<Der.Tlv> parts = Der.children(spki, outer);
            if (parts.size() < 2 || parts.get(0).tag != Der.TAG_SEQUENCE) {
                return null;
            }
            List<Der.Tlv> algorithm = Der.children(spki, parts.get(0));
            if (algorithm.size() < 2 || algorithm.get(1).tag != Der.TAG_OID) {
                return null;
            }
            return Der.decodeOid(spki, algorithm.get(1));
        } catch (RuntimeException ignored) {
            return null;
        }
    }
}
