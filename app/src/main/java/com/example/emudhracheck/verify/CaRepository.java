package com.example.emudhracheck.verify;

import com.example.emudhracheck.crypto.Pem;
import com.example.emudhracheck.crypto.PemKeys;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * 从 assets 读取 8 个中间 CA 与两个根证书。
 *
 * <p>根证书不写死映射：按「中间 CA 的 issuer == 根的 subject」匹配，并用根公钥验证
 * 中间 CA 签名，避免配置错误导致误判。读取方式通过 {@link Reader} 抽象，
 * Android 用 assets，JVM 单元测试用文件系统。</p>
 */
public final class CaRepository {

    public interface Reader {
        String read(String path) throws IOException;
    }

    public static final class Spec {
        public final String slug;
        public final String name;

        Spec(String slug, String name) {
            this.slug = slug;
            this.name = name;
        }
    }

    private static final Spec[] SPECS = {
            new Spec("em-dv-tls-ca-g3b-nl", "EM DV TLS CA - G3B（eMudhra BV, NL）"),
            new Spec("em-dv-tls-ca-g3c-us", "EM DV TLS CA - G3C（eMudhra Inc, US）"),
            new Spec("em-ev-tls-ca-g3b-nl", "EM EV TLS CA - G3B（eMudhra BV, NL）"),
            new Spec("em-ev-tls-ca-g3c-us", "EM EV TLS CA - G3C（eMudhra Inc, US）"),
            new Spec("em-ov-cs-ca-g3b-nl", "EM OV CS CA - G3B（eMudhra BV, NL）"),
            new Spec("em-ov-cs-ca-g3c-us", "EM OV CS CA - G3C（eMudhra Inc, US）"),
            new Spec("em-ov-tls-ca-g3b-nl", "EM OV TLS CA - G3B（eMudhra BV, NL）"),
            new Spec("em-ov-tls-ca-g3c-us", "EM OV TLS CA - G3C（eMudhra Inc, US）"),
    };

    private static final String[] ROOT_FILES = {
            "roots/aaa-certificate-services.pem",
            "roots/emsign-ecc-root-ca-g3.pem",
    };

    private CaRepository() {
    }

    /** 8 个 CA 的展示名称，顺序与固定端口 18443..18450 一致。 */
    public static List<String> displayNames() {
        List<String> names = new ArrayList<>();
        for (Spec spec : SPECS) {
            names.add(spec.name);
        }
        return names;
    }

    public static List<CaEntry> load(Reader reader) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        List<X509Certificate> roots = new ArrayList<>();
        for (String rootFile : ROOT_FILES) {
            roots.add(readCertificate(factory, reader.read(rootFile)));
        }

        List<CaEntry> entries = new ArrayList<>();
        for (Spec spec : SPECS) {
            X509Certificate intermediate = readCertificate(factory,
                    reader.read("certs/" + spec.slug + ".pem"));
            PrivateKey key = PemKeys.parseEcPrivateKey(
                    reader.read("certs/" + spec.slug + ".key"), intermediate);
            X509Certificate root = findIssuer(intermediate, roots);
            if (root == null) {
                throw new IllegalStateException("找不到签发 " + spec.name + " 的根证书");
            }
            entries.add(new CaEntry(spec.name, intermediate, key, root));
        }
        return entries;
    }

    private static X509Certificate readCertificate(CertificateFactory factory, String pemText)
            throws Exception {
        Pem.Block block = Pem.findFirst(pemText, "CERTIFICATE");
        if (block == null) {
            throw new IllegalArgumentException("未找到 CERTIFICATE PEM 块");
        }
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(block.der));
    }

    private static X509Certificate findIssuer(X509Certificate intermediate,
            List<X509Certificate> roots) {
        for (X509Certificate root : roots) {
            if (!intermediate.getIssuerX500Principal().equals(root.getSubjectX500Principal())) {
                continue;
            }
            try {
                intermediate.verify(root.getPublicKey());
                return root;
            } catch (Exception ignored) {
                // issuer 名称相同但公钥不匹配，继续尝试下一个根。
            }
        }
        return null;
    }
}
