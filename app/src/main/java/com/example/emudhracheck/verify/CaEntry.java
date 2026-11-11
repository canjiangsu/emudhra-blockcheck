package com.example.emudhracheck.verify;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/** 一个待验证的中间 CA：证书、已泄露私钥，以及签发它的根证书。 */
public final class CaEntry {

    public final String name;
    public final X509Certificate intermediate;
    public final PrivateKey key;
    public final X509Certificate root;

    public CaEntry(String name, X509Certificate intermediate, PrivateKey key, X509Certificate root) {
        this.name = name;
        this.intermediate = intermediate;
        this.key = key;
        this.root = root;
    }
}
