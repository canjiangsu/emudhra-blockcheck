package com.example.emudhracheck.verify;

/** 单个中间 CA 的验证结果。 */
public final class VerificationResult {

    public enum Status {
        BLOCKED("阻断生效"),
        NOT_BLOCKED("未阻断"),
        ROOT_UNTRUSTED("根证书不受信任"),
        ERROR("错误");

        public final String label;

        Status(String label) {
            this.label = label;
        }
    }

    public final String name;
    public final Status status;
    public final String detail;
    public final boolean rootTrusted;
    public final boolean systemSuccess;
    public final boolean controlSuccess;
    public final String protocol;
    public final String cipher;
    public final long durationMs;

    public VerificationResult(String name, Status status, String detail, boolean rootTrusted,
            boolean systemSuccess, boolean controlSuccess, String protocol, String cipher,
            long durationMs) {
        this.name = name;
        this.status = status;
        this.detail = detail;
        this.rootTrusted = rootTrusted;
        this.systemSuccess = systemSuccess;
        this.controlSuccess = controlSuccess;
        this.protocol = protocol;
        this.cipher = cipher;
        this.durationMs = durationMs;
    }
}
