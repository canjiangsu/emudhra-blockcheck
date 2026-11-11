package com.example.emudhracheck.verify;

import java.util.List;

/** 把结果列表格式化为可复制/分享的纯文本。 */
public final class ResultFormatter {

    private ResultFormatter() {
    }

    public static String format(List<VerificationResult> results, String deviceInfo,
            String timestamp) {
        int blocked = 0;
        int notBlocked = 0;
        int unknown = 0;
        int error = 0;
        for (VerificationResult result : results) {
            switch (result.status) {
                case BLOCKED:
                    blocked++;
                    break;
                case NOT_BLOCKED:
                    notBlocked++;
                    break;
                case ROOT_UNTRUSTED:
                    unknown++;
                    break;
                default:
                    error++;
                    break;
            }
        }

        StringBuilder out = new StringBuilder(2048);
        out.append("eMudhra 中间 CA 阻断验证结果\n");
        out.append("时间：").append(timestamp).append('\n');
        out.append("设备：").append(deviceInfo).append('\n');
        out.append("汇总：阻断生效 ").append(blocked)
                .append(" · 未阻断 ").append(notBlocked)
                .append(" · 根证书不受信任 ").append(unknown)
                .append(" · 错误 ").append(error).append('\n');

        for (VerificationResult result : results) {
            out.append('\n')
                    .append('[').append(result.status.label).append("] ")
                    .append(result.name).append('\n');
            out.append("  ").append(result.detail).append('\n');
            out.append("  根证书受信任：").append(result.rootTrusted ? "是" : "否")
                    .append("；耗时：").append(result.durationMs).append(" ms\n");
        }

        out.append("\n说明：本结果只反映本机 Android 系统默认 TrustManager 的判定，"
                + "不代表浏览器 CRLSet/吊销检查的结论。\n");
        return out.toString();
    }
}
