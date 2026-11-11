package com.example.emudhracheck.tls;

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

/** 区分「证书验证失败」与「网络/内部错误」。 */
public final class ExceptionClassifier {

    private ExceptionClassifier() {
    }

    /**
     * 沿 cause 链查找证书类异常。
     *
     * <p>只有出现 {@link CertificateException}、{@link CertPathValidatorException} 或
     * {@code CertificateRevokedException} 时，才认为系统是在证书校验阶段拒绝的。</p>
     */
    public static Throwable findCertificateCause(Throwable throwable) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<Throwable, Boolean>());
        Throwable current = throwable;
        while (current != null && seen.add(current)) {
            if (current instanceof CertificateException
                    || current instanceof CertPathValidatorException
                    || isCertificateRevoked(current)) {
                return current;
            }
            Throwable cause = current.getCause();
            current = (cause == current) ? null : cause;
        }
        return null;
    }

    public static boolean isCertificateFailure(Throwable throwable) {
        return findCertificateCause(throwable) != null;
    }

    /** 把异常链格式化为一行短文本，用于 UI 与导出。 */
    public static String describe(Throwable throwable) {
        if (throwable == null) {
            return "无异常";
        }
        StringBuilder out = new StringBuilder();
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<Throwable, Boolean>());
        Throwable current = throwable;
        int depth = 0;
        while (current != null && seen.add(current) && depth < 6) {
            if (depth > 0) {
                out.append(" <- ");
            }
            out.append(current.getClass().getName());
            String message = current.getMessage();
            if (message != null && !message.isEmpty()) {
                out.append(": ").append(oneLine(message));
            }
            Throwable cause = current.getCause();
            current = (cause == current) ? null : cause;
            depth++;
        }
        return truncate(out.toString(), 400);
    }

    private static boolean isCertificateRevoked(Throwable throwable) {
        // API 21 没有 CertificateRevokedException 类，直接引用会导致类加载失败；
        // 按类名识别（它本身继承 CertificateException，主要用于报告具体类型）。
        for (Class<?> type = throwable.getClass(); type != null; type = type.getSuperclass()) {
            if ("java.security.cert.CertificateRevokedException".equals(type.getName())) {
                return true;
            }
        }
        return false;
    }

    private static String oneLine(String text) {
        StringBuilder out = new StringBuilder(text.length());
        boolean lastSpace = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\r' || c == '\n' || c == '\t') {
                c = ' ';
            }
            if (c == ' ') {
                if (lastSpace) {
                    continue;
                }
                lastSpace = true;
            } else {
                lastSpace = false;
            }
            out.append(c);
        }
        return out.toString().trim();
    }

    private static String truncate(String text, int max) {
        if (text.length() <= max) {
            return text;
        }
        return text.substring(0, max) + "…";
    }
}
