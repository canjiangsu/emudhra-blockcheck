package com.example.emudhracheck;

import static org.junit.Assert.assertTrue;

import com.example.emudhracheck.verify.ResultFormatter;
import com.example.emudhracheck.verify.VerificationResult;
import java.util.Arrays;
import org.junit.Test;

public class ResultFormatterTest {

    @Test
    public void formatsSummaryAndEveryResult() {
        VerificationResult blocked = new VerificationResult("CA-A",
                VerificationResult.Status.BLOCKED, "detail-a", true, false, true, null, null, 12);
        VerificationResult notBlocked = new VerificationResult("CA-B",
                VerificationResult.Status.NOT_BLOCKED, "detail-b", true, true, true,
                "TLSv1.2", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 34);
        VerificationResult unknown = new VerificationResult("CA-C",
                VerificationResult.Status.ROOT_UNTRUSTED, "detail-c", false, false, true,
                null, null, 5);
        VerificationResult error = new VerificationResult("CA-D",
                VerificationResult.Status.ERROR, "detail-d", true, false, false, null, null, 7);

        String text = ResultFormatter.format(
                Arrays.asList(blocked, notBlocked, unknown, error),
                "Test Device, Android 14 (API 34)", "2026-11-11 10:00:00 +0800");

        assertTrue(text.contains("阻断生效 1"));
        assertTrue(text.contains("未阻断 1"));
        assertTrue(text.contains("根证书不受信任 1"));
        assertTrue(text.contains("错误 1"));
        assertTrue(text.contains("[阻断生效] CA-A"));
        assertTrue(text.contains("[未阻断] CA-B"));
        assertTrue(text.contains("detail-d"));
        assertTrue(text.contains("Test Device"));
        assertTrue(text.contains("不代表浏览器"));
    }
}
