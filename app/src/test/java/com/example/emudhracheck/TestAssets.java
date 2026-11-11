package com.example.emudhracheck;

import com.example.emudhracheck.verify.CaEntry;
import com.example.emudhracheck.verify.CaRepository;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

/** 单元测试从 app/src/main/assets 读取真实证书/私钥，避免复制一份敏感资产。 */
final class TestAssets {

    private TestAssets() {
    }

    static CaRepository.Reader reader() {
        File base = new File("src/main/assets");
        if (!new File(base, "certs").isDirectory()) {
            base = new File("app/src/main/assets");
        }
        final File root = base;
        return path -> {
            File file = new File(root, path);
            if (!file.isFile()) {
                throw new IOException("测试资产不存在：" + file.getAbsolutePath());
            }
            return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        };
    }

    static List<CaEntry> entries() throws Exception {
        return CaRepository.load(reader());
    }
}
