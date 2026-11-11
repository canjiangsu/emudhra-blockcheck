package com.example.emudhracheck.crypto;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 纯 Java PEM 解析。Android 5.0 没有 java.util.Base64（API 26 才有），
 * 因此这里自带一个最小 Base64 解码器。
 */
public final class Pem {

    private static final byte[] DECODE_TABLE = new byte[128];

    static {
        Arrays.fill(DECODE_TABLE, (byte) -1);
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < alphabet.length(); i++) {
            DECODE_TABLE[alphabet.charAt(i)] = (byte) i;
        }
    }

    private Pem() {
    }

    public static final class Block {
        public final String type;
        public final byte[] der;

        public Block(String type, byte[] der) {
            this.type = type;
            this.der = der;
        }
    }

    public static List<Block> parseAll(String text) {
        List<Block> blocks = new ArrayList<>();
        String[] lines = text.split("\r?\n");
        String type = null;
        StringBuilder body = null;
        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (line.startsWith("-----BEGIN ") && line.endsWith("-----")) {
                type = line.substring(11, line.length() - 5).trim();
                body = new StringBuilder();
            } else if (line.startsWith("-----END ") && line.endsWith("-----")) {
                if (type != null && body != null) {
                    blocks.add(new Block(type, base64Decode(body.toString())));
                }
                type = null;
                body = null;
            } else if (body != null) {
                body.append(line);
            }
        }
        return blocks;
    }

    public static Block findFirst(String text, String type) {
        for (Block block : parseAll(text)) {
            if (type.equals(block.type)) {
                return block;
            }
        }
        return null;
    }

    static byte[] base64Decode(String input) {
        StringBuilder clean = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '=') {
                clean.append(c);
            } else if (c < 128 && DECODE_TABLE[c] >= 0) {
                clean.append(c);
            }
        }
        if (clean.length() % 4 != 0) {
            throw new IllegalArgumentException("Base64 长度不是 4 的倍数");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(clean.length() / 4 * 3);
        for (int i = 0; i < clean.length(); i += 4) {
            int c0 = value(clean.charAt(i));
            int c1 = value(clean.charAt(i + 1));
            char ch2 = clean.charAt(i + 2);
            char ch3 = clean.charAt(i + 3);
            out.write((c0 << 2) | (c1 >> 4));
            if (ch2 != '=') {
                int c2 = value(ch2);
                out.write(((c1 & 0x0F) << 4) | (c2 >> 2));
                if (ch3 != '=') {
                    int c3 = value(ch3);
                    out.write(((c2 & 0x03) << 6) | c3);
                }
            }
        }
        return out.toByteArray();
    }

    private static int value(char c) {
        if (c == '=') {
            return 0;
        }
        int v = DECODE_TABLE[c];
        if (v < 0) {
            throw new IllegalArgumentException("非法 Base64 字符：" + c);
        }
        return v;
    }
}
