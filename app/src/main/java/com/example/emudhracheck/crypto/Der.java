package com.example.emudhracheck.crypto;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

/**
 * 极简 ASN.1 DER 编码/解析工具。
 *
 * <p>只实现本项目需要的类型（SEQUENCE、INTEGER、OID、字符串、BIT/OCTET STRING、上下文标签），
 * 从而在不引入 BouncyCastle 的前提下构造 X.509 v3 叶子证书。解析部分仅用于从 SEC1 私钥和
 * SubjectPublicKeyInfo 中取出曲线 OID。</p>
 */
public final class Der {

    public static final int TAG_BOOLEAN = 0x01;
    public static final int TAG_INTEGER = 0x02;
    public static final int TAG_BIT_STRING = 0x03;
    public static final int TAG_OCTET_STRING = 0x04;
    public static final int TAG_OID = 0x06;
    public static final int TAG_UTF8_STRING = 0x0C;
    public static final int TAG_IA5_STRING = 0x16;
    public static final int TAG_UTC_TIME = 0x17;
    public static final int TAG_SEQUENCE = 0x30;

    private Der() {
    }

    /** 编码一个 TLV。 */
    public static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(value.length + 6);
        out.write(tag);
        writeLength(out, value.length);
        out.write(value, 0, value.length);
        return out.toByteArray();
    }

    public static byte[] seq(byte[]... parts) {
        return tlv(TAG_SEQUENCE, concat(parts));
    }

    /** [n] EXPLICIT，constructed。 */
    public static byte[] explicit(int tagNumber, byte[] content) {
        return tlv(0xA0 | tagNumber, content);
    }

    public static byte[] integer(long value) {
        return integer(BigInteger.valueOf(value));
    }

    public static byte[] integer(BigInteger value) {
        // BigInteger.toByteArray() 已按 DER 要求输出最短的二进制补码形式。
        return tlv(TAG_INTEGER, value.toByteArray());
    }

    public static byte[] bool(boolean value) {
        return tlv(TAG_BOOLEAN, new byte[]{(byte) (value ? 0xFF : 0x00)});
    }

    public static byte[] oid(String dotted) {
        String[] parts = dotted.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("OID 至少需要两个分量：" + dotted);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        long first = Long.parseLong(parts[0]) * 40L + Long.parseLong(parts[1]);
        writeBase128(out, first);
        for (int i = 2; i < parts.length; i++) {
            writeBase128(out, Long.parseLong(parts[i]));
        }
        return tlv(TAG_OID, out.toByteArray());
    }

    public static byte[] octetString(byte[] value) {
        return tlv(TAG_OCTET_STRING, value);
    }

    public static byte[] bitString(byte[] value, int unusedBits) {
        byte[] content = new byte[value.length + 1];
        content[0] = (byte) unusedBits;
        System.arraycopy(value, 0, content, 1, value.length);
        return tlv(TAG_BIT_STRING, content);
    }

    public static byte[] utf8String(String value) {
        return tlv(TAG_UTF8_STRING, value.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] ia5String(String value) {
        return tlv(TAG_IA5_STRING, value.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * UTCTime，固定使用 GMT + 秒 + Z。本项目叶子证书有效期在当前时间 ± 数天，
     * 不会跨越 2050 年，因此无需 GeneralizedTime。
     */
    public static byte[] utcTime(Date value) {
        SimpleDateFormat format = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US);
        format.setTimeZone(TimeZone.getTimeZone("GMT"));
        return tlv(TAG_UTC_TIME, format.format(value).getBytes(StandardCharsets.US_ASCII));
    }

    public static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] array : arrays) {
            total += array.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, out, offset, array.length);
            offset += array.length;
        }
        return out;
    }

    /** 一个已解析的 TLV 位置信息。 */
    public static final class Tlv {
        public final int tag;
        public final int start;
        public final int valueOffset;
        public final int end;

        Tlv(int tag, int start, int valueOffset, int end) {
            this.tag = tag;
            this.start = start;
            this.valueOffset = valueOffset;
            this.end = end;
        }

        public byte[] value(byte[] data) {
            byte[] out = new byte[end - valueOffset];
            System.arraycopy(data, valueOffset, out, 0, out.length);
            return out;
        }
    }

    /** 读取 offset 处的 TLV，支持长格式长度。 */
    public static Tlv read(byte[] data, int offset) {
        if (data == null || offset < 0 || offset + 2 > data.length) {
            throw new IllegalArgumentException("DER 数据不完整");
        }
        int tag = data[offset] & 0xFF;
        int first = data[offset + 1] & 0xFF;
        int length;
        int valueOffset;
        if (first < 0x80) {
            length = first;
            valueOffset = offset + 2;
        } else {
            int count = first & 0x7F;
            if (count == 0) {
                throw new IllegalArgumentException("不支持不定长 DER");
            }
            if (count > 4) {
                throw new IllegalArgumentException("DER 长度字段过长");
            }
            length = 0;
            for (int i = 0; i < count; i++) {
                length = (length << 8) | (data[offset + 2 + i] & 0xFF);
            }
            valueOffset = offset + 2 + count;
        }
        int end = valueOffset + length;
        if (length < 0 || end < valueOffset || end > data.length) {
            throw new IllegalArgumentException("DER 长度越界");
        }
        return new Tlv(tag, offset, valueOffset, end);
    }

    public static List<Tlv> children(byte[] data, Tlv parent) {
        List<Tlv> out = new ArrayList<>();
        int offset = parent.valueOffset;
        while (offset < parent.end) {
            Tlv child = read(data, offset);
            out.add(child);
            if (child.end <= offset) {
                throw new IllegalArgumentException("DER 子项长度非法");
            }
            offset = child.end;
        }
        return out;
    }

    public static String decodeOid(byte[] data, Tlv oidTlv) {
        if (oidTlv.tag != TAG_OID || oidTlv.valueOffset >= oidTlv.end) {
            throw new IllegalArgumentException("不是有效的 OID");
        }
        int firstByte = data[oidTlv.valueOffset] & 0xFF;
        int first;
        int second;
        if (firstByte < 40) {
            first = 0;
            second = firstByte;
        } else if (firstByte < 80) {
            first = 1;
            second = firstByte - 40;
        } else {
            first = 2;
            second = firstByte - 80;
        }
        StringBuilder out = new StringBuilder();
        out.append(first).append('.').append(second);
        long value = 0;
        boolean pending = false;
        for (int i = oidTlv.valueOffset + 1; i < oidTlv.end; i++) {
            int b = data[i] & 0xFF;
            value = (value << 7) | (b & 0x7F);
            pending = true;
            if ((b & 0x80) == 0) {
                out.append('.').append(value);
                value = 0;
                pending = false;
            }
        }
        if (pending) {
            throw new IllegalArgumentException("OID 编码不完整");
        }
        return out.toString();
    }

    private static void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 0x80) {
            out.write(length);
            return;
        }
        int bytes = 1;
        int tmp = length;
        while ((tmp >>= 8) != 0) {
            bytes++;
        }
        out.write(0x80 | bytes);
        for (int i = bytes - 1; i >= 0; i--) {
            out.write((length >> (8 * i)) & 0xFF);
        }
    }

    private static void writeBase128(ByteArrayOutputStream out, long value) {
        if (value < 0) {
            throw new IllegalArgumentException("OID 分量不能为负");
        }
        int count = 1;
        long tmp = value;
        while ((tmp >>= 7) != 0) {
            count++;
        }
        for (int i = count - 1; i >= 0; i--) {
            int b = (int) ((value >> (7 * i)) & 0x7F);
            if (i > 0) {
                b |= 0x80;
            }
            out.write(b);
        }
    }
}
