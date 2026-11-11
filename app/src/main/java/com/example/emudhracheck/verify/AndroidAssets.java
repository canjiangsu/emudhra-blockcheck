package com.example.emudhracheck.verify;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** 把 Android assets 适配成 {@link CaRepository.Reader}，供 Activity 与前台 Service 共用。 */
public final class AndroidAssets {

    private AndroidAssets() {
    }

    public static CaRepository.Reader reader(Context context) {
        return path -> read(context, path);
    }

    public static String read(Context context, String path) throws IOException {
        try (InputStream input = context.getAssets().open(path)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        }
    }
}
