package com.example.emudhracheck;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.os.Bundle;
import android.widget.Button;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;
import com.example.emudhracheck.tls.ExceptionClassifier;
import com.example.emudhracheck.tls.SystemTrust;
import com.example.emudhracheck.verify.CaEntry;
import com.example.emudhracheck.verify.CaRepository;
import com.example.emudhracheck.verify.ResultFormatter;
import com.example.emudhracheck.verify.VerificationResult;
import com.example.emudhracheck.verify.VerificationRunner;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {

    private static final int TOTAL_CAS = 8;

    private final List<VerificationResult> results = new ArrayList<>();
    private ExecutorService executor;
    private ResultAdapter adapter;
    private Button startButton;
    private Button copyButton;
    private Button shareButton;
    private ProgressBar progressBar;
    private TextView statusText;

    private volatile boolean running;
    private volatile boolean destroyed;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        executor = Executors.newSingleThreadExecutor();
        startButton = findViewById(R.id.button_start);
        copyButton = findViewById(R.id.button_copy);
        shareButton = findViewById(R.id.button_share);
        progressBar = findViewById(R.id.progress);
        statusText = findViewById(R.id.status);
        ListView listView = findViewById(R.id.result_list);

        adapter = new ResultAdapter(this, results);
        listView.setAdapter(adapter);
        progressBar.setMax(TOTAL_CAS);
        progressBar.setProgress(0);
        copyButton.setEnabled(false);
        shareButton.setEnabled(false);
        statusText.setText(R.string.idle);

        startButton.setOnClickListener(v -> startVerification());
        copyButton.setOnClickListener(v -> copyResults());
        shareButton.setOnClickListener(v -> shareResults());
    }

    private void startVerification() {
        if (running) {
            return;
        }
        running = true;
        results.clear();
        adapter.notifyDataSetChanged();
        startButton.setEnabled(false);
        startButton.setText(R.string.running);
        copyButton.setEnabled(false);
        shareButton.setEnabled(false);
        progressBar.setProgress(0);
        statusText.setText(R.string.loading);

        executor.execute(() -> {
            try {
                CaRepository.Reader reader = this::readAsset;
                List<CaEntry> entries = CaRepository.load(reader);

                VerificationRunner runner = new VerificationRunner(
                        entry -> SystemTrust.defaultClientContext(),
                        SystemTrust::isTrustedRoot);

                runner.run(entries, (result, completed, total) -> runOnUiThreadSafe(() -> {
                    results.add(result);
                    adapter.notifyDataSetChanged();
                    progressBar.setProgress(completed);
                    statusText.setText(getString(R.string.progress, completed, total, result.name));
                }));

                runOnUiThreadSafe(() -> finishRun(null));
            } catch (Throwable t) {
                runOnUiThreadSafe(() -> finishRun(t));
            }
        });
    }

    private void finishRun(Throwable failure) {
        running = false;
        startButton.setEnabled(true);
        startButton.setText(R.string.start);

        if (failure != null) {
            progressBar.setProgress(0);
            statusText.setText(getString(R.string.load_failed,
                    ExceptionClassifier.describe(failure)));
            copyButton.setEnabled(!results.isEmpty());
            shareButton.setEnabled(!results.isEmpty());
            return;
        }

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
        statusText.setText(getString(R.string.summary, blocked, notBlocked, unknown, error));
        copyButton.setEnabled(!results.isEmpty());
        shareButton.setEnabled(!results.isEmpty());
    }

    private void copyResults() {
        if (results.isEmpty()) {
            return;
        }
        ClipboardManager clipboard =
                (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(ClipData.newPlainText("eMudhra verification", buildExportText()));
        Toast.makeText(this, R.string.copied, Toast.LENGTH_SHORT).show();
    }

    private void shareResults() {
        if (results.isEmpty()) {
            return;
        }
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_SUBJECT, getString(R.string.app_name));
        intent.putExtra(Intent.EXTRA_TEXT, buildExportText());
        startActivity(Intent.createChooser(intent, getString(R.string.share_title)));
    }

    private String buildExportText() {
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z", Locale.getDefault())
                .format(new Date());
        return ResultFormatter.format(new ArrayList<>(results), deviceInfo(), timestamp);
    }

    private String deviceInfo() {
        StringBuilder out = new StringBuilder();
        out.append(Build.MANUFACTURER).append(' ').append(Build.MODEL)
                .append("，Android ").append(Build.VERSION.RELEASE)
                .append(" (API ").append(Build.VERSION.SDK_INT).append(')');
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            String patch = Build.VERSION.SECURITY_PATCH;
            if (patch != null && !patch.isEmpty()) {
                out.append("，安全补丁 ").append(patch);
            }
        }
        try {
            PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), 0);
            if (info.versionName != null) {
                out.append("，App ").append(info.versionName);
            }
        } catch (Exception ignored) {
            // 版本号仅用于报告，失败不影响验证。
        }
        return out.toString();
    }

    private String readAsset(String path) throws IOException {
        try (InputStream input = getAssets().open(path)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) != -1) {
                output.write(buffer, 0, read);
            }
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private void runOnUiThreadSafe(Runnable action) {
        runOnUiThread(() -> {
            if (!destroyed) {
                action.run();
            }
        });
    }

    @Override
    protected void onDestroy() {
        destroyed = true;
        if (executor != null) {
            executor.shutdownNow();
        }
        super.onDestroy();
    }
}
