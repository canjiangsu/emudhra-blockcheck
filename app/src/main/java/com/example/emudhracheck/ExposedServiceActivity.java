package com.example.emudhracheck;

import android.Manifest;
import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;
import com.example.emudhracheck.expose.ExposedServerState;
import java.util.List;

/** 对外 TLS 验证服务控制页。 */
public final class ExposedServiceActivity extends Activity {

    private static final int REQUEST_NOTIFICATIONS = 100;

    private final ExposedServerState state = ExposedServerState.INSTANCE;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable poll = new Runnable() {
        @Override
        public void run() {
            refresh();
            handler.postDelayed(this, 1000);
        }
    };

    private Button toggleButton;
    private Button copyButton;
    private CheckBox lanCheck;
    private TextView statusText;
    private TextView addressesText;
    private ExposedPortAdapter adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_exposed_service);

        toggleButton = findViewById(R.id.button_expose_toggle);
        copyButton = findViewById(R.id.button_expose_copy);
        lanCheck = findViewById(R.id.checkbox_lan);
        statusText = findViewById(R.id.expose_status);
        addressesText = findViewById(R.id.expose_addresses);
        ListView portList = findViewById(R.id.expose_ports);

        adapter = new ExposedPortAdapter(this, state.snapshot());
        portList.setAdapter(adapter);

        lanCheck.setChecked(state.isLanEnabled());
        toggleButton.setOnClickListener(v -> toggleService());
        copyButton.setOnClickListener(v -> copyUrls());

        refresh();
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(poll);
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(poll);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        handler.removeCallbacks(poll);
        super.onDestroy();
    }

    private void toggleService() {
        boolean busy = state.isRunning() || state.isStarting();
        if (busy) {
            stopService(new Intent(this, ExposedVerificationService.class));
            state.setRunning(false);
            state.setStarting(false);
            refresh();
            handler.postDelayed(this::refresh, 500);
            return;
        }

        boolean lan = lanCheck.isChecked();
        requestNotificationPermissionIfNeeded();
        try {
            Intent intent = new Intent(this, ExposedVerificationService.class)
                    .setAction(ExposedVerificationService.ACTION_START)
                    .putExtra(ExposedVerificationService.EXTRA_LAN, lan);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent);
            } else {
                startService(intent);
            }
            state.setStarting(true);
            state.setRunning(false);
            state.setLastError(null);
        } catch (Exception e) {
            state.setStarting(false);
            state.setRunning(false);
            state.setLastError(shortMessage(e));
        }
        refresh();
        handler.postDelayed(this::refresh, 500);
    }

    private void refresh() {
        List<ExposedServerState.PortStatus> ports = state.snapshot();
        adapter.setPorts(ports);

        boolean busy = state.isRunning() || state.isStarting();
        toggleButton.setText(busy ? R.string.expose_stop : R.string.expose_start);
        lanCheck.setEnabled(!busy);

        if (state.isStarting()) {
            statusText.setText(R.string.expose_starting);
        } else if (state.isRunning()) {
            statusText.setText(getString(R.string.expose_running, state.getBindDescription()));
        } else if (state.getLastError() != null) {
            statusText.setText(getString(R.string.expose_start_failed, state.getLastError()));
        } else {
            statusText.setText(R.string.expose_stopped);
        }

        String addresses = state.getLocalAddresses().isEmpty()
                ? getString(R.string.expose_unknown)
                : TextUtils.join("，", state.getLocalAddresses());
        addressesText.setText(getString(R.string.expose_addresses, addresses));
        copyButton.setEnabled(true);
    }

    private void copyUrls() {
        List<ExposedServerState.PortStatus> ports = state.snapshot();
        StringBuilder out = new StringBuilder();
        out.append(getString(R.string.expose_title)).append('\n');
        out.append("绑定：").append(state.getBindDescription()).append('\n');
        out.append("本机地址：")
                .append(state.getLocalAddresses().isEmpty()
                        ? getString(R.string.expose_unknown)
                        : TextUtils.join("，", state.getLocalAddresses()))
                .append('\n');
        out.append("端口映射：\n");

        int firstPort = ExposedServerState.BASE_PORT;
        boolean first = true;
        for (ExposedServerState.PortStatus status : ports) {
            int port = status.port != 0 ? status.port : status.requestedPort;
            if (first) {
                firstPort = port == 0 ? ExposedServerState.BASE_PORT : port;
                first = false;
            }
            out.append(port).append("  ").append(status.name).append('\n');
        }

        String lanAddress = null;
        for (String address : state.getLocalAddresses()) {
            if (!address.startsWith("127.") && !"::1".equals(address)) {
                lanAddress = address;
                break;
            }
        }

        out.append("\n示例（客户端必须使用自己的信任库，不能加 -k）：\n");
        out.append("curl --cacert aaa-certificate-services.pem https://127.0.0.1:")
                .append(firstPort).append("/\n");
        if (lanAddress != null) {
            out.append("curl --cacert aaa-certificate-services.pem https://")
                    .append(lanAddress).append(':').append(firstPort).append("/\n");
        }
        out.append("注意：握手失败也可能只是客户端不信任 AAA 根。\n");

        ClipboardManager clipboard =
                (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(ClipData.newPlainText("eMudhra exposed service", out.toString()));
        Toast.makeText(this, R.string.expose_copied, Toast.LENGTH_SHORT).show();
    }

    private void requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                        != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},
                    REQUEST_NOTIFICATIONS);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions,
            int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQUEST_NOTIFICATIONS
                && grantResults.length > 0
                && grantResults[0] != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(this, R.string.expose_permission_denied, Toast.LENGTH_LONG).show();
        }
    }

    private static String shortMessage(Throwable throwable) {
        String message = throwable.getMessage();
        String text = throwable.getClass().getSimpleName()
                + (message == null || message.isEmpty() ? "" : ": " + message);
        return text.length() <= 160 ? text : text.substring(0, 160) + "…";
    }
}
