package com.example.emudhracheck;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import com.example.emudhracheck.expose.ExposedServerState;
import com.example.emudhracheck.expose.ExposedTlsServer;
import com.example.emudhracheck.verify.AndroidAssets;
import com.example.emudhracheck.verify.CaEntry;
import com.example.emudhracheck.verify.CaRepository;
import java.security.SecureRandom;
import java.util.List;

/**
 * 前台 Service：保持对外 TLS 验证端点常驻。
 *
 * <p>仅由用户从界面启动；绑定 127.0.0.1 或（显式开启时）所有接口。停止后立即关闭
 * 所有监听 socket。</p>
 */
public final class ExposedVerificationService extends Service {

    public static final String ACTION_START = "com.example.emudhracheck.action.START_EXPOSE";
    public static final String ACTION_STOP = "com.example.emudhracheck.action.STOP_EXPOSE";
    public static final String EXTRA_LAN = "lan";

    private static final String CHANNEL_ID = "exposed_tls";
    private static final int NOTIFICATION_ID = 42;

    private final ExposedServerState state = ExposedServerState.INSTANCE;
    private ExposedTlsServer server;
    private Thread startThread;
    private volatile int generation;
    private volatile boolean destroyed;

    @Override
    public void onCreate() {
        super.onCreate();
        createChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopServer();
            stopForeground(true);
            stopSelf();
            return START_NOT_STICKY;
        }

        boolean lan = intent != null && intent.getBooleanExtra(EXTRA_LAN, false);
        startForeground(NOTIFICATION_ID, buildNotification(getString(
                R.string.expose_notification_starting,
                getString(lan ? R.string.expose_lan_mode : R.string.expose_loopback_mode))));
        startServer(lan);
        return START_NOT_STICKY;
    }

    private synchronized void startServer(boolean lan) {
        stopServer();
        final int myGeneration = ++generation;
        state.setLanEnabled(lan);
        state.setStarting(true);
        state.setRunning(false);
        state.setLastError(null);

        startThread = new Thread(() -> {
            try {
                List<CaEntry> entries = CaRepository.load(AndroidAssets.reader(this));
                ExposedTlsServer newServer = ExposedTlsServer.start(entries, lan,
                        ExposedServerState.BASE_PORT, state, new SecureRandom());
                synchronized (ExposedVerificationService.this) {
                    if (destroyed || myGeneration != generation) {
                        newServer.stop();
                        return;
                    }
                    server = newServer;
                }
                updateNotification();
            } catch (Throwable throwable) {
                if (myGeneration == generation) {
                    state.setStarting(false);
                    state.setRunning(false);
                    state.setLastError(shortError(throwable));
                    updateNotification();
                }
            }
        }, "emudhra-expose-start");
        startThread.setDaemon(true);
        startThread.start();
    }

    private synchronized void stopServer() {
        generation++;
        if (server != null) {
            server.stop();
            server = null;
        }
        state.setRunning(false);
        state.setStarting(false);
    }

    @Override
    public void onDestroy() {
        destroyed = true;
        stopServer();
        stopForeground(true);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID,
                    getString(R.string.expose_notification_channel),
                    NotificationManager.IMPORTANCE_LOW);
            channel.setDescription(getString(R.string.expose_subtitle));
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    private Notification buildNotification(String text) {
        Intent openIntent = new Intent(this, ExposedServiceActivity.class);
        PendingIntent contentIntent = PendingIntent.getActivity(this, 1, openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | immutableFlag());

        Intent stopIntent = new Intent(this, ExposedVerificationService.class)
                .setAction(ACTION_STOP);
        PendingIntent stopPendingIntent = PendingIntent.getService(this, 2, stopIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | immutableFlag());

        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        builder.setSmallIcon(R.drawable.ic_notification)
                .setContentTitle(getString(R.string.expose_notification_title))
                .setContentText(text)
                .setOngoing(true)
                .setContentIntent(contentIntent)
                .addAction(R.drawable.ic_notification,
                        getString(R.string.expose_notification_stop), stopPendingIntent);
        return builder.build();
    }

    private void updateNotification() {
        String text;
        if (state.isRunning()) {
            text = getString(R.string.expose_notification_running, state.getBindDescription());
        } else if (state.getLastError() != null) {
            text = getString(R.string.expose_notification_failed, state.getLastError());
        } else {
            text = getString(R.string.expose_notification_starting,
                    getString(state.isLanEnabled()
                            ? R.string.expose_lan_mode : R.string.expose_loopback_mode));
        }
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, buildNotification(text));
        }
    }

    private static int immutableFlag() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
                ? PendingIntent.FLAG_IMMUTABLE : 0;
    }

    private static String shortError(Throwable throwable) {
        String message = throwable.getMessage();
        String text = throwable.getClass().getSimpleName()
                + (message == null || message.isEmpty() ? "" : ": " + message);
        return text.length() <= 160 ? text : text.substring(0, 160) + "…";
    }
}
