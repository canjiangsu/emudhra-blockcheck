package com.example.emudhracheck.expose;

import com.example.emudhracheck.verify.CaRepository;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 对外 TLS 服务的进程内共享状态。
 *
 * <p>前台 Service 更新，Activity 轮询展示；端口对象在 reset 后保持稳定，计数使用原子类型。</p>
 */
public final class ExposedServerState {

    public static final int BASE_PORT = 18443;
    public static final ExposedServerState INSTANCE = new ExposedServerState();

    public static final class PortStatus {
        public final String name;
        public final int requestedPort;
        public volatile int port;
        public volatile boolean listening;
        public volatile String error;
        public final AtomicLong accepted = new AtomicLong();
        public final AtomicLong rejected = new AtomicLong();
        public final AtomicLong filtered = new AtomicLong();

        PortStatus(String name, int requestedPort) {
            this.name = name;
            this.requestedPort = requestedPort;
            this.port = requestedPort;
        }
    }

    private final List<PortStatus> ports = new ArrayList<>();
    private volatile boolean running;
    private volatile boolean starting;
    private volatile boolean lanEnabled;
    private volatile String bindDescription = "127.0.0.1";
    private volatile List<String> localAddresses = Collections.emptyList();
    private volatile String lastError;

    public ExposedServerState() {
        resetInternal(CaRepository.displayNames(), false, BASE_PORT, false);
    }

    public synchronized void reset(List<String> names, boolean lanEnabled, int basePort) {
        resetInternal(names, lanEnabled, basePort, true);
    }

    private void resetInternal(List<String> names, boolean lanEnabled, int basePort,
            boolean starting) {
        ports.clear();
        for (int i = 0; i < names.size(); i++) {
            ports.add(new PortStatus(names.get(i), basePort == 0 ? 0 : basePort + i));
        }
        this.lanEnabled = lanEnabled;
        this.bindDescription = lanEnabled
                ? "0.0.0.0（所有接口，仅私有来源）"
                : "127.0.0.1";
        this.running = false;
        this.starting = starting;
        this.localAddresses = Collections.emptyList();
        this.lastError = null;
    }

    public synchronized List<PortStatus> snapshot() {
        return new ArrayList<>(ports);
    }

    public synchronized PortStatus port(int index) {
        return ports.get(index);
    }

    public synchronized int size() {
        return ports.size();
    }

    public boolean isRunning() {
        return running;
    }

    public void setRunning(boolean running) {
        this.running = running;
    }

    public boolean isStarting() {
        return starting;
    }

    public void setStarting(boolean starting) {
        this.starting = starting;
    }

    public boolean isLanEnabled() {
        return lanEnabled;
    }

    public void setLanEnabled(boolean lanEnabled) {
        this.lanEnabled = lanEnabled;
    }

    public String getBindDescription() {
        return bindDescription;
    }

    public List<String> getLocalAddresses() {
        return localAddresses;
    }

    public void setLocalAddresses(List<String> localAddresses) {
        this.localAddresses = Collections.unmodifiableList(new ArrayList<>(localAddresses));
    }

    public String getLastError() {
        return lastError;
    }

    public void setLastError(String lastError) {
        this.lastError = lastError;
    }
}
