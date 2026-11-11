package com.example.emudhracheck.expose;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 收集对外 TLS 服务可用的本机地址。
 *
 * <p>叶子证书 SAN 只覆盖本机回环与网卡地址，绝不接受任意域名或远端提供的名称。
 * 链接本地（link-local）地址依赖 scope，SAN 无法可靠表达，故不加入证书。</p>
 */
public final class LocalAddresses {

    public static final class SanSet {
        public final List<String> dnsNames;
        public final List<byte[]> ipAddresses;
        public final List<String> displayAddresses;

        SanSet(List<String> dnsNames, List<byte[]> ipAddresses, List<String> displayAddresses) {
            this.dnsNames = dnsNames;
            this.ipAddresses = ipAddresses;
            this.displayAddresses = displayAddresses;
        }
    }

    private LocalAddresses() {
    }

    public static SanSet collect() {
        Map<String, byte[]> addresses = new LinkedHashMap<>();
        addresses.put("127.0.0.1", new byte[]{127, 0, 0, 1});
        addresses.put("::1", new byte[]{
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});

        try {
            for (NetworkInterface networkInterface
                    : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (networkInterface == null || !networkInterface.isUp()) {
                    continue;
                }
                for (InetAddress address
                        : Collections.list(networkInterface.getInetAddresses())) {
                    if (!isSuitableForSan(address)) {
                        continue;
                    }
                    addresses.put(display(address), address.getAddress());
                }
            }
        } catch (SocketException ignored) {
            // 仅使用已经收集到的回环地址。
        }

        List<String> displayAddresses = new ArrayList<>(addresses.keySet());
        List<byte[]> ipAddresses = new ArrayList<>(addresses.values());
        List<String> dnsNames = Collections.singletonList("localhost");
        return new SanSet(dnsNames, ipAddresses, displayAddresses);
    }

    /** 局域网模式只接受回环与私有/链接本地来源，避免在公网地址上意外暴露。 */
    public static boolean isAllowedSource(InetAddress address) {
        if (address == null) {
            return false;
        }
        if (address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()) {
            return true;
        }
        // Java 的 isSiteLocalAddress 只识别已废弃的 fec0::/10；额外接受 fc00::/7 ULA。
        if (address instanceof Inet6Address) {
            byte first = address.getAddress()[0];
            return (first & 0xFE) == 0xFC;
        }
        return false;
    }

    private static boolean isSuitableForSan(InetAddress address) {
        if (address == null || address.isAnyLocalAddress() || address.isMulticastAddress()) {
            return false;
        }
        // 链接本地地址的 scope 无法写入 iPAddress SAN，客户端难以匹配。
        return !address.isLinkLocalAddress();
    }

    private static String display(InetAddress address) {
        String hostAddress = address.getHostAddress();
        int scope = hostAddress.indexOf('%');
        return scope >= 0 ? hostAddress.substring(0, scope) : hostAddress;
    }
}
