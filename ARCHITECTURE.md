# OMNIT VPN: Adaptive Routing 2.0 Architecture

OMNIT VPN is a direct-first Linux desktop VPN client built on top of Qt 6, sing-box 1.13, and Xray-core. It provides autonomous, per-service multi-region routing without requiring manual whitelists, continuous reconnects, or intrusive traffic inspection.

## 1. System Landscape

```text
               +----------------------------------------------------+
               |              Desktop / Applications                |
               +----------------------------------------------------+
                                         |
                                         v
                         +-------------------------------+
                         |      OMNIT sing-box TUN       |
                         |   (Split DNS + Local Rules)   |
                         +-------------------------------+
                                         |
            +----------------------------+----------------------------+
            |                            |                            |
      Level 1, 3, 5                Level 4, 6                      Level 2
      (Direct / RU)             (Multi-Egress)                 (User Pinned)
            |                            |                            |
            v                            v                            v
     +--------------+           +------------------+         +------------------+
     | Direct Egress|           |   Starter Pool   |         |  Target Egress   |
     |  (Physical)  |           | (NL / DE / US)   |         |   (Selected)     |
     +--------------+           +------------------+         +------------------+
```

## 2. 6-Level Routing Priority Hierarchy

Every outgoing request is resolved through a strict 6-level policy hierarchy:

1. **[System Bypass]**: LAN (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), `.local`, `.lan`, internal IPC $\to$ **`direct`**.
2. **[User Pinned Rules]**: Explicit rules configured by the owner in UI/CLI $\to$ **Highest Priority Outbound**.
3. **[Protected Russian Services]**: Gosuslugi, Sber, T-Bank, VTB, Alfa, mos.ru, nalog.ru, etc. $\to$ **Strict `direct`** (immune to automatic failover).
4. **[Adaptive Route Cache]**: Verified routing decisions stored in SQLite (`adaptive_routing.db`) with active TTL $\to$ **Cached Outbound** (`proxy-nl`, `proxy-de`, `proxy-us`, `direct`).
5. **[Regional Hints]**: `*.ru`, `*.рф`, `*.su` domains $\to$ **Default `direct`**, but eligible for autonomous diagnostic healing if confirmed unreachable.
6. **[Default Outbound Proxy]**: All other foreign SaaS, CDN, and international endpoints $\to$ **Primary VPN Pool** (`proxy-nl` or lowest latency node).

## 3. Multi-Egress Starter Pool

Instead of running all servers simultaneously or switching the entire system to a single country:
- OMNIT maintains a lightweight starter pool of 3 key exit countries concurrently:
  - 🇳🇱 **Netherlands (`proxy-nl`)**: SOCKS bridge `127.0.0.1:22101` (Default)
  - 🇩🇪 **Germany (`proxy-de`)**: SOCKS bridge `127.0.0.1:22102`
  - 🇺🇸 **United States (`proxy-us`)**: SOCKS bridge `127.0.0.1:22103`
- Additional countries are brought up on-demand without interrupting existing tunnels.
- Memory footprint: ~32 MB RSS per active Xray node; idle CPU: 0.0%.

## 4. Hot Rule Updates (Zero-Downtime Re-routing)

- sing-box local `rule_set` definitions (`rules_adaptive_nl.json`, `rules_adaptive_de.json`, `rules_adaptive_us.json`, `rules_adaptive_direct.json`) are watched by the core.
- The Python Adaptive Router writes rule updates atomically using `mkstemp` $\to$ `fsync` $\to$ `os.replace`.
- Route migrations take effect immediately for new connections without recreating `throne-tun` or terminating active TCP sessions.

## 5. Honest Error Detection & Rate-Limited Probing

The router distinguishes between kernel/network failures and application errors:
- **Transport / Kernel Errors**: TCP RST, connection refused, SYN timeout, DNS failures $\to$ Detected by core dialer, triggering candidate probing.
- **Application Geoblocking**: HTTP 403, Cloudflare turnstile, application-level block $\to$ Handled via manual "Fix Access" UI trigger.
- **Probe Guardrails**:
  - Max 30 diagnostic probes per hour.
  - Max 2 candidate countries tested per failure event.
  - Exponential backoff for persistently failing targets.
  - Zero leakage: no authentication cookies, tokens, or POST payloads are ever sent in probes.

## 6. Linux Networking & Routing Loop Prevention

- Physical interface detection uses `netlink.RouteGet` to identify the active gateway (`enp4s0` or Wi-Fi `wlan*`).
- Outgoing proxy transport binds to the active physical interface, avoiding routing loops inside `throne-tun`.
- Linux `fwmark` avoids collision with sing-box default mark `0x2024`.

