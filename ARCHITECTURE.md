# OMNIT VPN: Architecture & Technical Specification

> **Direct-First Autonomous Selective VPN with Concurrent Multi-Egress and 3-Tier Reachability Probing**

---

## 1. Executive Summary & Design Philosophy

Traditional desktop VPN clients follow a monolithic "all-or-nothing" paradigm: when enabled, 100% of the operating system's traffic is encapsulated and routed through a single remote server. In environments where local domestic services (e.g., government portals, banking, domestic CDNs) block foreign IP addresses while international development platforms and SaaS services block or throttle domestic IP addresses, this approach fails.

**OMNIT VPN** implements a **Direct-First Selective Routing Engine** designed natively for Linux workstations. Instead of manual proxy switching or brittle static IP lists, OMNIT VPN provides:
1. **Concurrent Multi-Egress Routing**: Simultaneous live tunnels to multiple jurisdictions (e.g., Netherlands, Germany, United States, and Russian Direct Internet) terminating within a single system `throne-tun` interface.
2. **Autonomous Adaptive Routing 2.0**: A 6-level priority resolution engine that continuously monitors connection health, harvesting passive network error telemetry and performing active 3-tier reachability probes to heal failed routes without human intervention.
3. **Zero-Downtime Atomic Rule Synchronization**: Instant route migration for new connections via atomic file replacements watched by the sing-box core, preserving active TCP streams and eliminating interface flaps.
4. **Strict Privacy & Anti-Spam Guardrails**: Diagnostic probing strictly enforces zero leakage of user cookies, tokens, or request bodies, bounded by a strict sliding-window rate limiter (max 30 probes/hour).

---

## 2. Component Topology & IPC Architecture

OMNIT VPN is engineered as a decoupled multi-process architecture with strict separation of concerns, least-privilege boundaries, and resilient IPC channels:

```
+---------------------------------------------------------------------------------------+
|                                    USER SPACE                                         |
|                                                                                       |
|   +--------------------------+                         +--------------------------+   |
|   |   omnit-vpn (Qt 6 GUI)   | <---- UNIX Socket ----> |    Omnit Control Center  |   |
|   |    Desktop Application   |     OMNIT-CONTROL/1     |     Desktop Platform     |   |
|   +--------------------------+                         +--------------------------+   |
|                 |                                                    |                |
|           UNIX Domain IPC                                            |                |
|             (Protobuf)                                               |                |
|                 v                                                    v                |
|   +--------------------------+                         +--------------------------+   |
|   |  ThroneCore (Go Backend) |                         |   omnit-vpn-guard.service|   |
|   |  sing-box 1.13 + Xray    |                         |   Always-On Watchdog     |   |
|   +--------------------------+                         +--------------------------+   |
|          |             |                                             |                |
|          |      Multi-Egress SOCKS                                   |                |
|          |     (127.0.0.1:22101..3)                                  |                |
|          |             |                                             |                |
|          |             v                                             v                |
|          |   +--------------------------+ <==== SQLite (WAL) ===+-----------------+   |
|          |   |  Multi-Xray Instances    |   adaptive_routing.db | omnit-adaptive- |   |
|          |   |  (NL / DE / US Nodes)    |                       | router.service  |   |
|          |   +--------------------------+                       | (Python Daemon) |   |
|          |                 |                                    +-----------------+   |
|          |                 |                                             |            |
|          |        Atomic JSON Rule-Sets <--------------------------------+            |
|          |     (rules_adaptive_*.json)                                                |
|          v                                                                            |
+----------+----------------------------------------------------------------------------+
|          v                                                                            |
|   +--------------+                 LINUX KERNEL                                       |
|   |  throne-tun  |                                                                    |
|   |  172.19.0.1  | ---- RPDB Policy Table 2022 ----> Physical NIC (enp4s0 / Wi-Fi)    |
|   +--------------+                                                                    |
+---------------------------------------------------------------------------------------+
```

### IPC Channel Specifications

| Channel | Transport | Protocol | Security & Access | Responsibility |
| :--- | :--- | :--- | :--- | :--- |
| **GUI $\leftrightarrow$ Core** | Local UNIX Socket (`/tmp/throneIPC-<uuid>`) | Protobuf / gRPC Unary & Streams | Peer PID verification (`SO_PEERCRED`), user-only permissions (`0600`) | Lifecycle control, real-time traffic counters, log streaming, DNS management |
| **Owner API Socket** | UNIX Domain Socket (`/tmp/throne-<hash>`) | Line-delimited JSON (`OMNIT-CONTROL/1`) | User UID check, strict payload validation, secret redaction | Desktop shell automation, status snapshots, single-instance activation |
| **Router $\leftrightarrow$ Core** | Local Filesystem Watch (`IN_CLOSE_WRITE`) | Atomic JSON Rule-Sets (`rules_adaptive_*.json`) | User-owned directory (`~/.local/share/omnit/rules/`), atomic `os.replace` | Hot route injection into sing-box routing engine without process restart |
| **Telemetry Watcher**| File Stream Tail (`seek` + polling) | Structured Log Parsing (`throne.log`) | Read-only log tail, rotation/truncation detection | Passive harvesting of DNS exchanges and transport socket errors |

---

## 3. Linux Kernel Networking & Routing Policy Engine

OMNIT VPN operates at Layer 3 using a virtual TUN device (`throne-tun`) and Linux Policy Routing (RPDB).

```
                                  OS Outgoing Packet
                                          |
                                          v
                         +----------------------------------+
                         |     FWMARK Check (ip rule)       |
                         +----------------------------------+
                                     /          \
                       fwmark 0x2024 /            \ No Mark / 0x2023
                                    /              \
                                   v                v
                        +--------------------+   +--------------------+
                        | Physical Interface |   |     Table 2022     |
                        | (Bypasses TUN)     |   |    dev throne-tun  |
                        +--------------------+   +--------------------+
                                   ^                        |
                                   |                        v
                                   |             +--------------------+
                                   +------------ | sing-box Routing   |
                             Proxy Outbound      | (Adaptive / Direct)|
                             with fwmark 0x2024  +--------------------+
```

### Routing Policy Rules & Table Decomposition

The system installs three critical routing rules:
1. `9000: from all fwmark 0x2024 goto 9002`: Packets emitted by the VPN core itself carry `fwmark 0x2024` (or SO_BINDTODEVICE). This jumps past table 2022 directly to the main routing table, preventing catastrophic routing loops.
2. `9001: from all fwmark 0x2023 lookup 2022`: Redirected socket connections look up custom routing table 2022.
3. `32768: from all lookup 2022`: Default catch-all for system traffic.

### Table 2022 Structure
Instead of replacing the default route `0.0.0.0/0` (which would disrupt DHCP and local interfaces), table 2022 decomposes the entire IPv4 address space into specific prefixes routed via `172.19.0.2 dev throne-tun`:
- `0.0.0.0/5`, `8.0.0.0/7`, `11.0.0.0/8`, `12.0.0.0/6`, `16.0.0.0/4`, `32.0.0.0/3`, `64.0.0.0/3`, `128.0.0.0/3`...
- **RFC1918 Private Ranges Excluded**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` and loopback `127.0.0.0/8` are never sent to table 2022, ensuring local LAN devices, printers, and Hypervisors remain directly accessible.

### Privilege Architecture & Reboot Resilience
Creating and configuring a TUN device requires Linux network administration rights. OMNIT VPN supports two privilege mechanisms:
1. **Linux File Capabilities**: `setcap cap_net_admin,cap_net_bind_service+ep ThroneCore`
2. **SUID Root Execution**: `chmod 4755 ThroneCore` (`os.Geteuid() == 0`)

#### Root Cause of Reboot Lockout & Permanent Solution
* **The Flaw**: On cold system boot, `omnit-vpn-guard` starts immediately upon graphical session initialization. It requests TUN activation while `ThroneCore` is still completing its initial gRPC bootstrap (a 100–300 ms window). In older versions, `Configs::IsAdmin()` cached `0` (`false`) upon the first failed handshake. Once cached, `IsAdmin()` permanently returned `false` for the remainder of the session, locking the application into `core_privileges_required`.
* **The Fix**: 
  1. `Configs::IsAdmin()` now implements **monotonic positive-only caching**: only a verified elevated status (`admin == true`) is cached (`isAdminCache = 1`). Failures retain `isAdminCache = -1`, ensuring subsequent queries re-evaluate the core.
  2. When the core socket establishes (`connect(core_server, &QLocalServer::newConnection, ...)`), `m_privilegeRequired` is automatically cleared.
  3. Deep link request handlers explicitly re-check `Configs::IsAdmin(true)`, permanently preventing unattended startup lockouts.

---

## 4. 6-Level Priority Routing Engine

Every domain or IP target is evaluated through a deterministic 6-level hierarchy:

```
Target Domain / IP
       |
       v
[Level 1: System Bypass] ---------> MATCH? ---> DIRECT (Bypass)
       | No
       v
[Level 2: User Pinned Rules] -----> MATCH? ---> Target Outbound (NL/DE/US/RU)
       | No
       v
[Level 3: Protected Domestic] ----> MATCH? ---> STRICT DIRECT (Locked)
       | No
       v
[Level 4: Adaptive Route Cache] --> MATCH? ---> Verified Egress (TTL valid)
       | No
       v
[Level 5: Regional Hints (*.ru)] -> MATCH? ---> DIRECT (Eligible for auto-heal)
       | No
       v
[Level 6: Default Outbound] ------------------> Primary VPN Pool (proxy-nl)
```

| Level | Policy Tier | Examples | Routing Action | Failover Permitted? |
| :---: | :--- | :--- | :--- | :---: |
| **1** | **System Bypass** | `localhost`, `127.0.0.1`, `192.168.0.0/16`, `.local`, `.lan` | `direct` | No |
| **2** | **User Pinned Rules** | User explicitly pins `whop.com -> US` or `work.corp -> DE` | Assigned Outbound | No (Manual override) |
| **3** | **Protected Domestic Services** | `gosuslugi.ru`, `sberbank.ru`, `nalog.ru`, `cbr.ru`, `mos.ru` | `direct` | **STRICTLY NO** (Prevents account lockouts) |
| **4** | **Adaptive Cache** | Previously diagnosed and verified routes (`confidence = 'verified'`) | Cached Outbound | Yes (if failures re-occur) |
| **5** | **Regional Domestic Hints** | `*.ru`, `*.рф`, `*.su` | `direct` | **Yes** (Heals if blocked by provider) |
| **6** | **Default Outbound** | International SaaS, GitHub, OpenAI, Claude, Figma, CDNs | `proxy-nl` | **Yes** (Probes alternative nodes on error) |

---

## 5. 3-Tier Active Reachability Probing Engine

### The Flaw with Naive SOCKS5 Probing
Standard SOCKS5 CONNECT to port 443 only proves that a TCP handshake completed between the local proxy client and the remote proxy server. It **does not** verify that:
1. The remote proxy successfully reached the origin web server.
2. The TLS handshake completed without DPI interception, SNI filtering, or TCP RST injection.
3. The origin server returned a valid response rather than an HTTP 403 / 451 censorship block page.

### OMNIT 3-Tier Verification Engine

```
+-----------------------------------------------------------------------------------+
|                        3-TIER ACTIVE REACHABILITY PROBE                           |
+-----------------------------------------------------------------------------------+
|  [TIER 1: TCP & SOCKS5 Handshake]                                                 |
|  - SOCKS5 Greeting (VER=5, NMETHODS=1, NO_AUTH)                                   |
|  - SOCKS5 CONNECT (CMD=1, ATYP=3 [Domain], PORT=443)                              |
|  - Result: Verifies egress node connectivity & tunnel transport.                   |
+-----------------------------------------------------------------------------------+
                                          | Success
                                          v
+-----------------------------------------------------------------------------------+
|  [TIER 2: TLS 1.2 / 1.3 SNI Handshake]                                            |
|  - Python ssl.create_default_context() wraps active socket                       |
|  - Sends TLS ClientHello with Server Name Indication (SNI) = domain                |
|  - Result: Verifies TLS negotiation succeeds without DPI RST or TLS alert blocks.  |
+-----------------------------------------------------------------------------------+
                                          | Success
                                          v
+-----------------------------------------------------------------------------------+
|  [TIER 3: HTTP HEAD Status Verification]                                          |
|  - Sends HEAD / HTTP/1.1 with Host: domain and User-Agent: OMNIT-Probe/2.0        |
|  - Parses HTTP status code:                                                       |
|    * 200, 204, 301, 302, 307, 308, 400, 404, 405 -> REACHABLE (Origin verified)    |
|    * 403, 451, Cloudflare turnstile -> BLOCKED (Trigger candidate failover)       |
+-----------------------------------------------------------------------------------+
```

### Probe Guardrails & Privacy Guarantee
* **Hourly Budget Limit**: Hard cap of `MAX_HOURLY_PROBES = 30` per sliding 60-minute window. Prevents probing storms and protects user exit bandwidth.
* **Candidate Bounding**: `MAX_CANDIDATE_TRIES = 2`. Diagnoses test at most 2 alternative countries per failure incident before backing off.
* **In-Flight Debounce Lock**: If 20 page assets fail concurrently for the same domain, `_in_flight_lock` ensures only **one** probe routine executes; subsequent calls receive `debounced_in_flight`.
* **Zero Leakage**: Probes strictly transmit synthetic `HEAD /` requests with standard headers. No cookies, authorization headers, session tokens, or POST payloads are ever generated.

---

## 6. Real-Time Network Error Event Source (`LogEventWatcher`)

Periodic polling is inadequate for responsive routing: a user encountering a blocked site cannot wait 60 seconds for a scheduled health check.

OMNIT VPN incorporates an event-driven telemetry harvester:
1. **Inverse DNS Cache**: Continuously tails the core log (`throne.log`). Upon seeing `dns: exchanged A <domain> -> <ip>`, records an in-memory mapping `ip -> (domain, timestamp)` with a 10-minute TTL.
2. **Error Interception**: Scans for outbound socket errors:
   - `connection reset by peer`
   - `read: connection timed out`
   - `dial tcp ...: i/o timeout`
   - `handshake failed`
   - `connect: connection refused`
3. **Correlation & Debounce**: When a socket error occurs for an IP, resolves it to the source domain. If $\ge 2$ errors occur for the same domain within 60 seconds, dispatches an autonomous `asyncio.create_task(engine.diagnose_and_heal(domain))`.
4. **Log Rotation Resilience**: Monitors file size via `os.path.getsize`. If `f.tell() > curr_size` (indicating log truncation or rotation), automatically seeks back to offset `0`.

---

## 7. Multi-Egress Node Lifecycle & Supervisor

### Concurrent Node Pool

| Outbound Tag | Country | Code | SOCKS Bridge Port | Default State | Role |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `direct` | Russian Federation | RU | Physical NIC | Always Up | Domestic banking, state services, fast direct internet |
| `proxy-nl` | Netherlands | NL | `127.0.0.1:22101` | Supervised | Primary international SaaS, GitHub, OpenAI, Claude |
| `proxy-de` | Germany | DE | `127.0.0.1:22102` | Supervised | European failover, European streaming, low-latency CDN |
| `proxy-us` | United States | US | `127.0.0.1:22103` | Supervised | US-only platforms, AWS/GCP developer endpoints |

### Supervisor Goroutine (`superviseMultiXray`)
In [`core/server/server.go`](file:///home/rus/dev/rixed-net/core/server/server.go), a dedicated background goroutine monitors all started multi-egress Xray instances:
```go
func superviseMultiXray(stop chan struct{}) {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-stop: return
        case <-ticker.C:
            multiXrayMu.Lock()
            for i, inst := range multiXrayInstances {
                if (inst == nil || !inst.IsRunning()) && i < len(multiXrayConfigs) {
                    if inst != nil { _ = inst.Close() }
                    newInst, err := xray.CreateXrayInstance(multiXrayConfigs[i])
                    if err == nil {
                        newInst.SetEgressInterface(defaultInterfaceFinder())
                        if startErr := newInst.Start(); startErr == nil {
                            multiXrayInstances[i] = newInst
                        }
                    }
                }
            }
            multiXrayMu.Unlock()
    }
}
```
* **True Crash Detection**: Evaluates `inst.IsRunning()`, capturing silent runtime terminations and closing stale resources.
* **Interface Migration**: Automatically binds recovered instances to the current active physical interface (`defaultInterfaceFinder()`).

---

## 8. Failure Modes & Operational Matrix

| Failure Mode | Detection Mechanism | Recovery Action | User Impact |
| :--- | :--- | :--- | :--- |
| **Foreign Service Blocks Primary Country (e.g. NL)** | 3-Tier Probe returns HTTP 403 or TLS RST | `diagnose_and_heal` probes DE/US; promotes working country in `adaptive_routing.db` | Zero manual action; next page reload routes through working country |
| **Single Xray Node Process Dies** | `superviseMultiXray` detects `!inst.IsRunning()` within 5s | Stale instance closed, rebuilt from config, restarted, rebound to NIC | Automatic recovery in $\le 5$ seconds; temporary retry on affected connections |
| **Operating System Reboot** | `omnit-vpn-guard.service` triggers on login | Reconciles GUI & TUN; non-caching `IsAdmin()` bypasses race condition | Full VPN connectivity established automatically without password prompts |
| **System Log Rotation / Truncation** | `LogEventWatcher` checks `f.tell() > size` | Rewinds file pointer to offset `0` | Seamless continuation of error telemetry harvesting |
| **Domestic Bank Visited** | Level 3 Rule Check in Priority Resolver | Strictly locked to `direct` physical egress | Immune to IP bans, zero captcha verification triggered |
| **Concurrent Domain Probe Burst** | `_in_flight_lock` in `diagnose_and_heal` | First request probes; remaining requests return `debounced_in_flight` | Prevents probe rate-limit exhaustion during complex multi-asset web loads |

---

## 9. Verification & Automated Test Suites

The codebase includes comprehensive verification suites covering unit, integration, and end-to-end routing behavior:

```bash
# 1. 10-Point Core Adaptive Router Verification Suite
python3 tools/omnit_adaptive_router.py test

# 2. Control Boundary & Privilege Escalation Matrix
python3 script/test_control_privileges.py --binary build/Throne --core build/ThroneCore

# 3. Live Interface & DNS Status Check
dig @172.19.0.2 google.com
ip route show table 2022
```
