# OMNIT VPN

> **Autonomous Selective Linux VPN Client with Multi-Egress Routing, 3-Tier Reachability Probing, and Zero-Downtime Hot Rule Updates.**

[![Platform](https://img.shields.io/badge/platform-Linux-blue.svg)](https://github.com/rixed318/omnit-vpn)
[![Core](https://img.shields.io/badge/core-sing--box%201.13%20%2B%20Xray--core-orange.svg)](https://github.com/rixed318/omnit-vpn)
[![License](https://img.shields.io/badge/license-GPLv3-green.svg)](LICENSE)
[![CI Status](https://img.shields.io/badge/CI-passing-brightgreen.svg)](https://github.com/rixed318/omnit-vpn/actions)
[![Release](https://img.shields.io/badge/release-v2.0.0--alpha.1-blue.svg)](https://github.com/rixed318/omnit-vpn/releases/tag/v2.0.0-alpha.1)

---

## Overview

OMNIT VPN is engineered specifically for Linux workstations requiring simultaneous, low-latency access to domestic services and restricted international platforms. Instead of forcing all operating system traffic through a single foreign gateway (which breaks domestic banking, government portals, and local CDNs) or relying on manual proxy toggling, OMNIT VPN introduces an **autonomous, per-domain selective routing layer**.

Every network connection is evaluated against a deterministic **6-level priority policy**. When transport anomalies or censorship blocks occur, the built-in **3-Tier Reachability Probe** and real-time **Log Event Correlation Engine** identify working exit jurisdictions and update the core routing tables in memory—with zero downtime and zero interface flaps.

---

## Key Capabilities

- **Concurrent Multi-Egress Routing**: Operates concurrent tunnels to multiple jurisdictions (🇳🇱 Netherlands, 🇩🇪 Germany, 🇺🇸 United States, and 🇷🇺 Russian Direct Internet) terminating within a single system `throne-tun` interface.
- **6-Level Deterministic Priority Hierarchy**:
  1. `System Bypass`: Localhost, RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), `.local`, `.lan` strictly bypass the TUN.
  2. `User Pinned Rules`: Manual user overrides configured via CLI/UI with absolute priority.
  3. `Protected Domestic Services`: Critical Russian portals (Gosuslugi, banking, tax services) locked to direct physical egress.
  4. `Adaptive Route Cache`: TTL-validated historical success routes stored in SQLite WAL database.
  5. `Regional Hints`: `*.ru`, `*.рф`, `*.su` default to Direct; autonomously healed if verified blocked.
  6. `Default Outbound`: International development SaaS, AI services, and CDNs routed to the primary international pool.
- **3-Tier Active Reachability Probing**:
  - **Tier 1 (Layer 4)**: SOCKS5 handshake & TCP connect.
  - **Tier 2 (Layer 5/6)**: TLS 1.2/1.3 SNI negotiation (detects DPI handshake resets and SNI filtering).
  - **Tier 3 (Layer 7)**: HTTP `HEAD /` status classification (differentiates genuine 2xx/3xx origins from 403/451 censorship blocks).
- **Event-Driven Auto-Healing (`LogEventWatcher`)**: Passively harvests DNS resolution mappings and correlates connection timeouts/resets to trigger immediate route migration without waiting for periodic polling.
- **Zero-Downtime Rule Updates**: Emits atomic file replacements (`rules_adaptive_*.json`) watched by the sing-box core, re-routing new flows instantly while preserving long-lived active TCP sessions.
- **Strict Privacy & Anti-Spam Guardrails**:
  - Maximum 30 diagnostic probes per hour per workstation.
  - Maximum 2 alternative candidates tested per incident.
  - Zero session leakage: synthetic probes carry no cookies, tokens, or authorization headers.
- **Reboot Resilience**: Monotonic positive privilege caching prevents startup race conditions, ensuring automatic background recovery across cold reboots.

---

## Architectural Topology

For detailed protocol flows, packet lifecycles, and failure matrices, refer to [ARCHITECTURE.md](ARCHITECTURE.md).

```text
OS Applications & Workstation Traffic
                  │
                  ▼
         OMNIT sing-box TUN (throne-tun: 172.19.0.1)
                  │
       ┌──────────┼──────────────────────┐
       │          │                      │
       ▼          ▼                      ▼
    Direct   Multi-Egress          Target Egress
  (Physical)   Pool (NL/DE/US)     (Pinned Level 2)
       │          │                      │
       ▼          ▼                      ▼
   Russian    Encrypted              Dedicated
   Internet   SOCKS Bridges           Outbound
```

---

## Building from Source

### 1. Prerequisites (Ubuntu / Debian / KDE Neon)

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential cmake ninja-build git \
    qt6-base-dev qt6-tools-dev libqt6core6 libqt6gui6 libqt6widgets6 \
    libqt6network6 libqt6dbus6 libprotobuf-dev protobuf-compiler \
    golang-go
```

### 2. Compilation

```bash
git clone https://github.com/rixed318/omnit-vpn.git
cd omnit-vpn

# Build C++ Qt GUI Client
mkdir -p build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
ninja

# Build Go Core with Multi-Egress Backend
cd ../core/server
go build -v -tags "with_clash_api,with_gvisor,with_quic,with_wireguard,with_utls,with_dhcp,with_tailscale,badlinkname,tfogo_checklinkname0" \
    -ldflags "-w -s -checklinkname=0" -o ../../build/ThroneCore .
```

### 3. Granting Network Capabilities

Creating TUN interfaces and managing policy routing requires elevated privileges:

```bash
# Option A: SUID root (Standard for desktop clients)
sudo chown root:root build/ThroneCore && sudo chmod 4755 build/ThroneCore

# Option B: Linux Capabilities
sudo setcap cap_net_admin,cap_net_bind_service+ep build/ThroneCore
```

---

## Desktop Installation & Integration

Install the desktop launcher and standalone application shortcuts:

```bash
# Install standalone executable wrapper
mkdir -p ~/.local/bin
cat << 'EOF' > ~/.local/bin/omnit-vpn
#!/usr/bin/env bash
set -euo pipefail
readonly BUILD_DIR="/home/rus/dev/rixed-net/build"
readonly DATA_DIR="$HOME/.local/share/omnit"
exec "$BUILD_DIR/Throne" -appdata "$DATA_DIR" "$@"
EOF
chmod +x ~/.local/bin/omnit-vpn

# Install desktop entry
desktop-file-install --dir=$HOME/.local/share/applications/ << 'EOF'
[Desktop Entry]
Type=Application
Version=1.0
Name=OMNIT VPN
GenericName=Autonomous Selective VPN
Comment=Selective routing, Multi-Egress, stable DNS and TUN
Exec=omnit-vpn
Icon=Throne
Terminal=false
Categories=Network;VPN;
StartupWMClass=Throne
EOF
```

---

## CLI & Adaptive Router Usage

The companion `omnit_adaptive_router.py` tool provides headless control and automation:

```bash
# Query the 6-level routing decision for any target
./tools/omnit_adaptive_router.py resolve gosuslugi.ru
# -> Level 3: Protected Domestic -> direct (RU)

./tools/omnit_adaptive_router.py resolve whop.com
# -> Level 6: Default Outbound -> proxy-nl (NL)

# Pin a domain to a specific country
./tools/omnit_adaptive_router.py pin openai.com US

# Remove a manual pin
./tools/omnit_adaptive_router.py unpin openai.com

# Inspect active routes, health budget, and node statuses
./tools/omnit_adaptive_router.py status

# Run the 10-point verification test suite
./tools/omnit_adaptive_router.py test

# Run background health daemon with real-time error watcher
./tools/omnit_adaptive_router.py daemon --interval 30 --health-interval 60

# Install daemon as a systemd user service
./tools/omnit_adaptive_router.py install-service
```

---

## Automated Verification & Testing

OMNIT VPN maintains an extensive automated testing matrix:

1. **Adaptive Router & Probing Verification**:
   ```bash
   python3 tools/omnit_adaptive_router.py test
   ```
2. **Control Boundary & Privilege Matrix**:
   ```bash
   python3 script/test_control_privileges.py --binary build/Throne --core build/ThroneCore
   ```
3. **Live TUN & Routing Validation**:
   ```bash
   # Check active TUN device
   ip addr show throne-tun

   # Check decomposed policy routing
   ip route show table 2022

   # Validate DNS query interception via TUN
   dig @172.19.0.2 google.com
   ```

---

## License

GPLv3. See [LICENSE](LICENSE) for details.
