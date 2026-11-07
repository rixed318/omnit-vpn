# OMNIT VPN

> Open-source Linux VPN client with adaptive routing, multi-region egress, and intelligent traffic management.

[![Platform](https://img.shields.io/badge/platform-Linux-blue.svg)](https://github.com/rixed318/omnit-vpn)
[![Core](https://img.shields.io/badge/core-sing--box%20%2B%20Xray-orange.svg)](https://github.com/rixed318/omnit-vpn)
[![License](https://img.shields.io/badge/license-GPLv3-green.svg)](LICENSE)

OMNIT VPN is designed for Linux workstations requiring seamless access to both domestic Russian services and international applications simultaneously. Instead of forcing all internet traffic through a single foreign VPN or requiring manual whitelist management, OMNIT autonomously routes each service through its optimal connection.

---

## Key Features

- **Multi-Egress Architecture**: Concurrently routes traffic to different countries (e.g. Netherlands, Germany, United States, and Direct Russian internet) in the same TUN interface.
- **Adaptive Routing 2.0**: Automatically detects connection failures and learns the optimal exit node for each service, storing decisions in a local SQLite cache.
- **Zero-Downtime Hot Rule Updates**: Dynamically migrates domain routes via atomic rule-sets without tearing down `throne-tun` or resetting ongoing connections.
- **6-Level Priority Resolver**:
  1. System Bypass (LAN, loopback, private RFC1918 networks).
  2. User Pinned Rules (highest priority manual controls).
  3. Protected Russian Services (Gosuslugi, banks, tax portals stay strictly Direct).
  4. Adaptive Route Cache (TTL-validated historical success routes).
  5. Regional Hints (`*.ru`, `*.рф` default to Direct, adaptable on failure).
  6. Default Outbound (foreign SaaS, AI tools, CDN to primary VPN pool).
- **Safe Active Probing**: Built-in anti-spam limits (max 30 probes/hour, max 2 candidate countries per incident, exponential backoff) with zero session credential leakage.
- **Owner-Local Control Protocol**: Single-instance desktop IPC via secure UNIX domain socket (`OMNIT-CONTROL/1`).

---

## Architecture Overview

See [ARCHITECTURE.md](ARCHITECTURE.md) for full design specifications and protocol flows.

```text
applications & desktop traffic
              |
              v
     OMNIT sing-box TUN
              |-- Unmatched & Russian sensitive ---> DIRECT (Physical enp4s0 / Wi-Fi)
              |-- Adaptive cached services ---------> Multi-Egress Pool (NL / DE / US)
              `-- Pinned overrides -----------------> Target Outbound
```

---

## Building from Source

### Prerequisites (Ubuntu / Debian / Kubuntu)

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential cmake ninja-build git \
    qt6-base-dev qt6-tools-dev libqt6core6 libqt6gui6 libqt6widgets6 \
    libqt6network6 libqt6dbus6 libprotobuf-dev protobuf-compiler
```

### Build Commands

```bash
mkdir -p build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
ninja
```

The resulting binaries will be placed in:
- `build/Throne` — Qt 6 GUI Desktop Client.
- `build/ThroneCore` — Unified sing-box + Xray-core backend.

---

## Running Adaptive Router CLI

```bash
# Verify routing decision for a domain
./tools/omnit_adaptive_router.py resolve gosuslugi.ru
./tools/omnit_adaptive_router.py resolve whop.com

# Pin a domain to Germany
./tools/omnit_adaptive_router.py pin whop.com DE

# View router status and node pool
./tools/omnit_adaptive_router.py status

# Run automated tests
./tools/omnit_adaptive_router.py test

# Run background maintenance daemon
./tools/omnit_adaptive_router.py daemon --interval 30 --health-interval 60

# Install systemd user service
./tools/omnit_adaptive_router.py install-service
```

---

## License

GPLv3. See [LICENSE](LICENSE) for details.
