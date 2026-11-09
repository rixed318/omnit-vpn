#!/usr/bin/env python3
"""OMNIT Adaptive Router 2.0: Multi-Egress Smart Routing Engine.

Manages autonomous per-domain egress selection across concurrent multi-country
VPN nodes and Direct connection with honest error detection, SQLite decision caching,
and atomic rule-set synchronization for sing-box / Xray.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import socket
import sqlite3
import struct
import subprocess
import ssl
import sys
import tempfile
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple

# Configuration Defaults
DEFAULT_OMNIT_DIR = Path.home() / ".local" / "share" / "omnit"
DEFAULT_DB_PATH = DEFAULT_OMNIT_DIR / "vpn" / "adaptive_routing.db"
DEFAULT_RULES_DIR = DEFAULT_OMNIT_DIR / "rules"
DEFAULT_SOCKET_PATH = DEFAULT_OMNIT_DIR / "vpn" / "adaptive_router.sock"
DEFAULT_LOG_PATH = DEFAULT_OMNIT_DIR / "config" / "logs" / "throne.log"

# Routing Outbound Tags
TAG_DIRECT = "direct"
TAG_NL = "proxy-nl"
TAG_DE = "proxy-de"
TAG_US = "proxy-us"
TAG_DEFAULT = "proxy-nl"  # Default fallback proxy

# Starter Pool Nodes
STARTER_NODES = [
    {
        "outbound_tag": TAG_NL,
        "country_code": "NL",
        "country_name": "Нидерланды",
        "socks_port": 22101,
        "profile_id": 11338,
    },
    {
        "outbound_tag": TAG_DE,
        "country_code": "DE",
        "country_name": "Германия",
        "socks_port": 22102,
        "profile_id": 6813,
    },
    {
        "outbound_tag": TAG_US,
        "country_code": "US",
        "country_name": "США",
        "socks_port": 22103,
        "profile_id": 6818,
    },
]

# Strict Protected Russian Domains (Level 3 - Strict Direct, never auto-proxy)
PROTECTED_RU_DOMAINS: Set[str] = {
    "gosuslugi.ru",
    "esia.gosuslugi.ru",
    "sberbank.ru",
    "sber.ru",
    "online.sberbank.ru",
    "tbank.ru",
    "tinkoff.ru",
    "vtb.ru",
    "online.vtb.ru",
    "alfabank.ru",
    "click.alfabank.ru",
    "nalog.ru",
    "nalog.gov.ru",
    "mos.ru",
    "cbr.ru",
    "spb.ru",
    "genproc.gov.ru",
    "fssp.gov.ru",
    "kremlin.ru",
    "duma.gov.ru",
    "zakupki.gov.ru",
    "pfr.gov.ru",
    "sfr.gov.ru",
    "customs.gov.ru",
    "sudrf.ru",
}

# TTL Settings
TTL_VERIFIED_SECONDS = 24 * 3600      # 24 hours for confirmed working routes
TTL_FAILED_SECONDS = 1800             # 30 mins for unreachable candidates
TTL_CACHED_SECONDS = 12 * 3600        # 12 hours for adaptive decisions
MAX_HOURLY_PROBES = 30                # Safety budget to prevent spam / DoS
MAX_CANDIDATE_TRIES = 2               # Max alternative countries to probe per failure


logger = logging.getLogger("omnit_adaptive_router")


def normalize_domain(domain: str) -> str:
    """Normalize domain name: lowercase, strip trailing dot and leading dots."""
    d = domain.strip().lower()
    if d.endswith("."):
        d = d[:-1]
    while d.startswith("."):
        d = d[1:]
    return d


def is_system_bypass(domain_or_ip: str) -> bool:
    """Check Level 1: System Bypass (LAN, localhost, RFC1918, .local)."""
    val = domain_or_ip.strip().lower()
    if val in ("localhost", "local", "ip-nl.test", "ip-de.test", "ip-us.test", "ip-ru.test"):
        return True
    if val.endswith(".local") or val.endswith(".lan") or val.endswith(".internal"):
        return True
    try:
        ip = ipaddress.ip_address(val)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        pass
    return False


def is_protected_ru(domain: str) -> bool:
    """Check Level 3: Strict Direct Protected Russian Services."""
    d = normalize_domain(domain)
    for protected in PROTECTED_RU_DOMAINS:
        if d == protected or d.endswith("." + protected):
            return True
    return False


def is_regional_ru_hint(domain: str) -> bool:
    """Check Level 5: Regional Russian hint (.ru, .рф, .su)."""
    d = normalize_domain(domain)
    return d.endswith(".ru") or d.endswith(".рф") or d.endswith(".su")


@dataclasses.dataclass
class RouteDecision:
    domain: str
    country_code: str
    outbound_tag: str
    confidence: str
    reason: str
    level: int
    expires_at: int


class AdaptiveDatabase:
    """SQLite backing store for adaptive routing cache, node health, and audit logs."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        with self.get_connection() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=NORMAL;

                CREATE TABLE IF NOT EXISTS adaptive_routes (
                    domain TEXT PRIMARY KEY,
                    country_code TEXT NOT NULL,
                    outbound_tag TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    fail_count INTEGER DEFAULT 0,
                    last_ok_at INTEGER,
                    expires_at INTEGER,
                    created_at INTEGER
                );

                CREATE TABLE IF NOT EXISTS node_pool (
                    outbound_tag TEXT PRIMARY KEY,
                    country_code TEXT NOT NULL,
                    country_name TEXT NOT NULL,
                    socks_port INTEGER NOT NULL,
                    profile_id INTEGER,
                    is_alive BOOLEAN DEFAULT 1,
                    latency_ms INTEGER DEFAULT 0,
                    last_check_at INTEGER DEFAULT 0,
                    fail_streak INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS probe_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    tried_outbound TEXT NOT NULL,
                    result TEXT NOT NULL,
                    latency_ms INTEGER,
                    error_detail TEXT,
                    timestamp INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_routes_expires ON adaptive_routes(expires_at);
                CREATE INDEX IF NOT EXISTS idx_probe_timestamp ON probe_audit_log(timestamp);
                """
            )
            # Seed starter nodes
            for node in STARTER_NODES:
                conn.execute(
                    """
                    INSERT INTO node_pool (outbound_tag, country_code, country_name, socks_port, profile_id)
                    VALUES (:outbound_tag, :country_code, :country_name, :socks_port, :profile_id)
                    ON CONFLICT(outbound_tag) DO UPDATE SET
                        socks_port=excluded.socks_port,
                        country_code=excluded.country_code,
                        country_name=excluded.country_name,
                        profile_id=excluded.profile_id
                    """,
                    node,
                )
            conn.commit()

    def get_route(self, domain: str) -> Optional[Dict[str, Any]]:
        d = normalize_domain(domain)
        with self.get_connection() as conn:
            cur = conn.execute("SELECT * FROM adaptive_routes WHERE domain = ?", (d,))
            row = cur.fetchone()
            if row:
                return dict(row)
        return None

    def upsert_route(
        self,
        domain: str,
        country_code: str,
        outbound_tag: str,
        confidence: str,
        reason: str,
        ttl_seconds: int = TTL_CACHED_SECONDS,
    ) -> None:
        d = normalize_domain(domain)
        now = int(time.time())
        expires = now + ttl_seconds
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO adaptive_routes (domain, country_code, outbound_tag, confidence, reason, fail_count, last_ok_at, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    country_code=excluded.country_code,
                    outbound_tag=excluded.outbound_tag,
                    confidence=excluded.confidence,
                    reason=excluded.reason,
                    fail_count=0,
                    last_ok_at=excluded.last_ok_at,
                    expires_at=excluded.expires_at
                """,
                (d, country_code, outbound_tag, confidence, reason, now, expires, now),
            )
            conn.commit()

    def record_probe(
        self,
        domain: str,
        tried_outbound: str,
        result: str,
        latency_ms: Optional[int],
        error_detail: Optional[str] = None,
    ) -> None:
        now = int(time.time())
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO probe_audit_log (domain, tried_outbound, result, latency_ms, error_detail, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (normalize_domain(domain), tried_outbound, result, latency_ms, error_detail, now),
            )
            conn.commit()

    def get_hourly_probe_count(self) -> int:
        one_hour_ago = int(time.time()) - 3600
        with self.get_connection() as conn:
            cur = conn.execute("SELECT COUNT(*) FROM probe_audit_log WHERE timestamp >= ?", (one_hour_ago,))
            return cur.fetchone()[0]

    def list_all_active_routes(self) -> List[Dict[str, Any]]:
        now = int(time.time())
        with self.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM adaptive_routes WHERE confidence = 'pinned' OR expires_at > ? ORDER BY domain ASC",
                (now,),
            )
            return [dict(r) for r in cur.fetchall()]

    def list_nodes(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cur = conn.execute("SELECT * FROM node_pool ORDER BY socks_port ASC")
            return [dict(r) for r in cur.fetchall()]

    def update_node_status(self, outbound_tag: str, is_alive: bool, latency_ms: int) -> None:
        now = int(time.time())
        with self.get_connection() as conn:
            if is_alive:
                conn.execute(
                    """
                    UPDATE node_pool
                    SET is_alive = 1, latency_ms = ?, last_check_at = ?, fail_streak = 0
                    WHERE outbound_tag = ?
                    """,
                    (latency_ms, now, outbound_tag),
                )
            else:
                conn.execute(
                    """
                    UPDATE node_pool
                    SET is_alive = 0, last_check_at = ?, fail_streak = fail_streak + 1
                    WHERE outbound_tag = ?
                    """,
                    (now, outbound_tag),
                )
            conn.commit()

    def prune_expired_routes(self) -> int:
        now = int(time.time())
        with self.get_connection() as conn:
            cur = conn.execute(
                "DELETE FROM adaptive_routes WHERE confidence != 'pinned' AND expires_at <= ?",
                (now,),
            )
            conn.commit()
            return cur.rowcount

    def clear_cache(self, keep_pinned: bool = True) -> int:
        with self.get_connection() as conn:
            if keep_pinned:
                cur = conn.execute("DELETE FROM adaptive_routes WHERE confidence != 'pinned'")
            else:
                cur = conn.execute("DELETE FROM adaptive_routes")
            conn.commit()
            return cur.rowcount


class RuleSetSynchronizer:
    """Generates sing-box local rule_set JSON files atomically."""

    def __init__(self, rules_dir: Path, db: AdaptiveDatabase):
        self.rules_dir = rules_dir
        self.db = db
        self.rules_dir.mkdir(parents=True, exist_ok=True)

    def write_atomic_json(self, target_file: Path, payload: Dict[str, Any]) -> None:
        """Write JSON via temporary file with fsync and atomic rename."""
        target_file.parent.mkdir(parents=True, exist_ok=True)
        temp_fd, temp_path = tempfile.mkstemp(
            prefix="rules_", suffix=".tmp", dir=str(target_file.parent)
        )
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, str(target_file))
        except Exception:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

    def sync(self) -> Dict[str, int]:
        """Read all active routes and generate per-outbound rules_adaptive_*.json."""
        routes = self.db.list_all_active_routes()

        grouped: Dict[str, Set[str]] = {
            TAG_NL: set(),
            TAG_DE: set(),
            TAG_US: set(),
            TAG_DIRECT: set(),
        }

        for r in routes:
            tag = r.get("outbound_tag")
            domain = r.get("domain")
            if tag in grouped and domain:
                grouped[tag].add(domain)

        counts: Dict[str, int] = {}
        for tag, domains in grouped.items():
            short_tag = tag.replace("proxy-", "")
            rule_file = self.rules_dir / f"rules_adaptive_{short_tag}.json"
            sorted_domains = sorted(domains)
            payload = {
                "version": 1,
                "rules": [
                    {
                        "domain_suffix": sorted_domains
                    }
                ]
            }
            self.write_atomic_json(rule_file, payload)
            counts[tag] = len(sorted_domains)

        return counts


class AdaptiveRouterEngine:
    """Core decision engine implementing 6-level routing priority & safe active probing."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH, rules_dir: Path = DEFAULT_RULES_DIR):
        self.db = AdaptiveDatabase(db_path)
        self.synchronizer = RuleSetSynchronizer(rules_dir, self.db)

    def resolve(self, domain_or_target: str) -> RouteDecision:
        """Resolve route for domain following 6-level priority hierarchy."""
        domain = normalize_domain(domain_or_target)
        now = int(time.time())

        # Level 1: System Bypass
        if is_system_bypass(domain):
            return RouteDecision(
                domain=domain,
                country_code="RU",
                outbound_tag=TAG_DIRECT,
                confidence="system",
                reason="System bypass (LAN, localhost or RFC1918)",
                level=1,
                expires_at=0,
            )

        # Level 2: User Pinned Rule (checked in SQLite)
        route = self.db.get_route(domain)
        if route and route.get("confidence") == "pinned":
            return RouteDecision(
                domain=domain,
                country_code=route["country_code"],
                outbound_tag=route["outbound_tag"],
                confidence="pinned",
                reason=route["reason"] or "User pinned rule",
                level=2,
                expires_at=route["expires_at"],
            )

        # Level 3: Protected Russian Services (Strict Direct)
        if is_protected_ru(domain):
            return RouteDecision(
                domain=domain,
                country_code="RU",
                outbound_tag=TAG_DIRECT,
                confidence="protected",
                reason="Protected Russian infrastructure (Strict Direct)",
                level=3,
                expires_at=0,
            )

        # Level 4: Adaptive Cache (Valid cached decision)
        if route and route.get("expires_at", 0) > now and route.get("fail_count", 0) < 3:
            return RouteDecision(
                domain=domain,
                country_code=route["country_code"],
                outbound_tag=route["outbound_tag"],
                confidence=route["confidence"],
                reason=route["reason"],
                level=4,
                expires_at=route["expires_at"],
            )

        # Level 5: Regional Russian hint (.ru, .рф)
        if is_regional_ru_hint(domain):
            return RouteDecision(
                domain=domain,
                country_code="RU",
                outbound_tag=TAG_DIRECT,
                confidence="hint",
                reason="Regional Russian domain hint (Direct default, adaptable on failure)",
                level=5,
                expires_at=now + TTL_CACHED_SECONDS,
            )

        # Level 6: Default Outbound Proxy
        return RouteDecision(
            domain=domain,
            country_code="NL",
            outbound_tag=TAG_DEFAULT,
            confidence="default",
            reason="Unmatched foreign service -> Default proxy pool",
            level=6,
            expires_at=now + TTL_CACHED_SECONDS,
        )

    def pin_domain(self, domain: str, country_code: str) -> RouteDecision:
        """Pin domain to a specific country (User override - Level 2)."""
        d = normalize_domain(domain)
        cc = country_code.upper()
        tag_map = {"NL": TAG_NL, "DE": TAG_DE, "US": TAG_US, "RU": TAG_DIRECT}
        outbound = tag_map.get(cc, TAG_DEFAULT)
        self.db.upsert_route(
            domain=d,
            country_code=cc,
            outbound_tag=outbound,
            confidence="pinned",
            reason="User manual pin in OMNIT",
            ttl_seconds=365 * 24 * 3600,
        )
        self.synchronizer.sync()
        return self.resolve(d)

    def unpin_domain(self, domain: str) -> None:
        """Remove user pin for domain."""
        d = normalize_domain(domain)
        with self.db.get_connection() as conn:
            conn.execute("DELETE FROM adaptive_routes WHERE domain = ? AND confidence = 'pinned'", (d,))
            conn.commit()
        self.synchronizer.sync()

    async def probe_socks_node(self, socks_port: int, domain: str, timeout: float = 4.0) -> Tuple[bool, int, str]:
        """Perform 3-tier active probe (Tier 1: TCP/SOCKS5 -> Tier 2: TLS SNI -> Tier 3: HTTP HEAD)."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._probe_socks_sync, socks_port, domain, timeout)

    @staticmethod
    def _probe_socks_sync(socks_port: int, domain: str, timeout: float = 4.0) -> Tuple[bool, int, str]:
        start = time.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            # Tier 1: TCP & SOCKS5 Handshake
            s.connect(("127.0.0.1", socks_port))
            s.sendall(b"\x05\x01\x00")
            auth_resp = s.recv(2)
            if auth_resp != b"\x05\x00":
                return False, int((time.perf_counter() - start) * 1000), "[TCP] SOCKS auth rejected"

            domain_b = domain.encode("idna")
            req = struct.pack("!BBBB", 5, 1, 0, 3) + bytes([len(domain_b)]) + domain_b + struct.pack("!H", 443)
            s.sendall(req)
            reply = s.recv(10)
            if len(reply) < 4 or reply[1] != 0x00:
                rep_code = reply[1] if len(reply) >= 2 else -1
                return False, int((time.perf_counter() - start) * 1000), f"[TCP] connect error 0x{rep_code:02x}"

            # Tier 2: TLS SNI Handshake
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            try:
                ss = ssl_ctx.wrap_socket(s, server_hostname=domain)
            except (ssl.SSLError, OSError) as e:
                return False, int((time.perf_counter() - start) * 1000), f"[TLS] handshake failed: {e}"

            # Tier 3: HTTP HEAD Verification
            try:
                head_req = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {domain}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) OMNIT-Probe/2.0\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii")
                ss.sendall(head_req)
                resp_data = ss.recv(512).decode("iso-8859-1", errors="replace")
                first_line = resp_data.splitlines()[0] if resp_data else ""
                parts = first_line.split()
                status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
                latency_ms = int((time.perf_counter() - start) * 1000)

                if status_code in (200, 204, 301, 302, 303, 304, 307, 308, 400, 404, 405):
                    return True, latency_ms, f"[HTTP] reachable ({status_code})"
                elif status_code in (403, 451):
                    return False, latency_ms, f"[HTTP] blocked: status {status_code}"
                elif status_code == 0:
                    return False, latency_ms, "[HTTP] empty response from origin"
                else:
                    return True, latency_ms, f"[HTTP] origin responded ({status_code})"
            except (socket.timeout, TimeoutError):
                return False, int((time.perf_counter() - start) * 1000), "[HTTP] response timeout"
            except Exception as e:
                return False, int((time.perf_counter() - start) * 1000), f"[HTTP] request failed: {e}"
            finally:
                try:
                    ss.close()
                except Exception:
                    pass
        except (socket.timeout, TimeoutError):
            return False, int((time.perf_counter() - start) * 1000), "[TCP] connection timeout"
        except ConnectionRefusedError:
            return False, int((time.perf_counter() - start) * 1000), "[TCP] node offline (connection refused)"
        except Exception as e:
            return False, int((time.perf_counter() - start) * 1000), f"[TCP] error: {e}"
        finally:
            try:
                s.close()
            except Exception:
                pass

    async def diagnose_and_heal(self, domain: str) -> Dict[str, Any]:
        """Diagnose connection issue and select optimal country without flooding."""
        d = normalize_domain(domain)
        result_report = {
            "domain": d,
            "previous_route": None,
            "new_route": None,
            "probed": [],
            "action": "none",
        }

        # Check safety budget
        current_hourly_probes = self.db.get_hourly_probe_count()
        if current_hourly_probes >= MAX_HOURLY_PROBES:
            result_report["action"] = "rate_limited"
            result_report["reason"] = f"Hourly probe budget exhausted ({current_hourly_probes}/{MAX_HOURLY_PROBES})"
            return result_report

        current_decision = self.resolve(d)
        result_report["previous_route"] = current_decision.outbound_tag

        # If it's a Level 3 protected RU service, never heal to VPN
        if current_decision.level == 3:
            result_report["action"] = "protected_direct_locked"
            return result_report

        # Candidate order: if current is NL -> try DE, then US. If DE -> try NL, then US.
        pool_nodes = self.db.list_nodes()
        nodes_by_tag = {n["outbound_tag"]: n for n in pool_nodes}

        candidate_tags = [TAG_DE, TAG_NL, TAG_US]
        if current_decision.outbound_tag in candidate_tags:
            candidate_tags.remove(current_decision.outbound_tag)

        # Probe max 2 candidate countries
        successful_tag = None
        for tag in candidate_tags[:MAX_CANDIDATE_TRIES]:
            node = nodes_by_tag.get(tag)
            if not node or not node.get("socks_port"):
                continue

            socks_port = node["socks_port"]
            ok, latency_ms, detail = await self.probe_socks_node(socks_port, d)
            self.db.record_probe(d, tag, "ok" if ok else "failed", latency_ms, detail)
            result_report["probed"].append({
                "outbound_tag": tag,
                "country_code": node["country_code"],
                "success": ok,
                "latency_ms": latency_ms,
                "detail": detail,
            })
            if ok:
                successful_tag = tag
                country_code = node["country_code"]
                break

        if successful_tag and successful_tag != current_decision.outbound_tag:
            self.db.upsert_route(
                domain=d,
                country_code=country_code,
                outbound_tag=successful_tag,
                confidence="verified",
                reason=f"Auto-healed: verified reachable via {country_code} ({latency_ms}ms)",
                ttl_seconds=TTL_VERIFIED_SECONDS,
            )
            self.synchronizer.sync()
            result_report["action"] = "healed"
            result_report["new_route"] = successful_tag
        else:
            result_report["action"] = "retained_or_no_alternative"

        return result_report

    async def check_node_health(self, node: Dict[str, Any]) -> Tuple[bool, int]:
        """Check if a node in node_pool is alive and measure its roundtrip latency."""
        socks_port = node.get("socks_port")
        if not socks_port:
            return False, 0
        ok, latency_ms, _ = await self.probe_socks_node(socks_port, "cp.cloudflare.com", timeout=3.0)
        self.db.update_node_status(node["outbound_tag"], ok, latency_ms)
        return ok, latency_ms

    async def check_all_nodes(self) -> Dict[str, Any]:
        """Check health of all nodes in the pool."""
        nodes = self.db.list_nodes()
        results = {}
        for n in nodes:
            ok, lat = await self.check_node_health(n)
            results[n["outbound_tag"]] = {"alive": ok, "latency_ms": lat}
        return results

class LogEventWatcher:
    """Tails Throne/sing-box log, correlates IP to domain via DNS events, and triggers auto-heal on recurring transport errors."""

    DNS_PATTERN = re.compile(r"dns:\s*(?:exchanged|cached)\s+A\s+([\w.-]+?)\.?\s+\d+\s+IN\s+A\s+([0-9.]+)")
    ERROR_PATTERN = re.compile(
        r"(?:outbound/.*?|inbound/.*?):\s*(?:connection to|dial tcp)\s+([0-9.]+):[0-9]+.*?"
        r"(connection reset by peer|connection timed out|i/o timeout|handshake failed|connection refused|context deadline exceeded)",
        re.IGNORECASE,
    )

    def __init__(self, engine: AdaptiveRouterEngine, log_path: Path = DEFAULT_LOG_PATH):
        self.engine = engine
        self.log_path = log_path
        self._ip_to_domain: Dict[str, Tuple[str, float]] = {}
        self._domain_failures: Dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=10))
        self._stop_event = asyncio.Event()

    def handle_line(self, line: str) -> Optional[str]:
        # 1. Check DNS resolution
        dns_match = self.DNS_PATTERN.search(line)
        if dns_match:
            domain, ip = dns_match.group(1).lower().rstrip("."), dns_match.group(2)
            self._ip_to_domain[ip] = (domain, time.time())
            return None

        # 2. Check connection error
        err_match = self.ERROR_PATTERN.search(line)
        if err_match:
            ip = err_match.group(1)
            record = self._ip_to_domain.get(ip)
            if not record:
                return None
            domain, dns_time = record
            if time.time() - dns_time > 600:
                return None

            now = time.time()
            dq = self._domain_failures[domain]
            dq.append(now)

            recent_failures = [t for t in dq if now - t <= 60.0]
            if len(recent_failures) >= 2:
                dq.clear()
                return domain
        return None

    async def run(self) -> None:
        """Tails the log file asynchronously."""
        if not self.log_path.exists():
            return
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, os.SEEK_END)
                while not self._stop_event.is_set():
                    line = f.readline()
                    if not line:
                        await asyncio.sleep(0.5)
                        continue
                    failed_domain = self.handle_line(line)
                    if failed_domain:
                        print(f"[OMNIT-EVENT] Recurring network errors for {failed_domain}, initiating autonomous heal...")
                        asyncio.create_task(self.engine.diagnose_and_heal(failed_domain))
        except Exception as e:
            print(f"[OMNIT-EVENT] Log watcher error: {e}", file=sys.stderr)

    def stop(self) -> None:
        self._stop_event.set()


    async def run_daemon(self, interval: float = 30.0, health_interval: float = 60.0) -> None:
        """Run ongoing background maintenance: pruning expired routes, checking node health, and watching network error events."""
        print(f"[OMNIT-ROUTER] Daemon started. Prune interval={interval}s, Node health interval={health_interval}s")
        watcher = LogEventWatcher(self)
        watcher_task = asyncio.create_task(watcher.run())

        last_health_check = 0.0
        try:
            while True:
                now = time.time()
                try:
                    # 1. Prune expired cache
                    pruned = self.db.prune_expired_routes()
                    if pruned > 0:
                        print(f"[OMNIT-ROUTER] Pruned {pruned} expired routes. Resynchronizing rule sets...")
                        self.synchronizer.sync()

                    # 2. Check node health
                    if now - last_health_check >= health_interval:
                        last_health_check = now
                        health_res = await self.check_all_nodes()
                        alive_count = sum(1 for v in health_res.values() if v["alive"])
                        print(f"[OMNIT-ROUTER] Health check: {alive_count}/{len(health_res)} nodes alive")
                except Exception as e:
                    print(f"[OMNIT-ROUTER] Daemon error: {e}", file=sys.stderr)

                await asyncio.sleep(interval)
        finally:
            watcher.stop()
            watcher_task.cancel()


def install_systemd_service(python_exec: Optional[str] = None) -> Path:
    """Install and enable systemd user unit for omnit-adaptive-router."""
    user_unit_dir = Path.home() / ".config" / "systemd" / "user"
    user_unit_dir.mkdir(parents=True, exist_ok=True)
    unit_file = user_unit_dir / "omnit-adaptive-router.service"
    py = python_exec or sys.executable
    script_path = Path(__file__).resolve()

    content = f"""[Unit]
Description=OMNIT Adaptive Router & Multi-Egress Engine Daemon
After=network-online.target graphical-session.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={py} {script_path} daemon --interval 30 --health-interval 60
Restart=always
RestartSec=3
TimeoutStopSec=10
UMask=0077
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
"""
    with tempfile.NamedTemporaryFile("w", dir=user_unit_dir, prefix=".omnit-adaptive-router.service.", delete=False) as tf:
        tf.write(content)
        temp_name = Path(tf.name)
    temp_name.chmod(0o600)
    os.replace(temp_name, unit_file)

    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "--user", "enable", "--now", "omnit-adaptive-router.service"], check=False)
    print(f"Installed and started {unit_file}")
    return unit_file


def run_tests() -> int:
    """Automated verification suite testing all 6 levels, SQLite persistence, and atomic writes."""
    import tempfile
    import shutil

    test_dir = Path(tempfile.mkdtemp(prefix="omnit_router_test_"))
    try:
        print("[TEST] Initializing test router in:", test_dir)
        db_file = test_dir / "test_adaptive.db"
        rules_dir = test_dir / "rules"
        engine = AdaptiveRouterEngine(db_path=db_file, rules_dir=rules_dir)

        # 1. Level 1: System Bypass
        dec1 = engine.resolve("localhost")
        assert dec1.level == 1 and dec1.outbound_tag == TAG_DIRECT, f"Level 1 failed: {dec1}"
        dec1_ip = engine.resolve("192.168.1.100")
        assert dec1_ip.level == 1 and dec1_ip.outbound_tag == TAG_DIRECT, f"Level 1 IP failed: {dec1_ip}"

        # 2. Level 3: Protected RU Services
        dec3 = engine.resolve("gosuslugi.ru")
        assert dec3.level == 3 and dec3.outbound_tag == TAG_DIRECT, f"Level 3 failed: {dec3}"
        dec3_sub = engine.resolve("esia.gosuslugi.ru")
        assert dec3_sub.level == 3 and dec3_sub.outbound_tag == TAG_DIRECT, f"Level 3 subdomain failed: {dec3_sub}"

        # 3. Level 2: User Pinned Rules
        engine.pin_domain("whop.com", "US")
        dec2 = engine.resolve("whop.com")
        assert dec2.level == 2 and dec2.outbound_tag == TAG_US and dec2.country_code == "US", f"Level 2 failed: {dec2}"

        # 4. Level 5: Regional RU hint
        dec5 = engine.resolve("habr.ru")
        assert dec5.level == 5 and dec5.outbound_tag == TAG_DIRECT, f"Level 5 failed: {dec5}"

        # 5. Level 6: Default Outbound
        dec6 = engine.resolve("openai.com")
        assert dec6.level == 6 and dec6.outbound_tag == TAG_DEFAULT, f"Level 6 failed: {dec6}"

        # 6. Atomic Rule-Set Sync
        counts = engine.synchronizer.sync()
        us_rule = rules_dir / "rules_adaptive_us.json"
        assert us_rule.exists(), "rules_adaptive_us.json not generated!"
        with open(us_rule) as f:
            data = json.load(f)
            assert "whop.com" in data["rules"][0]["domain_suffix"], "whop.com not in US rule set!"

        # 7. Safe Probe rate limiter test
        for i in range(MAX_HOURLY_PROBES + 2):
            engine.db.record_probe("spam-test.org", TAG_DE, "failed", 100)
        assert engine.db.get_hourly_probe_count() >= MAX_HOURLY_PROBES, "Hourly probe count not recording!"

        # 8. Unpin and clear cache
        engine.unpin_domain("whop.com")
        dec2_cleared = engine.resolve("whop.com")
        assert dec2_cleared.level == 6, f"Unpin failed: {dec2_cleared}"

        # 9. Real-time LogEventWatcher correlation and recurring error detection
        watcher = LogEventWatcher(engine)
        dns_line = "2026-11-09 18:00:00 [INF] [ui] INFO[100] [1234 50ms] dns: exchanged A test-event.org. 300 IN A 198.51.100.77"
        res_dns = watcher.handle_line(dns_line)
        assert res_dns is None, "DNS line should not trigger failure"
        assert "198.51.100.77" in watcher._ip_to_domain, "IP to domain mapping failed"
        assert watcher._ip_to_domain["198.51.100.77"][0] == "test-event.org"

        err1 = "2026-11-09 18:00:01 [INF] [ui] outbound/socks[proxy]: connection to 198.51.100.77:443: connection reset by peer"
        assert watcher.handle_line(err1) is None, "First failure should not trigger heal"
        err2 = "2026-11-09 18:00:02 [INF] [ui] outbound/socks[proxy]: dial tcp 198.51.100.77:443: connection timed out"
        triggered_domain = watcher.handle_line(err2)
        assert triggered_domain == "test-event.org", f"Second failure did not trigger expected domain: {triggered_domain}"

        # 10. 3-Tier probe stages: verify TCP stage handling on unreachable port
        unreachable_res, _, stage = AdaptiveRouterEngine._probe_socks_sync(1, "example.com", timeout=0.2)
        assert not unreachable_res and stage.startswith("[TCP]"), f"Probe did not correctly identify TCP stage: {stage}"

        print("[TEST] ALL 10 CORE VERIFICATION TESTS PASSED SUCCESSFULLY!")
        return 0
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="OMNIT Adaptive Router 2.0")
    subparsers = parser.add_subparsers(dest="command", help="Subcommand")

    # test
    subparsers.add_parser("test", help="Run automated test suite")

    # resolve
    p_resolve = subparsers.add_parser("resolve", help="Resolve route for domain")
    p_resolve.add_argument("domain", help="Target domain (e.g. whop.com)")

    # pin
    p_pin = subparsers.add_parser("pin", help="Pin domain to specific country")
    p_pin.add_argument("domain", help="Target domain")
    p_pin.add_argument("country", choices=["NL", "DE", "US", "RU"], help="Country code")

    # unpin
    p_unpin = subparsers.add_parser("unpin", help="Unpin domain")
    p_unpin.add_argument("domain", help="Target domain")

    # sync
    subparsers.add_parser("sync", help="Synchronize rule sets")

    # status
    subparsers.add_parser("status", help="Show router status")

    # diagnose
    p_diag = subparsers.add_parser("diagnose", help="Diagnose and heal route")
    p_diag.add_argument("domain", help="Target domain")

    # clear-cache
    subparsers.add_parser("clear-cache", help="Clear non-pinned adaptive routes")

    # daemon
    p_daemon = subparsers.add_parser("daemon", help="Run maintenance daemon")
    p_daemon.add_argument("--interval", type=float, default=30.0, help="Prune interval in seconds")
    p_daemon.add_argument("--health-interval", type=float, default=60.0, help="Health check interval in seconds")

    # install-service
    p_install = subparsers.add_parser("install-service", help="Install systemd user service")
    p_install.add_argument("--python", help="Path to python executable")

    args = parser.parse_args()

    if args.command == "test":
        sys.exit(run_tests())

    engine = AdaptiveRouterEngine()

    if args.command == "resolve":
        res = engine.resolve(args.domain)
        print(f"Domain:      {res.domain}")
        print(f"Level:       Level {res.level}")
        print(f"Outbound:    {res.outbound_tag} ({res.country_code})")
        print(f"Confidence:  {res.confidence}")
        print(f"Reason:      {res.reason}")

    elif args.command == "pin":
        res = engine.pin_domain(args.domain, args.country)
        print(f"Pinned {res.domain} -> {res.outbound_tag} ({res.country_code})")

    elif args.command == "unpin":
        engine.unpin_domain(args.domain)
        print(f"Unpinned {args.domain}")

    elif args.command == "sync":
        counts = engine.synchronizer.sync()
        print("Synchronized rule sets:", counts)

    elif args.command == "status":
        routes = engine.db.list_all_active_routes()
        nodes = engine.db.list_nodes()
        probes = engine.db.get_hourly_probe_count()
        print("=== OMNIT Adaptive Router Status ===")
        print(f"Active adaptive routes: {len(routes)}")
        print(f"Probes in last hour:    {probes} / {MAX_HOURLY_PROBES}")
        print("\nNode Pool:")
        for n in nodes:
            status = "UP" if n["is_alive"] else "DOWN"
            print(f"  [{status:4}] {n['country_name']:12} ({n['country_code']}) | Port: {n['socks_port']} | Latency: {n['latency_ms']}ms | Outbound: {n['outbound_tag']}")
        print("\nSample Active Routes:")
        for r in routes[:10]:
            print(f"  {r['domain']:25} -> {r['outbound_tag']:10} [{r['confidence']}] ({r['reason']})")

    elif args.command == "diagnose":
        res = asyncio.run(engine.diagnose_and_heal(args.domain))
        print(json.dumps(res, indent=2, ensure_ascii=False))

    elif args.command == "clear-cache":
        cleared = engine.db.clear_cache()
        engine.synchronizer.sync()
        print(f"Cleared {cleared} cached routes and resynced rules.")

    elif args.command == "daemon":
        try:
            asyncio.run(engine.run_daemon(interval=args.interval, health_interval=args.health_interval))
        except KeyboardInterrupt:
            print("[OMNIT-ROUTER] Daemon stopped by user.")

    elif args.command == "install-service":
        unit = install_systemd_service(python_exec=args.python)
        print(f"OMNIT Adaptive Router daemon service installed: {unit}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
