"""Owner-local adapter for the existing OMNIT VPN/Throne runtime.

This module never reads the VPN SQLite database and never handles subscription
URLs, HWID or server credentials.  It talks to the versioned, user-only local
socket implemented by the existing GUI and converts the compact JSON response
into a stable Python model for the desktop shell.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


API_VERSION = 1
WIRE_PREFIX = b"OMNIT-CONTROL/1 "
DEFAULT_APP_DATA = Path.home() / ".local" / "share" / "omnit"
VPN_LAUNCHER = Path.home() / ".local" / "bin" / "omnit-vpn"
DEFAULT_LAUNCHER = VPN_LAUNCHER if VPN_LAUNCHER.exists() else Path.home() / ".local" / "bin" / "omnit"
DEFAULT_LOG_PATH = DEFAULT_APP_DATA / "config" / "logs" / "throne.log"
VPN_EGRESS_PROXY = "http://127.0.0.1:2081"
DIRECT_EGRESS_PROXY = "http://127.0.0.1:2082"

_PRIVATE_URI_RE = re.compile(
    r"\b(?:vless|vmess|trojan|ss|ssr|hysteria2?|tuic|wireguard)://\S+",
    re.IGNORECASE,
)
_HTTP_URI_RE = re.compile(r"https?://[^\s\]\[<>()\"']+", re.IGNORECASE)
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_NAMED_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|token|secret|authorization|uuid)\s*[:=]\s*([^\s,;]+)"
)
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_-]{40,}\b")


class VpnAdapterError(RuntimeError):
    """The local VPN control boundary is unavailable or rejected a request."""


@dataclass(frozen=True)
class VpnStatus:
    api_available: bool = False
    gui_running: bool = False
    state: str = "unavailable"
    connected: bool = False
    tun_enabled: bool = False
    system_proxy_enabled: bool = False
    profile_id: int = -1
    profile_name: str = ""
    profile_group: str = ""
    profile_location: str = ""
    route_id: int = -1
    route_name: str = ""
    route_mode: str = "unknown"
    mixed_address: str = ""
    mixed_port: int = 0
    proxy_download: int = 0
    proxy_upload: int = 0
    direct_download: int = 0
    direct_upload: int = 0
    error: str = ""


@dataclass(frozen=True)
class VpnProfileOption:
    id: int
    name: str
    type: str
    latency_ms: int
    country: str
    selected: bool


@dataclass(frozen=True)
class VpnGroupOption:
    id: int
    name: str
    profiles: tuple[VpnProfileOption, ...]


@dataclass(frozen=True)
class VpnRouteOption:
    id: int
    name: str
    mode: str
    selected: bool
    service_choices_supported: bool


@dataclass(frozen=True)
class VpnServiceOption:
    id: str
    title: str
    description: str
    category: str
    use_proxy: bool
    recommended_proxy: bool
    automatic: bool
    confidence: str
    security_sensitive: bool


@dataclass(frozen=True)
class VpnCatalog:
    status: VpnStatus
    groups: tuple[VpnGroupOption, ...]
    routes: tuple[VpnRouteOption, ...]
    services: tuple[VpnServiceOption, ...]
    service_choices_supported: bool


def parse_public_ip(value: str) -> str:
    """Return a canonical public IP or an empty string for unsafe output."""

    candidate = value.strip().splitlines()[0].strip() if value.strip() else ""
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return ""
    if not address.is_global:
        return ""
    return address.compressed


def sanitize_log_line(line: str) -> str:
    """Remove credentials and subscription payloads from a VPN log line."""

    line = _PRIVATE_URI_RE.sub("[конфиг скрыт]", line)

    def sanitize_http(match: re.Match[str]) -> str:
        value = match.group(0)
        # Keep the host useful for diagnostics, but paths and queries can be
        # HWID subscription tokens and must never cross the adapter boundary.
        authority = value.split("//", 1)[1].split("/", 1)[0]
        if "@" in authority:
            authority = authority.rsplit("@", 1)[1]
        suffix = "/[…]" if "/" in value.split("//", 1)[1] else ""
        return f"{value.split('://', 1)[0]}://{authority}{suffix}"

    line = _HTTP_URI_RE.sub(sanitize_http, line)
    line = _NAMED_SECRET_RE.sub(lambda match: f"{match.group(1)}=[скрыто]", line)
    line = _UUID_RE.sub("[uuid скрыт]", line)
    line = _LONG_TOKEN_RE.sub("[секрет скрыт]", line)
    return line[:1200]


def tail_sanitized_logs(
    path: Path = DEFAULT_LOG_PATH,
    *,
    max_lines: int = 160,
    max_bytes: int = 512 * 1024,
) -> tuple[str, ...]:
    """Read only a bounded, owner-local and redacted tail of Throne's log."""

    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or metadata.st_uid != os.getuid():
            return ()
        with path.open("rb") as stream:
            size = metadata.st_size
            offset = max(0, size - max_bytes)
            stream.seek(offset)
            raw = stream.read(max_bytes)
    except OSError:
        return ()
    lines = raw.decode("utf-8", errors="replace").splitlines()
    if offset and lines:
        lines = lines[1:]
    visible = []
    for raw_line in lines:
        if "Another instance tried to wake us up" in raw_line:
            continue
        clean = sanitize_log_line(raw_line).strip()
        if clean:
            visible.append(clean)
    return tuple(visible[-max(1, max_lines):])


def clear_logs(path: Path = DEFAULT_LOG_PATH) -> bool:
    """Truncate Throne's owner-local regular log without following symlinks."""

    flags = os.O_WRONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            return False
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
    except OSError:
        return False
    finally:
        os.close(descriptor)
    return True


def server_name(app_data: Path = DEFAULT_APP_DATA) -> str:
    absolute = str(app_data.expanduser().resolve()).encode("utf-8")
    digest = base64.b64encode(hashlib.md5(absolute).digest()).decode("ascii")
    safe = digest.rstrip("=").replace("+", "0").replace("/", "1")
    return f"throne-{safe}"


def socket_path(app_data: Path = DEFAULT_APP_DATA) -> Path:
    # QLocalServer uses the platform temp directory for a bare server name on
    # this Linux build. Keeping the derivation here mirrors Throne's main.cpp.
    return Path(tempfile.gettempdir()) / server_name(app_data)


def _running_process(name: str, proc_root: Path = Path("/proc")) -> bool:
    try:
        entries = proc_root.iterdir()
    except OSError:
        return False
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "comm").read_text(encoding="utf-8").strip() == name:
                return True
        except OSError:
            continue
    return False


def _parse_status(payload: dict[str, Any]) -> VpnStatus:
    profile = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}
    route = payload.get("route") if isinstance(payload.get("route"), dict) else {}
    mixed = payload.get("mixed") if isinstance(payload.get("mixed"), dict) else {}
    rates = payload.get("rates") if isinstance(payload.get("rates"), dict) else {}

    def number(key: str) -> int:
        value = rates.get(key, 0)
        return max(0, int(value)) if isinstance(value, (int, float)) else 0

    route_name = str(route.get("name") or "")
    route_mode = str(route.get("mode") or "").strip().casefold()
    if route_mode not in {"full", "split", "custom"}:
        if route_name == "OMNIT Full Tunnel":
            route_mode = "full"
        elif route_name == "OMNIT Whitelist":
            route_mode = "split"
        else:
            route_mode = "unknown"

    return VpnStatus(
        api_available=payload.get("apiVersion") == API_VERSION,
        gui_running=bool(payload.get("guiRunning")),
        state=str(payload.get("state") or "unavailable"),
        connected=bool(payload.get("connected")),
        tun_enabled=bool(payload.get("tunEnabled")),
        system_proxy_enabled=bool(payload.get("systemProxyEnabled")),
        profile_id=int(profile.get("id") or -1),
        profile_name=str(profile.get("name") or ""),
        profile_group=str(profile.get("group") or ""),
        profile_location=str(profile.get("location") or ""),
        route_id=int(route.get("id") or -1),
        route_name=route_name,
        route_mode=route_mode,
        mixed_address=str(mixed.get("address") or ""),
        mixed_port=int(mixed.get("port") or 0),
        proxy_download=number("proxyDownload"),
        proxy_upload=number("proxyUpload"),
        direct_download=number("directDownload"),
        direct_upload=number("directUpload"),
        error=str(payload.get("error") or ""),
    )


def _request_payload(
    action: str = "status",
    *,
    app_data: Path = DEFAULT_APP_DATA,
    timeout: float = 1.0,
    **parameters: Any,
) -> dict[str, Any]:
    message = {"apiVersion": API_VERSION, "action": action, **parameters}
    raw = WIRE_PREFIX + json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"
    path = socket_path(app_data)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(str(path))
        client.sendall(raw)
        response = bytearray()
        while b"\n" not in response:
            chunk = client.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > 1024 * 1024:
                raise VpnAdapterError("VPN control response is too large")
    except (OSError, TimeoutError) as error:
        raise VpnAdapterError(f"VPN control socket is unavailable: {error}") from error
    finally:
        client.close()

    line = bytes(response).split(b"\n", 1)[0]
    if not line.startswith(WIRE_PREFIX):
        raise VpnAdapterError("VPN control returned an unsupported response")
    try:
        payload = json.loads(line[len(WIRE_PREFIX):].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise VpnAdapterError("VPN control returned invalid JSON") from error
    if not isinstance(payload, dict):
        raise VpnAdapterError("VPN control returned a non-object response")
    if not payload.get("ok", False):
        status = _parse_status(payload)
        raise VpnAdapterError(status.error or "VPN control rejected the request")
    return payload


def request(
    action: str = "status",
    *,
    app_data: Path = DEFAULT_APP_DATA,
    timeout: float = 1.0,
    **parameters: Any,
) -> VpnStatus:
    return _parse_status(
        _request_payload(
            action,
            app_data=app_data,
            timeout=timeout,
            **parameters,
        )
    )


def _parse_catalog(payload: dict[str, Any]) -> VpnCatalog:
    groups: list[VpnGroupOption] = []
    for raw_group in payload.get("groups", []):
        if not isinstance(raw_group, dict):
            continue
        profiles: list[VpnProfileOption] = []
        for raw_profile in raw_group.get("profiles", []):
            if not isinstance(raw_profile, dict):
                continue
            profiles.append(
                VpnProfileOption(
                    id=int(raw_profile.get("id") or -1),
                    name=str(raw_profile.get("name") or ""),
                    type=str(raw_profile.get("type") or ""),
                    latency_ms=max(0, int(raw_profile.get("latencyMs") or 0)),
                    country=str(raw_profile.get("country") or ""),
                    selected=bool(raw_profile.get("selected")),
                )
            )
        groups.append(
            VpnGroupOption(
                id=int(raw_group.get("id") or -1),
                name=str(raw_group.get("name") or ""),
                profiles=tuple(profiles),
            )
        )

    routes = tuple(
        VpnRouteOption(
            id=int(item.get("id") or -1),
            name=str(item.get("name") or ""),
            mode=str(item.get("mode") or "").strip().casefold() or "custom",
            selected=bool(item.get("selected")),
            service_choices_supported=bool(item.get("serviceChoicesSupported")),
        )
        for item in payload.get("routes", [])
        if isinstance(item, dict)
    )
    services = tuple(
        VpnServiceOption(
            id=str(item.get("id") or ""),
            title=str(item.get("title") or ""),
            description=str(item.get("description") or ""),
            category=str(item.get("category") or ""),
            use_proxy=bool(item.get("useProxy")),
            recommended_proxy=bool(item.get("recommendedProxy")),
            automatic=bool(item.get("automatic")),
            confidence=str(item.get("confidence") or ""),
            security_sensitive=bool(item.get("securitySensitive")),
        )
        for item in payload.get("services", [])
        if isinstance(item, dict) and item.get("id")
    )
    return VpnCatalog(
        status=_parse_status(payload),
        groups=tuple(groups),
        routes=routes,
        services=services,
        service_choices_supported=bool(payload.get("serviceChoicesSupported")),
    )


def status(app_data: Path = DEFAULT_APP_DATA) -> VpnStatus:
    try:
        return request("status", app_data=app_data, timeout=0.2)
    except VpnAdapterError as error:
        return VpnStatus(
            api_available=False,
            gui_running=_running_process("Throne"),
            error=str(error),
        )


def ensure_gui(
    *,
    launcher: Path | None = None,
    app_data: Path = DEFAULT_APP_DATA,
    timeout: float = 10.0,
) -> VpnStatus:
    active_launcher = launcher or (VPN_LAUNCHER if VPN_LAUNCHER.exists() else DEFAULT_LAUNCHER)
    current = status(app_data)
    if current.api_available:
        return current
    if not active_launcher.is_file() or not os.access(active_launcher, os.X_OK):
        raise VpnAdapterError(f"VPN launcher is missing: {active_launcher}")
    if not current.gui_running:
        try:
            subprocess.Popen(
                [str(active_launcher)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as error:
            raise VpnAdapterError(f"Could not launch OMNIT VPN: {error}") from error
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = status(app_data)
        if current.api_available:
            return current
        time.sleep(0.15)
    raise VpnAdapterError("OMNIT VPN started but its control API did not appear")


def open_gui(app_data: Path = DEFAULT_APP_DATA) -> VpnStatus:
    """Open or bring the standalone OMNIT VPN application window to the foreground."""
    ensure_gui(app_data=app_data)
    try:
        return request("show", app_data=app_data)
    except Exception:
        return status(app_data)


def control(action: str, **parameters: Any) -> VpnStatus:
    ensure_gui()
    return request(action, **parameters)


def catalog(*, app_data: Path = DEFAULT_APP_DATA) -> VpnCatalog:
    ensure_gui(app_data=app_data)
    return _parse_catalog(
        _request_payload("catalog", app_data=app_data, timeout=2.0)
    )


def format_rate(value: int) -> str:
    amount = float(max(0, value))
    for suffix in ("Б/с", "КБ/с", "МБ/с", "ГБ/с"):
        if amount < 1024 or suffix == "ГБ/с":
            return f"{amount:.0f} {suffix}" if suffix == "Б/с" else f"{amount:.1f} {suffix}"
        amount /= 1024
    return "0 Б/с"


# OMNIT Adaptive Routing 2.0 Integration
def adaptive_router():
    """Lazily load and return the AdaptiveRouterEngine."""
    try:
        from omnit_adaptive_router import AdaptiveRouterEngine
        return AdaptiveRouterEngine()
    except ImportError:
        import sys
        sys.path.insert(0, str(Path(__file__).parent))
        from omnit_adaptive_router import AdaptiveRouterEngine
        return AdaptiveRouterEngine()


def adaptive_resolve(domain: str) -> dict[str, Any]:
    """Resolve route for domain using 6-level adaptive policy."""
    router = adaptive_router()
    decision = router.resolve(domain)
    return {
        "domain": decision.domain,
        "level": decision.level,
        "country_code": decision.country_code,
        "outbound_tag": decision.outbound_tag,
        "confidence": decision.confidence,
        "reason": decision.reason,
        "expires_at": decision.expires_at,
    }


def adaptive_pin(domain: str, country: str) -> dict[str, Any]:
    """Pin a domain to a specific country (NL, DE, US, RU)."""
    router = adaptive_router()
    decision = router.pin_domain(domain, country)
    return {
        "domain": decision.domain,
        "level": decision.level,
        "country_code": decision.country_code,
        "outbound_tag": decision.outbound_tag,
        "confidence": decision.confidence,
        "reason": decision.reason,
    }


def adaptive_unpin(domain: str) -> bool:
    """Remove manual pin for a domain."""
    router = adaptive_router()
    router.unpin_domain(domain)
    return True


def adaptive_status() -> dict[str, Any]:
    """Return status of adaptive routes, node pool, and hourly probe budget."""
    router = adaptive_router()
    routes = router.db.list_all_active_routes()
    nodes = router.db.list_nodes()
    probes = router.db.get_hourly_probe_count()
    return {
        "active_routes_count": len(routes),
        "hourly_probes": probes,
        "nodes": nodes,
        "routes": routes,
    }

