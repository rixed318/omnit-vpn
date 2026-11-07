#!/usr/bin/python3
"""Keep the owner-session OMNIT VPN and TUN connected.

The guard deliberately uses only the public, owner-only OMNIT control socket.
It does not open the Throne database and never handles subscription URLs,
credentials or server configuration.  The selected route is preserved unless
the service was explicitly installed with ``--full-tunnel``.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import omnit_vpn_adapter as vpn_adapter


SERVICE_NAME = "omnit-vpn-guard.service"
DEFAULT_INTERVAL = 10.0


@dataclass(frozen=True)
class GuardResult:
    connected: bool
    tun_enabled: bool
    route_mode: str
    changes: tuple[str, ...] = ()


def _safe_unit_path(value: Path | str) -> str:
    text = str(value)
    if not Path(text).is_absolute() or any(character in text for character in "\r\n\0"):
        raise ValueError("systemd path must be absolute and safe")
    return text.replace("\\", "\\\\").replace(" ", "\\x20").replace("%", "%%")


def user_service_path(home: Path | None = None) -> Path:
    owner = Path(home or Path.home()).expanduser().resolve()
    return owner / ".config" / "systemd" / "user" / SERVICE_NAME


def service_unit(
    *,
    source_root: Path | None = None,
    python_executable: Path | None = None,
    interval: float = DEFAULT_INTERVAL,
    enforce_full_tunnel: bool = False,
) -> str:
    source = Path(source_root or Path(__file__).resolve().parents[1]).resolve()
    if source.name == "src" and (source / Path(__file__).name).is_file():
        source = source.parent
    python = Path(python_executable or sys.executable).resolve()
    script = source / "src" / Path(__file__).name
    seconds = max(2.0, float(interval))
    route_argument = " --full-tunnel" if enforce_full_tunnel else ""
    return "\n".join((
        "[Unit]",
        "Description=OMNIT VPN always-on connection guard",
        "After=graphical-session.target network-online.target",
        "Wants=network-online.target",
        "PartOf=graphical-session.target",
        "",
        "[Service]",
        "Type=simple",
        f"ExecStart={_safe_unit_path(python)} {_safe_unit_path(script)} "
        f"run --interval {seconds:g}{route_argument}",
        "Restart=always",
        "RestartSec=3",
        "TimeoutStopSec=10",
        "UMask=0077",
        "Environment=PYTHONUNBUFFERED=1",
        "",
        "[Install]",
        "WantedBy=graphical-session.target",
        "",
    ))


def _systemctl(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["systemctl", "--user", *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def install_user_service(
    *,
    source_root: Path | None = None,
    home: Path | None = None,
    python_executable: Path | None = None,
    interval: float = DEFAULT_INTERVAL,
    enforce_full_tunnel: bool = False,
) -> Path:
    unit = user_service_path(home)
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.parent.chmod(0o700)
    content = service_unit(
        source_root=source_root,
        python_executable=python_executable,
        interval=interval,
        enforce_full_tunnel=enforce_full_tunnel,
    )
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=unit.parent,
        prefix=f".{SERVICE_NAME}.", delete=False,
    ) as handle:
        temporary = Path(handle.name)
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o600)
    os.replace(temporary, unit)
    for arguments in (("daemon-reload",), ("enable", "--now", SERVICE_NAME)):
        result = _systemctl(*arguments)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout).strip())
    return unit


def reconcile(
    *,
    ensure_gui: Callable[[], vpn_adapter.VpnStatus] = vpn_adapter.ensure_gui,
    get_catalog: Callable[[], vpn_adapter.VpnCatalog] = vpn_adapter.catalog,
    control: Callable[..., vpn_adapter.VpnStatus] = vpn_adapter.control,
    enforce_full_tunnel: bool = False,
) -> GuardResult:
    """Restore TUN and connection while preserving the owner's route choice."""

    status = ensure_gui()
    changes: list[str] = []

    if enforce_full_tunnel and status.route_mode != "full":
        catalog = get_catalog()
        full_route = next((route for route in catalog.routes if route.mode == "full"), None)
        if full_route is None:
            raise vpn_adapter.VpnAdapterError("OMNIT Full Tunnel route is unavailable")
        status = control("set-route", routeId=full_route.id)
        changes.append("route")

    if not status.tun_enabled:
        status = control("set-tun", enabled=True)
        changes.append("tun")

    if not status.connected:
        status = control("connect")
        changes.append("connect")

    try:
        ar_check = subprocess.run(
            ["systemctl", "--user", "is-active", "--quiet", "omnit-adaptive-router.service"],
            timeout=5,
        )
        if ar_check.returncode != 0:
            subprocess.run(
                ["systemctl", "--user", "start", "omnit-adaptive-router.service"],
                timeout=10,
            )
            changes.append("adaptive-router")
    except Exception:
        pass

    return GuardResult(
        connected=status.connected,
        tun_enabled=status.tun_enabled,
        route_mode=status.route_mode,
        changes=tuple(changes),
    )


def run_forever(
    *,
    interval: float = DEFAULT_INTERVAL,
    enforce_full_tunnel: bool = False,
    reconcile_action: Callable[[], GuardResult] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    delay = max(2.0, float(interval))
    action = reconcile_action or (
        lambda: reconcile(enforce_full_tunnel=enforce_full_tunnel)
    )
    last_error = ""
    while True:
        try:
            result = action()
            if result.changes:
                print(f"OMNIT VPN restored: {','.join(result.changes)}", flush=True)
            last_error = ""
        except (OSError, RuntimeError, vpn_adapter.VpnAdapterError) as error:
            message = str(error).strip()[:500]
            if message != last_error:
                print(f"OMNIT VPN guard waiting: {message}", file=sys.stderr, flush=True)
                last_error = message
        sleep(delay)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL)
    run_parser.add_argument("--full-tunnel", action="store_true")
    install_parser = subparsers.add_parser("install")
    install_parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL)
    install_parser.add_argument("--full-tunnel", action="store_true")
    once_parser = subparsers.add_parser("once")
    once_parser.add_argument("--full-tunnel", action="store_true")
    args = parser.parse_args(argv)

    if args.command == "install":
        print(
            install_user_service(
                interval=args.interval,
                enforce_full_tunnel=args.full_tunnel,
            )
        )
        return 0
    if args.command == "once":
        result = reconcile(enforce_full_tunnel=args.full_tunnel)
        print(
            f"connected={int(result.connected)} tun={int(result.tun_enabled)} "
            f"route={result.route_mode} changes={','.join(result.changes) or 'none'}"
        )
        return 0
    run_forever(
        interval=args.interval,
        enforce_full_tunnel=args.full_tunnel,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
