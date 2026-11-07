#!/usr/bin/env python3
"""Exercise unattended privilege failures against the real Linux GUI and core.

Uses fresh temporary databases and an unprivileged copy of ThroneCore; never
reads the owner's VPN configuration or enables routing on the host.
Run: python3 script/test_control_privileges.py --binary build/Throne
"""

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time


PREFIX = b"OMNIT-CONTROL/1 "


def socket_path(app_data):
    digest = base64.b64encode(hashlib.md5(str(app_data).encode()).digest())
    name = digest.decode().rstrip("=").replace("+", "0").replace("/", "1")
    return Path(tempfile.gettempdir()) / f"throne-{name}"


def wire(action, **parameters):
    return PREFIX + json.dumps({"apiVersion": 1, "action": action, **parameters}).encode() + b"\n"


def request(path, action="status", **parameters):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(1.0)
        client.connect(str(path))
        client.sendall(wire(action, **parameters))
        with client.makefile("rb") as stream:
            line = stream.readline()
    assert line.startswith(PREFIX), line
    return json.loads(line[len(PREFIX):])


def check_rejected(response, error="core_privileges_required"):
    assert response["ok"] is False, response
    assert response["accepted"] is False, response
    assert response["error"] == error, response
    assert response["tunEnabled"] is False, response
    assert response["connected"] is False, response


def run_case(runtime, name, settings, action, parameters, *,
             error="core_privileges_required", base_database=None, asynchronous=False):
    app_data = runtime / name
    config = app_data / "config"
    config.mkdir(parents=True)
    if base_database is not None:
        # SQLite may retain committed rows in its WAL after a stopped GUI.
        with sqlite3.connect(base_database) as source, sqlite3.connect(config / "throne.db") as target:
            source.backup(target)
    with sqlite3.connect(config / "throne.db") as database:
        database.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        database.executemany("INSERT OR REPLACE INTO settings VALUES (?, ?)", {
            "disable_tray": "true", **settings,
        }.items())

    environment = {
        **os.environ,
        "QT_QPA_PLATFORM": "offscreen",
        "QT_QPA_PLATFORMTHEME": "",
        "XDG_CONFIG_HOME": str(runtime / "xdg-config"),
        "XDG_DATA_HOME": str(runtime / "xdg-data"),
        "XDG_CACHE_HOME": str(runtime / "xdg-cache"),
    }
    for key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        Path(environment[key]).mkdir(exist_ok=True)
    path = socket_path(app_data)
    with (runtime / f"{name}.log").open("wb") as log:
        process = subprocess.Popen(
            ["dbus-run-session", "--", str(runtime / "Throne"), "-appdata", str(app_data), "-tray"],
            stdout=log, stderr=log, env=environment, start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 15
            while True:
                assert process.poll() is None, "Test GUI exited during startup"
                try:
                    if request(path).get("ok"):
                        break
                except (OSError, AssertionError):
                    pass
                if time.monotonic() > deadline:
                    output = (runtime / f"{name}.log").read_text(errors="replace")
                    raise AssertionError(f"Unprivileged test core did not become ready:\n{output[-6000:]}")
                time.sleep(0.05)

            def check(response):
                if not asynchronous:
                    check_rejected(response, error)
                    return
                assert response["ok"], response
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    status = request(path)
                    if status["state"] == "idle" and status.get("error") == error:
                        assert not status["connected"] and not status["tunEnabled"]
                        return
                    time.sleep(0.02)
                raise AssertionError(f"Missing asynchronous error: {status}")

            # Both immediate config errors and later core failures must leave
            # the control socket responsive under unattended retries.
            for _ in range(10):
                check(request(path, action, **parameters))
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(request, path, action, **parameters) for _ in range(24)]
                for future in futures:
                    check(future.result())

            # A caller disappearing must neither replay its request nor leave a
            # dangling socket pointer in the GUI's handler.
            for _ in range(20):
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(str(path))
                    client.sendall(wire(action, **parameters))
            for _ in range(5):
                status = request(path)
                assert status["ok"] and not status["tunEnabled"], status
                time.sleep(0.02)
            assert request(path, "set-tun", enabled=False)["ok"]
            invalid = request(path, "set-tun", enabled="yes")
            assert invalid["error"] == "enabled_must_be_boolean", invalid
            assert process.poll() is None
            print(f"PASS {name}: serial/concurrent retries, disconnected callers, responsive status", flush=True)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            # dbus-run-session may exit before a GUI stuck in its shutdown
            # handler. Reap any surviving members of this test-only group.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("build/Throne"))
    parser.add_argument("--core", type=Path, default=Path("build/ThroneCore"))
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("Run as an ordinary desktop user, not root")
    with tempfile.TemporaryDirectory(prefix="omnit-privilege-test-") as directory:
        runtime = Path(directory)
        shutil.copyfile(args.binary.resolve(), runtime / "Throne")
        shutil.copyfile(args.core.resolve(), runtime / "ThroneCore")
        for filename in ("Throne", "ThroneCore"):
            (runtime / filename).chmod(0o755)
        run_case(runtime, "missing-privilege", {}, "set-tun", {"enabled": True})
        run_case(runtime, "saved-tun", {"tun_mode_enabled": "true"}, "set-tun", {"enabled": True})
        run_case(runtime, "privileged-dns", {
            "enable_dns_server": "true", "dns_server_listen_port": "53",
        }, "connect", {})
        seed = runtime / "missing-privilege" / "config" / "throne.db"
        run_case(runtime, "missing-route", {"current_route_id": "999999"},
                 "connect", {}, error="invalid_profile_config", base_database=seed)
        run_case(runtime, "invalid-warp", {"enable_warp": "true"},
                 "connect", {}, error="invalid_profile_config", base_database=seed)
        run_case(runtime, "core-config-error", {"inbound_address": "invalid-address"},
                 "connect", {}, error="core_start_failed", base_database=seed, asynchronous=True)


if __name__ == "__main__":
    main()
