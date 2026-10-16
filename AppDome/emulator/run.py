#!/usr/bin/env python3
"""Launch the Appdome build and install its force-clean Frida hooks."""

import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import threading
import time

import frida


DEVICE = None
PACKAGE = "com.app.plnmobile"
ACTIVITY = f"{PACKAGE}/.MainActivity"
HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "frida-force-clean.js"
FRIDA_SERVER = "/data/local/tmp/frida-server-16.5.2"
FRIDA_ALIAS = "/data/local/tmp/fs64"
FRIDA_LOG = "/data/local/tmp/appdome-frida-server.log"


def run(*arguments, capture=False, timeout=10):
    """Run a command and fail immediately when it is unsuccessful."""
    return subprocess.run(
        list(arguments),
        check=True,
        text=capture,
        capture_output=capture,
        timeout=timeout,
    )


def frida_call(label, operation, *args, timeout=5, **kwargs):
    """Cancel a blocked Frida RPC; a readiness wait cannot bound script.load()."""
    cancellation = frida.Cancellable()
    timer = threading.Timer(timeout, cancellation.cancel)
    timer.daemon = True
    timer.start()
    try:
        return operation(*args, cancellable=cancellation, **kwargs)
    except frida.OperationCancelledError as error:
        raise TimeoutError(f"{label} timed out after {timeout:g} seconds") from error
    finally:
        timer.cancel()


def detach_session(session):
    """Best-effort bounded detach without hiding the original failure."""
    if session is None or session.is_detached:
        return
    try:
        frida_call("Frida detach", session.detach, timeout=2)
    except Exception as error:
        print(f"[cleanup] detach: {error}", flush=True)


def select_device(output, requested=None):
    """Select one ready ADB serial, optionally honoring an explicit serial."""
    states = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 2 and not line.startswith("List of devices"):
            states[fields[0]] = fields[1]

    ready = [serial for serial, state in states.items() if state == "device"]
    if requested:
        if requested in ready:
            return requested
        state = states.get(requested, "not connected")
        raise RuntimeError(f"ADB device {requested} is {state}")
    if len(ready) == 1:
        return ready[0]
    if not ready:
        raise RuntimeError("No ready ADB device is connected")
    raise RuntimeError(
        "Multiple ADB devices are connected; set ANDROID_SERIAL to one of: "
        + ", ".join(ready)
    )


def detect_device():
    """Return the only connected ADB device, or the requested serial."""
    output = run("adb", "devices", capture=True).stdout
    requested = os.environ.get("ANDROID_SERIAL") or os.environ.get(
        "EMULATOR_SERIAL"
    )
    return select_device(output, requested)


def adb(*arguments, capture=False):
    """Run ADB against the selected device."""
    return run("adb", "-s", DEVICE, *arguments, capture=capture)


def adb_root(command, capture=False):
    """Run one complete command through the device's root shell."""
    return adb(
        "shell",
        f"su 0 sh -c {shlex.quote(command)}",
        capture=capture,
    )


def require_installed():
    """Require the user-managed Appdome APK installation to be present."""
    packages = adb(
        "shell",
        "cmd",
        "package",
        "list",
        "packages",
        PACKAGE,
        capture=True,
    ).stdout
    if f"package:{PACKAGE}" not in packages:
        raise RuntimeError(f"{PACKAGE} is not installed on {DEVICE}")


def stop_frida_server():
    """Stop local Frida servers before Appdome performs its startup checks."""
    adb_root(
        "kill -9 $(pidof frida-server-16.5.2) $(pidof fs64) "
        "2>/dev/null || true"
    )


def start_frida_server():
    """Start the configured server and require a successful server RPC."""
    adb_root(
        f"cp {FRIDA_SERVER} {FRIDA_ALIAS}; "
        f"chmod 755 {FRIDA_ALIAS}; "
        f"{FRIDA_ALIAS} -P >{FRIDA_LOG} 2>&1 &"
    )
    deadline = time.monotonic() + 5
    last_error = None
    while time.monotonic() < deadline:
        try:
            device = frida.get_device(DEVICE, timeout=1)
            frida_call(
                "Frida server handshake", device.enumerate_processes,
                timeout=min(1, max(0.01, deadline - time.monotonic())),
            )
            print("[setup] Frida server ready (RPC verified)", flush=True)
            return device
        except (frida.TransportError, frida.ServerNotRunningError, TimeoutError) as error:
            last_error = error
            time.sleep(0.05)
    raise RuntimeError("Frida server did not respond before readiness deadline") from last_error


def app_processes():
    """Return package PIDs and their parent PIDs."""
    output = adb(
        "shell",
        "ps",
        "-A",
        "-o",
        "PID,PPID,NAME",
        capture=True,
    ).stdout
    processes = {}
    for line in output.splitlines():
        match = re.match(r"\s*(\d+)\s+(\d+)\s+(\S+)", line)
        if match and match.group(3).strip("[]") == PACKAGE:
            processes[int(match.group(1))] = int(match.group(2))
    return processes


def launch_application():
    """Launch normally and return the package's root process."""
    adb("shell", "am", "force-stop", PACKAGE)
    adb("shell", "am", "start", "-n", ACTIVITY)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        processes = app_processes()
        roots = [
            pid for pid, parent in processes.items() if parent not in processes
        ]
        if roots:
            pid = roots[0]
            print(f"[setup] main={pid}", flush=True)
            return pid
        time.sleep(0.02)
    raise RuntimeError("Application process was not observed")


def install_hooks(device, pid, resume=None, interactive=False):
    """Attach to the running app and load the force-clean script."""
    ready = threading.Event()
    health = {"heartbeat": time.monotonic(), "touches": 0, "error": None}
    session = frida_call("Frida attach", device.attach, pid)
    script = None

    def on_message(message, _data):
        payload = message.get("payload")
        if isinstance(payload, dict):
            tag = payload.get("tag")
            if tag == "ui-heartbeat":
                health["heartbeat"] = time.monotonic()
            elif tag == "ui-touch":
                health["touches"] = payload["touches"]
            elif tag == "setup-error":
                health["error"] = payload.get("error")
                ready.set()
            else:
                print(f"[frida] {payload}", flush=True)
            if payload.get("tag") == "appdome-ready":
                ready.set()
        elif message.get("type") == "error":
            health["error"] = message.get("stack") or str(message)
            ready.set()
            print(health["error"], flush=True)

    try:
        source = (
            f"globalThis.APPDOME_INTERACTIVE = {str(interactive).lower()};\n"
            f"{SCRIPT.read_text()}"
        )
        script = frida_call("Frida create script", session.create_script, source)
        script.on("message", on_message)
        frida_call("Frida load script", script.load)
        if resume is not None:
            frida_call("Frida resume", resume)
        if not ready.wait(5):
            raise RuntimeError("Force-clean hooks did not become ready")
        if health["error"]:
            raise RuntimeError(health["error"])
        return session, script, health
    except BaseException:
        detach_session(session)
        raise


def focused_window():
    """Return the currently focused Android window."""
    output = adb("shell", "dumpsys", "window", capture=True).stdout
    return next(
        (line.strip() for line in output.splitlines() if "mCurrentFocus" in line),
        "",
    )


def require_alive(session, pid, health, check_heartbeat=True):
    """An inherited Frida connection or stale window does not prove survival."""
    if session.is_detached or pid not in app_processes():
        raise RuntimeError(f"Main application process {pid} exited")
    if health["error"]:
        raise RuntimeError(health["error"])
    if check_heartbeat and time.monotonic() - health["heartbeat"] > 5:
        raise RuntimeError("Main thread stopped responding for more than 5 seconds")


def verify(session, pid, health):
    """Verify process survival, visible UI, and a safe input interaction."""
    for _ in range(60):
        time.sleep(1)
        require_alive(session, pid, health)
    if PACKAGE not in focused_window():
        raise RuntimeError("MainActivity is not the focused window")

    for attempt in range(2):
        touches = health["touches"]
        adb("shell", "input", "tap", "200", "580")
        time.sleep(1)
        require_alive(session, pid, health)
        if PACKAGE not in focused_window():
            raise RuntimeError("Application failed the interaction check")
        if health["touches"] <= touches:
            raise RuntimeError("Application did not acknowledge the touch event")
        input_method = adb(
            "shell", "dumpsys", "input_method", capture=True
        ).stdout
        if not re.search(r"m(InputShown|IsInputViewShown)=true", input_method):
            raise RuntimeError("Phone field did not show the keyboard")
        if attempt == 0:
            adb("shell", "input", "keyevent", "BACK")
            time.sleep(1)
            require_alive(session, pid, health)
    print(
        "[verify] PASS: main PID responsive for 60s; "
        "phone field and keyboard worked twice",
        flush=True,
    )


def cleanup():
    """Remove stopped watchdogs and the temporary Frida server."""
    commands = [
        ["adb", "-s", DEVICE, "shell", "am", "force-stop", PACKAGE],
        [
            "adb",
            "-s",
            DEVICE,
            "shell",
            f"su 0 sh -c {shlex.quote('kill -9 $(pidof fs64) 2>/dev/null || true')}",
        ],
    ]
    for command in commands:
        try:
            subprocess.run(command, check=False, timeout=5, capture_output=True)
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f"[cleanup] {error}", flush=True)


def main():
    """Run interactively, or execute one bounded end-to-end verification."""
    global DEVICE

    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify-only", action="store_true")
    mode.add_argument("--interactive", action="store_true")
    args = parser.parse_args()

    DEVICE = detect_device()
    print(f"[setup] ADB device={DEVICE}", flush=True)
    require_installed()
    adb("shell", "am", "clear-debug-app")
    stop_frida_server()
    session = None
    script = None
    pid = None
    try:
        device = start_frida_server()
        if args.interactive:
            pid = launch_application()
            session, script, health = install_hooks(
                device, pid, interactive=True
            )
        else:
            pid = launch_application()
            time.sleep(0.8)
            session, script, health = install_hooks(device, pid)
        if args.verify_only:
            verify(session, pid, health)
            return
        print("[ready] App is running; press Ctrl+C to stop", flush=True)
        while True:
            time.sleep(1)
            require_alive(
                session,
                pid,
                health,
                check_heartbeat=not args.interactive,
            )
    except KeyboardInterrupt:
        pass
    except Exception:
        server_pid = adb_root("pidof fs64 || true", capture=True).stdout.strip()
        app_pid = adb_root(f"pidof {PACKAGE} || true", capture=True).stdout.strip()
        print(
            f"[diagnostic] server={server_pid or 'stopped'}; "
            f"app={app_pid or 'stopped'}",
            flush=True,
        )
        try:
            server_log = adb_root(f"tail -n 30 {FRIDA_LOG}", capture=True).stdout.strip()
            if server_log:
                print(f"[diagnostic] Frida server log:\n{server_log}", flush=True)
        except Exception as error:
            print(f"[diagnostic] unable to read server log: {error}", flush=True)
        raise
    finally:
        # A dead process may leave an inherited session reporting attached.
        # Do not detach it after killing the server: Frida 16.5.2 can abort
        # inside _frida_device_release_session_co instead of raising Python.
        try:
            if session is not None and pid is not None and pid in app_processes():
                detach_session(session)
        except Exception as error:
            print(f"[cleanup] session status: {error}", flush=True)
        finally:
            cleanup()


if __name__ == "__main__":
    main()
