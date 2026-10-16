#!/usr/bin/env python3
"""Restore emulator payloads after reinstall and launch the Frida script."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import shlex
import subprocess
import threading


DEVICE = os.environ.get("EMULATOR_SERIAL", "emulator-5554")
PACKAGE = "com.app.plnmobile"
HERE = Path(__file__).resolve().parent
SRC = HERE / "src"
SCRIPT = HERE / "frida-force-clean-emulator.js"
PAYLOADS = {
    "nexilis_install.bin": (
        f"/data/data/{PACKAGE}/files/nexilis_install.bin",
        "0dd9b08fde9482e89be3b780f46f491722a8aa522a99f8b9b6e6024002f1aeec",
    ),
    "nexilis_native_components.snpc": (
        f"/data/data/{PACKAGE}/no_backup/nexilis_native_components.snpc",
        "72ac0d09901925d8b070cd38c114910920d5fbbb2a4894352b69db317b184fe3",
    ),
}


def run(*arguments, capture=False):
    """Run a command and fail immediately on an unsuccessful result."""
    return subprocess.run(
        list(arguments),
        check=True,
        text=capture,
        capture_output=capture,
    )


def adb(*arguments, capture=False):
    """Run ADB against the selected emulator."""
    return run("adb", "-s", DEVICE, *arguments, capture=capture)


def adb_root(command, capture=False):
    """Run one complete command through the emulator's Magisk root shell."""
    return adb(
        "shell",
        f"su 0 sh -c {shlex.quote(command)}",
        capture=capture,
    )


def verify_payloads():
    """Reject missing or modified payloads before touching the device."""
    for name, (_, expected) in PAYLOADS.items():
        path = SRC / name
        if not path.is_file():
            raise RuntimeError(f"Missing payload: {path}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError(f"Payload hash mismatch: {name}")


def require_installed():
    """Require the user-managed APK installation to be present."""
    installed = adb(
        "shell",
        "cmd",
        "package",
        "list",
        "packages",
        PACKAGE,
        capture=True,
    ).stdout
    if f"package:{PACKAGE}" in installed:
        return
    raise RuntimeError(
        "Install APK manually before running this launcher: "
        f"{PACKAGE} is not installed on {DEVICE}"
    )


def package_uid():
    """Return the package UID assigned by the latest installation."""
    output = adb(
        "shell",
        "cmd",
        "package",
        "list",
        "packages",
        "-U",
        PACKAGE,
        capture=True,
    ).stdout
    match = re.search(r"uid:(\d+)", output)
    if match is None:
        raise RuntimeError(f"Unable to determine UID for {PACKAGE}")
    return match.group(1)


def restore_payloads():
    """Restore encrypted payloads with the new UID and SELinux labels."""
    uid = package_uid()
    adb("shell", "am", "force-stop", PACKAGE)
    for name, (destination, _) in PAYLOADS.items():
        temporary = f"/data/local/tmp/{name}"
        parent = str(Path(destination).parent)
        adb("push", str(SRC / name), temporary)
        adb_root(
            f"mkdir -p {shlex.quote(parent)}; "
            f"chown {uid}:{uid} {shlex.quote(parent)}; "
            f"chmod 771 {shlex.quote(parent)}; "
            f"restorecon {shlex.quote(parent)}; "
            f"cp {shlex.quote(temporary)} {shlex.quote(destination)}; "
            f"chown {uid}:{uid} {shlex.quote(destination)}; "
            f"chmod 600 {shlex.quote(destination)}; "
            f"restorecon {shlex.quote(destination)}; "
            f"rm -f {shlex.quote(temporary)}"
        )
    print("[restore] encrypted payloads restored", flush=True)


def ensure_frida_server():
    """Start the existing Frida 16.5.2 server when it is not running."""
    running = adb_root(
        "pidof frida-server-16.5.2 || true",
        capture=True,
    ).stdout.strip()
    if not running:
        adb_root(
            "/data/local/tmp/frida-server-16.5.2 >/dev/null 2>&1 &"
        )


def verify_launch():
    """Run a bounded end-to-end launch for automated verification."""
    import frida

    ready = threading.Event()

    def on_message(message, _data):
        payload = message.get("payload")
        if (
            isinstance(payload, dict)
            and payload.get("tag") == "emulator-protected-runtime"
        ):
            ready.set()
        elif message.get("type") == "error":
            print(message.get("stack") or message, flush=True)

    device = frida.get_device(DEVICE, timeout=5)
    pid = device.spawn([PACKAGE])
    session = device.attach(pid)
    script = session.create_script(SCRIPT.read_text())
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    if not ready.wait(20):
        raise RuntimeError("Protected runtime did not become active")
    threading.Event().wait(5)
    if session.is_detached:
        raise RuntimeError("Application exited during verification")
    session.detach()
    print("[restore] clean-reinstall launch verified", flush=True)


def main():
    """Restore required state, then run interactively or verify once."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    verify_payloads()
    require_installed()
    restore_payloads()
    ensure_frida_server()
    if args.verify_only:
        verify_launch()
        return

    print("[restore] launching self-contained Frida script", flush=True)
    os.execvp(
        "frida",
        [
            "frida",
            "-D",
            DEVICE,
            "-f",
            PACKAGE,
            "-l",
            str(SCRIPT),
        ],
    )


if __name__ == "__main__":
    main()
