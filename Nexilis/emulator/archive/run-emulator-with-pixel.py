#!/usr/bin/env python3
"""Boot the ARM64 emulator with a Pixel-provided, in-memory ZTA bootstrap."""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import threading

import frida


PACKAGE = "com.app.plnmobile"
PIXEL = os.environ.get("PIXEL_SERIAL", "0A091FDD4009ZQ")
EMULATOR = os.environ.get("EMULATOR_SERIAL", "emulator-5554")
APP_PAYLOAD = f"/data/data/{PACKAGE}/files/nexilis_install.bin"
NATIVE_PAYLOAD = (
    f"/data/data/{PACKAGE}/no_backup/nexilis_native_components.snpc"
)
BOOTSTRAP_FILE = (
    f"/data/data/{PACKAGE}/files/.nexilis_emulator_bootstrap.json"
)
SCRIPT_DIR = Path(__file__).resolve().parent


def adb(serial, *arguments, capture=False):
    """Run ADB against one explicit device."""
    return subprocess.run(
        ["adb", "-s", serial, *arguments],
        check=True,
        text=capture,
        capture_output=capture,
    )


def adb_root(serial, command, capture=False):
    """Run one complete command inside the Magisk root shell."""
    return adb(
        serial,
        "shell",
        f"su 0 sh -c {shlex.quote(command)}",
        capture=capture,
    )


def ensure_frida_server(serial):
    """Start the existing Frida 16.5.2 server through Magisk when needed."""
    process = adb_root(
        serial,
        "pidof frida-server-16.5.2 || true",
        capture=True,
    )
    if process.stdout.strip():
        return
    adb_root(
        serial,
        "/data/local/tmp/frida-server-16.5.2 >/dev/null 2>&1 &",
    )


def remote_hash(serial, path):
    """Return the SHA-256 of one private app file."""
    result = adb_root(
        serial,
        f"sha256sum {path}",
        capture=True,
    )
    return result.stdout.split()[0]


def emulator_uid():
    """Read the emulator package UID without hard-coding an installation UID."""
    result = adb(
        EMULATOR,
        "shell",
        "cmd",
        "package",
        "list",
        "packages",
        "-U",
        PACKAGE,
        capture=True,
    )
    match = re.search(r"uid:(\d+)", result.stdout)
    if match is None:
        raise RuntimeError(f"Unable to determine UID for {PACKAGE} on {EMULATOR}")
    return match.group(1)


def copy_private_file(source_path, destination_path, uid):
    """Stream one private Pixel file to the emulator without a host copy."""
    source = subprocess.Popen(
        [
            "adb",
            "-s",
            PIXEL,
            "exec-out",
            f"su 0 sh -c {shlex.quote(f'cat {source_path}')}",
        ],
        stdout=subprocess.PIPE,
    )
    destination = subprocess.Popen(
        [
            "adb",
            "-s",
            EMULATOR,
            "shell",
            "su 0 sh -c "
            + shlex.quote(
                f"cat > {destination_path}; "
                f"chown {uid}:{uid} {destination_path}; "
                f"chmod 600 {destination_path}; restorecon {destination_path}"
            ),
        ],
        stdin=source.stdout,
    )
    if source.stdout is not None:
        source.stdout.close()
    destination_code = destination.wait()
    source_code = source.wait()
    if source_code or destination_code:
        raise RuntimeError(f"Encrypted file transfer failed: {source_path}")
    if remote_hash(PIXEL, source_path) != remote_hash(EMULATOR, destination_path):
        raise RuntimeError(f"Encrypted file hash differs after transfer: {source_path}")


def copy_encrypted_payloads():
    """Copy both encrypted artifacts required for standalone emulator boot."""
    adb(EMULATOR, "shell", "am", "force-stop", PACKAGE)
    uid = emulator_uid()
    copy_private_file(APP_PAYLOAD, APP_PAYLOAD, uid)
    copy_private_file(NATIVE_PAYLOAD, NATIVE_PAYLOAD, uid)
    print("[host] encrypted Pixel payloads copied and verified", flush=True)


def save_bootstrap(bootstrap):
    """Persist the minimum bootstrap bundle in private emulator app storage."""
    uid = emulator_uid()
    # ponytail: the payload key is plaintext-at-rest under root/app-only mode 0600;
    # upgrade to Android Keystore wrapping if this leaves a controlled POC emulator.
    command = (
        f"cat > {BOOTSTRAP_FILE}; chown {uid}:{uid} {BOOTSTRAP_FILE}; "
        f"chmod 600 {BOOTSTRAP_FILE}; restorecon {BOOTSTRAP_FILE}"
    )
    subprocess.run(
        [
            "adb",
            "-s",
            EMULATOR,
            "shell",
            f"su 0 sh -c {shlex.quote(command)}",
        ],
        input=json.dumps(bootstrap, separators=(",", ":")),
        text=True,
        check=True,
    )
    print("[host] standalone bootstrap saved with mode 0600", flush=True)


def load_bootstrap():
    """Load and validate the provisioned emulator bootstrap."""
    result = adb_root(EMULATOR, f"cat {BOOTSTRAP_FILE}", capture=True)
    bootstrap = json.loads(result.stdout)
    if bootstrap.get("schema") != 1:
        raise RuntimeError("Unsupported emulator bootstrap schema")
    if remote_hash(EMULATOR, APP_PAYLOAD) != bootstrap["payload_sha256"]:
        raise RuntimeError("Provisioned app payload hash mismatch")
    if remote_hash(EMULATOR, NATIVE_PAYLOAD) != bootstrap["native_sha256"]:
        raise RuntimeError("Provisioned native payload hash mismatch")
    bootstrap["standalone"] = True
    return bootstrap


DONOR_HOOK = r"""
Java.perform(function () {
  var Base64 = Java.use('android.util.Base64');
  var App = Java.use('com.protector.stub.ProtectorApplication');
  var delivery = App.performKeyDeliveryWithRetry.overload(
    'android.content.Context',
    'java.lang.String',
    'java.lang.String',
    'com.protector.o.y0',
    'boolean'
  );
  delivery.implementation = function (context, token, userAuth, registration, full) {
    var key = delivery.call(this, context, token, userAuth, registration, full);
    send({
      tag: 'pixel-bootstrap',
      key_b64: String(Base64.encodeToString(key, 2)),
      key_bytes: key.length,
      token: String(token),
      registration: {
        a: String(registration.a.value),
        b: String(registration.b.value),
        c: registration.c.value,
        d: String(registration.d.value),
        e: registration.e.value === null ? null : String(registration.e.value),
        f: Number(registration.f.value),
        g: registration.g.value === null ? null : String(registration.g.value),
        h: registration.h.value === null ? null : String(registration.h.value),
        i: registration.i.value,
        j: registration.j.value
      }
    });
    return key;
  };
  console.log('[donor] Pixel key capture installed');
});
"""


def receiver_hook(bootstrap):
    """Build the emulator overlay with runtime-only Pixel state."""
    return """
Java.perform(function () {
  var bootstrap = %s;
  var Base64 = Java.use('android.util.Base64');
  var App = Java.use('com.protector.stub.ProtectorApplication');
  var Registration = Java.use('com.protector.o.y0');
  var Session = Java.use('com.protector.o.z1');
  var Attacher = Java.use('com.protector.o.v0');
  var KillSwitch = Java.use('com.protector.stub.a');

  function registration() {
    var r = bootstrap.registration;
    return Registration.$new(r.a, r.b, r.c, r.d, r.e, r.f, r.g, r.h, r.i, r.j);
  }

  Session.f.overload('android.content.Context').implementation = function () {
    return bootstrap.token || 'emulator-provisioned';
  };
  if (bootstrap.standalone) {
    KillSwitch.b.overload(
      'android.content.Context', 'java.lang.String'
    ).implementation = function () {
      console.log('[pixel-donor] server status skipped for provisioned emulator');
      return true;
    };
  }
  App.ensureRegisteredWithRetry.overload('android.content.Context').implementation = function () {
    console.log('[pixel-donor] registration state supplied');
    return registration();
  };
  App.performKeyDeliveryWithRetry.overload(
    'android.content.Context',
    'java.lang.String',
    'java.lang.String',
    'com.protector.o.y0',
    'boolean'
  ).implementation = function () {
    console.log('[pixel-donor] session key supplied in memory');
    return Base64.decode(bootstrap.key_b64, 0);
  };
  Attacher.a.overload(
    'java.lang.ClassLoader',
    'android.content.Context',
    'boolean',
    'java.lang.String'
  ).implementation = function () {
    console.log('[force-clean] protected runtime reverify: allowed for Frida test');
    send({tag: 'emulator-protected-runtime'});
  };
  console.log('[pixel-donor] emulator bootstrap hooks installed');
});
""" % json.dumps(bootstrap, separators=(",", ":"))


def load_single_runtime(device, source, on_message):
    """Spawn the app and load all hooks in one Frida JavaScript runtime."""
    adb(device.id, "shell", "am", "force-stop", PACKAGE)
    pid = device.spawn([PACKAGE])
    session = device.attach(pid)
    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    return pid, session, script


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--provision",
        action="store_true",
        help="capture once from Pixel, persist privately, then verify standalone boot",
    )
    mode.add_argument(
        "--standalone",
        action="store_true",
        help="boot only from the previously provisioned emulator bundle",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="exit after protected runtime is observed instead of staying attached",
    )
    args = parser.parse_args()

    ensure_frida_server(EMULATOR)

    donor_ready = threading.Event()
    boot_ready = threading.Event()
    donor = {}

    def pixel_message(message, _data):
        payload = message.get("payload")
        if (
            message.get("type") == "send"
            and isinstance(payload, dict)
            and payload.get("tag") == "pixel-bootstrap"
        ):
            donor.update(payload)
            donor_ready.set()
            print(
                f"[host] Pixel bootstrap captured in memory ({payload['key_bytes']} bytes)",
                flush=True,
            )
            return
        print("[pixel] " + str(message.get("stack") or payload or message), flush=True)

    def emulator_message(message, _data):
        payload = message.get("payload")
        if (
            message.get("type") == "send"
            and isinstance(payload, dict)
            and payload.get("tag") == "emulator-protected-runtime"
        ):
            boot_ready.set()
            print("[host] emulator protected runtime signal received", flush=True)
            return
        text = str(message.get("stack") or payload or message)
        print("[emulator] " + text, flush=True)

    pixel_session = None
    emulator_session = None
    try:
        if args.standalone:
            bootstrap = load_bootstrap()
            print("[host] provisioned bootstrap loaded without Pixel", flush=True)
        else:
            ensure_frida_server(PIXEL)
            copy_encrypted_payloads()
            pixel_device = frida.get_device(PIXEL, timeout=5)
            pixel_source = (
                (
                    SCRIPT_DIR.parent.parent
                    / "pixel"
                    / "frida-force-clean.js"
                ).read_text()
                + "\n"
                + DONOR_HOOK
            )
            _, pixel_session, _ = load_single_runtime(
                pixel_device, pixel_source, pixel_message
            )
            if not donor_ready.wait(35):
                raise RuntimeError(
                    "Pixel did not provide a bootstrap key within 35 seconds"
                )
            bootstrap = {
                "key_b64": donor["key_b64"],
                "token": donor["token"],
                "registration": donor["registration"],
                "standalone": False,
            }
            if args.provision:
                save_bootstrap(
                    {
                        "schema": 1,
                        "key_b64": donor["key_b64"],
                        "registration": donor["registration"],
                        "payload_sha256": remote_hash(EMULATOR, APP_PAYLOAD),
                        "native_sha256": remote_hash(EMULATOR, NATIVE_PAYLOAD),
                    }
                )
                pixel_session.detach()
                bootstrap = load_bootstrap()
                print("[host] Pixel detached before standalone verification", flush=True)

        emulator_device = frida.get_device(EMULATOR, timeout=5)
        emulator_source = (
            (SCRIPT_DIR.parent / "frida-force-clean-emulator.js").read_text()
            + "\n"
            + receiver_hook(bootstrap)
        )
        pid, emulator_session, _ = load_single_runtime(
            emulator_device, emulator_source, emulator_message
        )
        print(f"[host] emulator started with Pixel bootstrap pid={pid}", flush=True)
        if not boot_ready.wait(35):
            raise RuntimeError("Emulator did not attach the protected runtime")
        print("[host] emulator protected runtime is active", flush=True)
        donor.clear()
        bootstrap.clear()
        if not args.verify_only:
            print("[host] sessions attached; press Ctrl-C to stop", flush=True)
            while not emulator_session.is_detached:
                threading.Event().wait(1)
    finally:
        donor.clear()
        if emulator_session is not None and not emulator_session.is_detached:
            emulator_session.detach()
        if pixel_session is not None and not pixel_session.is_detached:
            pixel_session.detach()


if __name__ == "__main__":
    main()
