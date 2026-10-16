#!/usr/bin/env python3
"""Embed the current emulator provisioning bundle into the Frida script."""

import json
import os
from pathlib import Path
import re
import shlex
import subprocess


DEVICE = os.environ.get("EMULATOR_SERIAL", "emulator-5554")
PACKAGE = "com.app.plnmobile"
BUNDLE = f"/data/data/{PACKAGE}/files/.nexilis_emulator_bootstrap.json"
SCRIPT = Path(__file__).resolve().parent.parent / "frida-force-clean-emulator.js"


result = subprocess.run(
    [
        "adb",
        "-s",
        DEVICE,
        "exec-out",
        f"su 0 sh -c {shlex.quote(f'cat {BUNDLE}')}",
    ],
    check=True,
    text=True,
    capture_output=True,
)
provisioning = json.loads(result.stdout)
embedded = {
    "schema": provisioning["schema"],
    "key_b64": provisioning["key_b64"],
    "registration": provisioning["registration"],
}

source = SCRIPT.read_text()
replacement = (
    "/* provisioning:start */ "
    + json.dumps(embedded, separators=(",", ":"))
    + " /* provisioning:end */"
)
source, replacements = re.subn(
    r"/\* provisioning:start \*/.*?/\* provisioning:end \*/",
    replacement,
    source,
    count=1,
    flags=re.DOTALL,
)
if replacements != 1:
    raise RuntimeError("Provisioning marker not found exactly once")
SCRIPT.write_text(source)
print("Provisioning embedded without printing key material")
