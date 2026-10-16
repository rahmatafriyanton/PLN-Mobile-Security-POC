import hashlib
from pathlib import Path


HERE = Path(__file__).resolve().parent
EMULATOR = HERE.parent
SRC = EMULATOR / "src"
expected = {
    "nexilis_install.bin": (
        "0dd9b08fde9482e89be3b780f46f491722a8aa522a99f8b9b6e6024002f1aeec"
    ),
    "nexilis_native_components.snpc": (
        "72ac0d09901925d8b070cd38c114910920d5fbbb2a4894352b69db317b184fe3"
    ),
}

launcher = EMULATOR / "run.py"
assert launcher.is_file(), "run.py must exist"

for name, digest in expected.items():
    payload = SRC / name
    assert payload.is_file(), f"{name} must exist"
    assert hashlib.sha256(payload.read_bytes()).hexdigest() == digest

source = launcher.read_text()
assert "adb" in source
assert "Install APK manually before running this launcher" in source
assert '"install",' not in source
assert "restorecon" in source
assert "frida-force-clean-emulator.js" in source
assert "--verify-only" in source

print("reinstall restore launcher checks passed")
