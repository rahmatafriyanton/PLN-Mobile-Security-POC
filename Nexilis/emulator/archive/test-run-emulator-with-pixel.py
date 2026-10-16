from pathlib import Path


runner = Path(__file__).with_name("run-emulator-with-pixel.py")
assert runner.is_file(), "emulator runner must exist"

source = runner.read_text()
assert "frida-force-clean.js" in source
assert "frida-force-clean-emulator.js" in source
assert "pixel-bootstrap" in source
assert "emulator-protected-runtime" in source
assert "key_b64" in source
assert "shlex.quote" in source
assert "--provision" in source
assert "--standalone" in source
assert ".nexilis_emulator_bootstrap.json" in source
assert "ponytail:" in source
assert "write_text" not in source
assert "write_bytes" not in source
assert "key_b64 =" not in source

print("emulator Pixel-bootstrap runner checks passed")
