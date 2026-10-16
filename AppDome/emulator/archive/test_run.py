#!/usr/bin/env python3
"""Small dependency-free checks for ADB device selection."""

import importlib.util
from pathlib import Path


RUN_PATH = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("appdome_run", RUN_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


assert MODULE.select_device("List of devices attached\nABC\tdevice\n") == "ABC"
assert (
    MODULE.select_device(
        "List of devices attached\nBAD\tunauthorized\nGOOD\tdevice\n"
    )
    == "GOOD"
)
assert MODULE.select_device(
    "List of devices attached\nA\tdevice\nB\tdevice\n", "B"
) == "B"

try:
    MODULE.select_device("List of devices attached\nA\tdevice\nB\tdevice\n")
except RuntimeError:
    pass
else:
    raise AssertionError("Multiple devices must require ANDROID_SERIAL")

print("PASS: ADB device selection")
