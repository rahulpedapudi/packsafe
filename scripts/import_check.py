"""Imports every PackSafe module on the running interpreter.

Exists because the oldest supported Python is the one least likely to be in a local test
matrix, and it is where stdlib behaviour differs: 3.11 rejects an unhashable dataclass
default, which 3.12+ accepts. That difference shipped a broken wheel to PyPI before.

Run it on every version you claim to support:

    uv run --python 3.11 --package packsafe python scripts/import_check.py
"""

from __future__ import annotations

import importlib
import pkgutil
import sys

PACKAGES = ("packsafe_core", "packsafe_cli")


def main() -> int:
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    print(f"python {version}")

    failures: list[tuple[str, str]] = []

    for name in PACKAGES:
        try:
            root = importlib.import_module(name)
        except Exception as e:  # noqa: BLE001 - this is a diagnostic, report anything
            failures.append((name, f"{type(e).__name__}: {e}"))
            continue

        for info in pkgutil.walk_packages(root.__path__, f"{name}."):
            try:
                importlib.import_module(info.name)
            except Exception as e:  # noqa: BLE001 - same
                failures.append((info.name, f"{type(e).__name__}: {e}"))

    for name, error in failures:
        print(f"  FAIL {name}: {error}")

    if failures:
        print(f"  {len(failures)} module(s) failed to import")
        return 1

    print("  all modules import cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())