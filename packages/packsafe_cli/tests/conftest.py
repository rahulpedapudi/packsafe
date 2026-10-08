"""Makes ``packsafe_cli`` importable when pytest runs from the repo root."""

import sys
from pathlib import Path

CLI_ROOT = Path(__file__).resolve().parent.parent

if str(CLI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLI_ROOT))