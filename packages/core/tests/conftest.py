import sys
from pathlib import Path

# Add the 'packsafe' root directory to sys.path so 'packages.core...' imports work
# This allows pytest to be run from inside the tests directory.
project_root = Path(__file__).resolve().parent.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
