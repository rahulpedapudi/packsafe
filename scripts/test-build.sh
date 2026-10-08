#!/usr/bin/env bash
# Build PackSafe wheels and install them into a throwaway sandbox venv, so the packaged
# result can be exercised without publishing anything or touching the dev environment.
#
#   ./scripts/test-build.sh              # build, install, smoke test
#   ./scripts/test-build.sh --keep       # leave the sandbox in place afterwards
#   ./scripts/test-build.sh --matrix     # also import-check every supported Python
#
# Why a separate venv: an editable install resolves imports from the source tree, so it
# hides packaging mistakes - a missing data file, an undeclared dependency, an
# interpreter-specific dataclass error - that only appear once the wheel is installed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANDBOX="${PACKSAFE_SANDBOX:-/tmp/packsafe-sandbox}"
DIST="$SANDBOX/dist"
TARGET_VENV="$SANDBOX/target"

#: Oldest first. 3.11 is where stdlib behaviour differs most from the dev interpreter.
SUPPORTED_PYTHONS=(3.11 3.12 3.13 3.14)

KEEP=0
MATRIX=0
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    --matrix) MATRIX=1 ;;
  esac
done

cleanup() {
  if [[ $KEEP -eq 0 ]]; then
    rm -rf "$TARGET_VENV"
  fi
}
trap cleanup EXIT

echo "==> Building wheels (nothing is uploaded)"
rm -rf "$DIST"
uv build --all-packages --out-dir "$DIST"

if [[ $MATRIX -eq 1 ]]; then
  echo
  echo "==> Import check across every supported Python (${SUPPORTED_PYTHONS[*]})"
  # The published wheel must import on the oldest supported interpreter, not just the
  # one in the dev venv. A dataclass default that 3.12 accepts and 3.11 rejects reached
  # PyPI once already.
  matrix_failed=0
  for py in "${SUPPORTED_PYTHONS[@]}"; do
    env_dir="$SANDBOX/py$py"
    rm -rf "$env_dir"
    uv venv --python "$py" "$env_dir" >/dev/null
    uv pip install --python "$env_dir/bin/python" \
      "$DIST"/packsafe_core-*.whl "$DIST"/packsafe-[0-9]*.whl >/dev/null 2>&1
    if output="$("$env_dir/bin/python" "$REPO_ROOT/scripts/import_check.py" 2>&1)"; then
      printf '  %s\n' "$output" | sed 's/^/  /'
    else
      printf '%s\n' "$output" | sed 's/^/  /'
      matrix_failed=1
    fi
    rm -rf "$env_dir"
  done
  if [[ $matrix_failed -ne 0 ]]; then
    echo "  FAILED: at least one supported Python could not import the wheel"
    exit 1
  fi
  echo "  ok: the wheel imports on every supported Python"
fi

echo
echo "==> Creating a clean venv at $SANDBOX/.venv"
rm -rf "$SANDBOX/.venv"
uv venv "$SANDBOX/.venv"

echo
echo "==> Installing the built wheels (not editable, not from the source tree)"
# Both wheels by path: naming them explicitly stops the resolver from quietly picking up
# a published packsafe-core from an index instead of the one just built.
uv pip install --python "$SANDBOX/.venv/bin/python" \
  "$DIST"/packsafe_core-*.whl \
  "$DIST"/packsafe-[0-9]*.whl

PACKSAFE="$SANDBOX/.venv/bin/packsafe"

echo
echo "==> Verifying the version flag reads the installed distribution"
"$PACKSAFE" --version | sed 's/^/  /'

echo
echo "==> Verifying the packaged data files shipped"
"$SANDBOX/.venv/bin/python" - <<'PY'
import glob
import os
import zipfile

sandbox = os.environ.get("PACKSAFE_SANDBOX", "/tmp/packsafe-sandbox")
wheels = glob.glob(os.path.join(sandbox, "dist", "packsafe_core-*.whl"))
names = zipfile.ZipFile(wheels[0]).namelist()
required = [
    "packsafe_core/scoring/config/metrics.yaml",
    "packsafe_core/scoring/config/weights.yaml",
    "packsafe_core/scoring/config/gates.yaml",
    "packsafe_core/data/popular_packages_v1.json",
]
missing = [n for n in required if n not in names]
if missing:
    raise SystemExit(f"missing from the wheel: {missing}")
print(f"  ok: {len(required)} required data files present")
PY

echo
echo "==> Verifying the score engine config loads from inside the wheel"
"$SANDBOX/.venv/bin/python" -c "
from packsafe_core.scoring.config import load_engine_config
c = load_engine_config()
print(f'  ok: config {c.config_version} sha {c.config_sha256[:12]}')
"

echo
echo "==> Commands available"
COLUMNS=100 "$PACKSAFE" --help 2>&1 | sed -n '/Commands/,$p'

echo
echo "==> Smoke test: analyze a known-good package"
COLUMNS=100 "$PACKSAFE" analyze urllib3 2>&1 | grep -E "SAFETY SCORE|Vulnerabilities " || true

echo
echo "==> Smoke test: the install gate blocks before running a package manager"
# --min-score 100 cannot be satisfied, so this must refuse and exit 4 without installing.
set +e
COLUMNS=100 "$PACKSAFE" install --uv requests --min-score 100 >"$SANDBOX/blocked.log" 2>&1
blocked_code=$?
set -e
if [[ $blocked_code -ne 4 ]]; then
  echo "  FAILED: expected exit 4 from the blocked path, got $blocked_code"
  cat "$SANDBOX/blocked.log"
  exit 1
fi
echo "  ok: refused with exit 4"
grep -E "Install Blocked" "$SANDBOX/blocked.log" | sed 's/^/  /'

echo
echo "==> Smoke test: logs land in ./.packsafe/logs, not in the working directory"
# Run from an empty directory so a stray log file would be visible.
LOG_DIR_TEST="$SANDBOX/logtest"
rm -rf "$LOG_DIR_TEST"
mkdir -p "$LOG_DIR_TEST"
(cd "$LOG_DIR_TEST" && COLUMNS=100 "$PACKSAFE" analyze flask) >/dev/null 2>&1
if [[ -f "$LOG_DIR_TEST/.packsafe/logs/packsafe.log" ]]; then
  echo "  ok: .packsafe/logs/packsafe.log"
else
  echo "  FAILED: log was not written to .packsafe/logs/"
  exit 1
fi
stray="$(find "$LOG_DIR_TEST" -maxdepth 1 -type f | wc -l | tr -d ' ')"
if [[ "$stray" == "0" ]]; then
  echo "  ok: no stray files in the working directory"
else
  echo "  FAILED: $stray stray file(s) in the working directory"
  find "$LOG_DIR_TEST" -maxdepth 1 -type f | sed 's/^/    /'
  exit 1
fi

echo
echo "==> Smoke test: install targets the CWD's environment, not a global one"
# Run from a directory holding only its own .venv. An install that resolved to a global
# or to PackSafe's own interpreter would still "succeed", so the assertion is that the
# package landed in ./.venv and nowhere else.
PROJECT_DIR="$SANDBOX/project"
rm -rf "$PROJECT_DIR"
mkdir -p "$PROJECT_DIR"
(cd "$PROJECT_DIR" && uv venv >/dev/null)

set +e
(cd "$PROJECT_DIR" && COLUMNS=100 "$PACKSAFE" install --uv requests) >"$SANDBOX/install.log" 2>&1
install_code=$?
set -e

grep -E "Install Cleared|Target:|\+ requests|✓ Installed" "$SANDBOX/install.log" | sed 's/^/  /'
if [[ $install_code -ne 0 ]]; then
  echo "  FAILED: expected a clean install, got exit $install_code"
  cat "$SANDBOX/install.log"
  exit 1
fi

"$PROJECT_DIR/.venv/bin/python" -c \
  "from importlib.metadata import version; print(f'  ok: requests {version(\"requests\")} landed in ./.venv')"

# The same run must not have touched any other environment. The PackSafe sandbox venv is
# the nearest neighbour, and the one a global PATH pip would have used instead.
if "$SANDBOX/.venv/bin/python" -c "
from importlib.metadata import PackageNotFoundError, version
try:
    version('requests'); raise SystemExit(0)
except PackageNotFoundError:
    raise SystemExit(1)
" 2>/dev/null; then
  echo "  FAILED: requests leaked into the PackSafe sandbox venv"
  exit 1
else
  echo "  ok: nothing leaked outside ./.venv"
fi

echo
echo "==> Smoke test: a directory with no environment is refused, not installed globally"
BARE_DIR="$SANDBOX/no-env"
rm -rf "$BARE_DIR"
mkdir -p "$BARE_DIR"
set +e
(cd "$BARE_DIR" && COLUMNS=100 "$PACKSAFE" install --uv requests) >"$SANDBOX/noenv.log" 2>&1
noenv_code=$?
set -e
if [[ $noenv_code -eq 5 ]]; then
  echo "  ok: refused with exit 5"
else
  echo "  FAILED: expected exit 5 with no environment, got $noenv_code"
  cat "$SANDBOX/noenv.log"
  exit 1
fi
grep -E "No Install Target|No Python environment" "$SANDBOX/noenv.log" | head -1 | sed 's/^/  /'

echo
if [[ $KEEP -eq 1 ]]; then
  echo "Sandbox kept at $SANDBOX"
  echo "  cd $SANDBOX && ./.venv/bin/packsafe --help"
else
  echo "All checks passed. Sandbox: $SANDBOX (target venv removed)"
fi