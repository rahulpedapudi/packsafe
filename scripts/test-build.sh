#!/usr/bin/env bash
# Build PackSafe wheels and install them into a throwaway sandbox venv, so the packaged
# result can be exercised without publishing anything or touching the dev environment.
#
#   ./scripts/test-build.sh              # build, install, smoke test
#   ./scripts/test-build.sh --keep       # leave the sandbox in place afterwards
#
# Why a separate venv: an editable install resolves imports from the source tree, so it
# hides packaging mistakes - a missing data file, an undeclared dependency - that only
# appear once the wheel is the thing on sys.path.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANDBOX="${PACKSAFE_SANDBOX:-/tmp/packsafe-sandbox}"
DIST="$SANDBOX/dist"
TARGET_VENV="$SANDBOX/target"

KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

cleanup() {
  if [[ $KEEP -eq 0 ]]; then
    rm -rf "$TARGET_VENV"
  fi
}
trap cleanup EXIT

echo "==> Building wheels (nothing is uploaded)"
rm -rf "$DIST"
uv build --all-packages --out-dir "$DIST"

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
echo "==> Verifying the packaged data files shipped"
"$SANDBOX/.venv/bin/python" - <<'PY'
import zipfile, glob
wheels = glob.glob("/tmp/packsafe-sandbox/dist/packsafe_core-*.whl")
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
echo "==> Smoke test: install a safe package into a separate throwaway venv"
# The target is its own venv so the sandbox itself stays clean and re-runnable.
rm -rf "$TARGET_VENV"
uv venv "$TARGET_VENV" >/dev/null
COLUMNS=100 "$PACKSAFE" install --uv requests -- --python "$TARGET_VENV/bin/python" 2>&1 |
  grep -E "Install Cleared|Running:|\+ requests|✓ Installed" | sed 's/^/  /'
"$TARGET_VENV/bin/python" -c \
  "from importlib.metadata import version; print(f'  ok: requests {version(\"requests\")} landed in the target venv')"

echo
if [[ $KEEP -eq 1 ]]; then
  echo "Sandbox kept at $SANDBOX"
  echo "  cd $SANDBOX && ./.venv/bin/packsafe --help"
else
  echo "All checks passed. Sandbox: $SANDBOX (target venv removed)"
fi