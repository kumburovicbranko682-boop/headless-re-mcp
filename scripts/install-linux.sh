#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "install-linux.sh supports Linux only" >&2
  exit 2
fi

case "$(uname -m)" in
  x86_64|amd64) ;;
  *)
    echo "Headless RE-MCP currently supports Linux x86_64 only" >&2
    exit 2
    ;;
esac

python_bin="${PYTHON:-python3}"
extras="${HEADLESS_RE_EXTRAS:-pe,web}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

# The backends step installs Chromium for the Web dynamic gate, which needs the
# Playwright Python package present first, so fold in the browser extra when the
# caller opts into backends (unless they already asked for it).
if [[ "${HEADLESS_RE_INSTALL_BACKENDS:-0}" == "1" ]]; then
  case ",${extras}," in
    *,browser,*) ;;
    *) extras="${extras},browser" ;;
  esac
fi

"${python_bin}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {
  echo "Python 3.11 or newer is required" >&2
  exit 2
}

"${python_bin}" -m pip install -e "${repo_root}[${extras}]"

# Optionally pull in the portable native backends (radare2, wabt, webcrack,
# apktool/apksigner/jadx, Chromium) so the Web, radare2 and Android integration
# gates run instead of skipping. Off by default because it uses the system
# package manager and npm; opt in with HEADLESS_RE_INSTALL_BACKENDS=1.
if [[ "${HEADLESS_RE_INSTALL_BACKENDS:-0}" == "1" ]]; then
  # Best-effort: a missing backend degrades a tool, it does not fail the install.
  # Pass the chosen interpreter through so the Chromium step uses the same venv.
  PYTHON="${python_bin}" "${script_dir}/install-linux-backends.sh" || \
    echo "Some portable backends were not installed; continuing." >&2
fi

"${python_bin}" -m headless_re_mcp doctor
