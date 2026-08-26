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

"${python_bin}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {
  echo "Python 3.11 or newer is required" >&2
  exit 2
}

"${python_bin}" -m pip install -e "${repo_root}[${extras}]"
"${python_bin}" -m headless_re_mcp doctor
