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

# A Playwright package without its managed browser cannot drive web.* at all,
# and the missing-browser error only surfaces on first use. Fetch Chromium
# whenever the browser extra brought Playwright in. Best-effort: a failed
# download leaves an honest doctor signal instead of aborting the install.
if "${python_bin}" -c 'import importlib.util, sys; sys.exit(0 if importlib.util.find_spec("playwright") else 1)'; then
  "${python_bin}" -m playwright install chromium || {
    echo "WARN: Playwright browser download failed;" >&2
    echo "      run '${python_bin} -m playwright install chromium' manually." >&2
  }
fi

# Opt-in provisioning of the FOSS CLI backends the non-PE lines shell out to,
# mirroring what Linux CI installs. System packages need apt and (unless run
# as root) sudo, so this never happens implicitly; on other distributions
# install the equivalents by hand. jadx is not packaged for apt: fetch a
# release from https://github.com/skylot/jadx and put its bin/ on PATH.
if [[ "${HEADLESS_RE_INSTALL_BACKENDS:-0}" == "1" ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    apt=(apt-get)
    if [[ "$(id -u)" != "0" ]]; then
      apt=(sudo apt-get)
    fi
    if ! { "${apt[@]}" update && "${apt[@]}" install -y radare2 upx-ucl wabt apktool apksigner; }; then
      echo "WARN: some FOSS backends failed to install; doctor will show which." >&2
    fi
  else
    echo "HEADLESS_RE_INSTALL_BACKENDS=1 needs apt-get; install radare2, wabt," >&2
    echo "UPX, apktool and apksigner with your distribution's package manager." >&2
  fi
fi

"${python_bin}" -m headless_re_mcp doctor
