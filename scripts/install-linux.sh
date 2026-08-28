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
# install the equivalents by hand. jadx and webcrack are not apt packages --
# jadx is a GitHub release, webcrack an npm global -- so each is fetched on its
# own below, best-effort and at the same version Linux CI proves the gates on.
if [[ "${HEADLESS_RE_INSTALL_BACKENDS:-0}" == "1" ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    apt=(apt-get)
    if [[ "$(id -u)" != "0" ]]; then
      apt=(sudo apt-get)
    fi
    if ! { "${apt[@]}" update && "${apt[@]}" install -y radare2 upx-ucl wabt apktool apksigner adb; }; then
      echo "WARN: some FOSS backends failed to install; doctor will show which." >&2
    fi
  else
    echo "HEADLESS_RE_INSTALL_BACKENDS=1 needs apt-get; install radare2, wabt," >&2
    echo "UPX, apktool, apksigner and adb with your distribution's package manager." >&2
  fi
  # jadx (the Android decompiler) is not in apt, so fetch the pinned release
  # Linux CI proves the jadx.* tools against and point HEADLESS_RE_JADX at its
  # launcher (the highest-priority source config.py reads). Needs curl+unzip to
  # fetch and a JRE 21+ to run; a missing fetch tool or a failed download is a
  # note, not a failure, so an apt-provisioned box still finishes the install.
  if command -v curl >/dev/null 2>&1 && command -v unzip >/dev/null 2>&1; then
    jadx_version="1.5.0"
    jadx_root="${HEADLESS_RE_JADX_ROOT:-${HOME}/jadx}"
    jadx_bin="${jadx_root}/bin/jadx"
    jadx_zip="$(mktemp --suffix=.zip)"
    if [[ -x "${jadx_bin}" ]] || {
        curl -fsSL -o "${jadx_zip}" \
          "https://github.com/skylot/jadx/releases/download/v${jadx_version}/jadx-${jadx_version}.zip" \
          && unzip -oq "${jadx_zip}" -d "${jadx_root}"; }; then
      rm -f "${jadx_zip}"
      export HEADLESS_RE_JADX="${jadx_bin}"
      echo "jadx installed under ${jadx_root}."
      echo "Persist HEADLESS_RE_JADX=${jadx_bin} (or add ${jadx_root}/bin to PATH) for future sessions."
    else
      rm -f "${jadx_zip}"
      echo "WARN: jadx download failed; doctor will show jadx as missing." >&2
      echo "      Fetch jadx-${jadx_version}.zip from the upstream releases and set" >&2
      echo "      HEADLESS_RE_JADX to its bin/jadx." >&2
    fi
  else
    echo "jadx needs curl and unzip to fetch; install those, or fetch jadx from" >&2
    echo "https://github.com/skylot/jadx/releases and set HEADLESS_RE_JADX." >&2
  fi
  # webcrack drives the JS line (js.deobfuscate/unpack/beautify). It is an npm
  # global rather than an apt package -- the same one Linux CI installs -- so it
  # is provisioned here, outside the apt branch, whenever npm is on PATH. It
  # needs Node 22/24; a missing npm is a note, not a failure, like jadx above.
  if command -v npm >/dev/null 2>&1; then
    npm install -g webcrack || \
      echo "WARN: webcrack (npm) install failed; js.* stays unavailable." >&2
  else
    echo "webcrack (the JS backend) needs Node 22/24 and npm; once Node is on" >&2
    echo "PATH install it with 'npm install -g webcrack'." >&2
  fi
fi

# Opt-in Ghidra provisioning: the one portable backend apt cannot supply.
# Fetches the exact pinned release Linux CI proves the ghidra.* tools against,
# then installs PyGhidra from the wheels that release vendors (Ghidra >= 11.3
# dropped Jython, so headless export scripts only run through PyGhidra, and
# --no-index keeps the two matched). Its own switch rather than part of
# HEADLESS_RE_INSTALL_BACKENDS because it downloads ~400 MB from upstream.
# Best-effort like everything above: on failure doctor shows ghidra missing.
# Running analyzeHeadless additionally needs a JDK 21+ on PATH.
if [[ "${HEADLESS_RE_INSTALL_GHIDRA:-0}" == "1" ]]; then
  ghidra_version="12.1.3"
  ghidra_date="20260817"
  ghidra_root="${HEADLESS_RE_GHIDRA_ROOT:-${HOME}/ghidra}"
  ghidra_home="${ghidra_root}/ghidra_${ghidra_version}_PUBLIC"
  ghidra_zip="$(mktemp --suffix=.zip)"
  if [[ -d "${ghidra_home}" ]] || {
      curl -fsSL -o "${ghidra_zip}" \
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${ghidra_version}_build/ghidra_${ghidra_version}_PUBLIC_${ghidra_date}.zip" \
        && unzip -oq "${ghidra_zip}" -d "${ghidra_root}"; }; then
    rm -f "${ghidra_zip}"
    "${python_bin}" -m pip install --no-index \
      -f "${ghidra_home}/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra || {
      echo "WARN: PyGhidra install failed; ghidra.* stays unavailable until it succeeds:" >&2
      echo "      ${python_bin} -m pip install --no-index -f '${ghidra_home}/Ghidra/Features/PyGhidra/pypkg/dist' pyghidra" >&2
    }
    export HEADLESS_RE_GHIDRA_HOME="${ghidra_home}"
    echo "Ghidra installed under ${ghidra_home}."
    echo "Persist HEADLESS_RE_GHIDRA_HOME=${ghidra_home} for future sessions."
  else
    rm -f "${ghidra_zip}"
    echo "WARN: Ghidra download failed; doctor will show ghidra as missing." >&2
    echo "      Fetch ghidra_${ghidra_version}_PUBLIC_${ghidra_date}.zip from the upstream" >&2
    echo "      releases yourself and set HEADLESS_RE_GHIDRA_HOME to the unpacked root." >&2
  fi
fi

"${python_bin}" -m headless_re_mcp doctor
