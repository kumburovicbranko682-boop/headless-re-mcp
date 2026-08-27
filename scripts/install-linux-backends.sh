#!/usr/bin/env bash
# Install the optional *portable* reverse-engineering backends on Linux x86_64:
#   radare2   cross-platform disassembler (r2 track)
#   mingw-w64 Windows PE cross-compiler    (r2 / UPX PE-portability gate fixtures)
#   upx       UPX packer/unpacker CLI      (portable UPX unpack gate)
#   wabt      wasm2wat / wasm-objdump      (Web WASM track)
#   webcrack  JavaScript deobfuscation     (Web JS track)
#   apktool   APK decode/rebuild           (Android repackaging track)
#   apksigner APK signing                  (Android repackaging track)
#   jadx      DEX -> Java decompiler        (Android decompilation track)
#   chromium  Playwright browser           (Web dynamic / CDP track)
# These are the non-PE backends the Web, radare2 and Android tracks depend on;
# without them the matching integration gates skip, and skip != pass. Each tool
# is discovered on PATH by the backend, so this only needs to put them there.
#
# Idempotent: anything already on PATH is left alone. Best-effort per tool: a
# single failure prints a hint and moves on rather than aborting the rest, so a
# machine that can install some of them still gets those.
set -uo pipefail

JADX_VERSION="${JADX_VERSION:-1.5.0}"
# Ghidra is opt-in (HEADLESS_RE_INSTALL_GHIDRA=1): it is a ~400MB download and,
# unlike the others, is found via HEADLESS_RE_GHIDRA_HOME rather than PATH. The
# pinned 11.1.2 still bundles a Jython provider, which the ExportJson.py
# GhidraScript needs; newer Ghidra drops Jython and would need the PyGhidra
# extension. Override GHIDRA_URL to install a different build.
GHIDRA_URL="${GHIDRA_URL:-https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "install-linux-backends.sh supports Linux only" >&2
  exit 2
fi

failures=0

# apt is the only package manager wired up here; radare2 and wabt both ship in
# the Debian/Ubuntu archives. A different distro should install them its own way
# and can still use the webcrack path below.
have_apt=0
if command -v apt-get >/dev/null 2>&1; then
  have_apt=1
fi

# apt and global npm need root; use sudo only when we are not already root and
# sudo is available, so this works both in a plain shell and in a container that
# already runs as root.
as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    return 127
  fi
}

apt_updated=0
apt_install() {
  local pkg="$1"
  if [[ "${have_apt}" -ne 1 ]]; then
    echo "  ! apt-get not found; install ${pkg} with your distro's package manager" >&2
    return 1
  fi
  if [[ "${apt_updated}" -eq 0 ]]; then
    as_root apt-get update -qq || true
    apt_updated=1
  fi
  as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkg}"
}

install_radare2() {
  if command -v r2 >/dev/null 2>&1 || command -v radare2 >/dev/null 2>&1; then
    echo "radare2: already present ($(command -v r2 || command -v radare2))"
    return 0
  fi
  echo "radare2: installing via apt…"
  if apt_install radare2; then
    echo "radare2: $(r2 -v 2>/dev/null | head -1)"
  else
    echo "  ! radare2 install failed; see https://github.com/radareorg/radare2" >&2
    return 1
  fi
}

install_wabt() {
  if command -v wasm2wat >/dev/null 2>&1; then
    echo "wabt: already present ($(command -v wasm2wat))"
    return 0
  fi
  echo "wabt: installing via apt…"
  if apt_install wabt; then
    echo "wabt: wasm2wat $(wasm2wat --version 2>/dev/null | head -1)"
  else
    echo "  ! wabt install failed; see https://github.com/WebAssembly/wabt" >&2
    return 1
  fi
}

install_webcrack() {
  if command -v webcrack >/dev/null 2>&1; then
    echo "webcrack: already present ($(command -v webcrack))"
    return 0
  fi
  if ! command -v npm >/dev/null 2>&1; then
    echo "  ! npm not found; webcrack needs Node.js 22 or 24" >&2
    return 1
  fi
  # webcrack requires a current Node; warn but still try, since the runtime check
  # belongs to webcrack itself and node versions vary by install method.
  local major
  major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  if [[ "${major}" -lt 22 ]]; then
    echo "  ! Node ${major}.x detected; webcrack needs Node 22 or 24" >&2
  fi
  echo "webcrack: installing via npm -g…"
  # Global installs land in npm's prefix, which is usually root-owned; fall back
  # to sudo while preserving PATH so the node/npm on PATH is the one used.
  if npm install -g webcrack >/dev/null 2>&1 \
    || as_root env "PATH=${PATH}" npm install -g webcrack >/dev/null 2>&1; then
    echo "webcrack: $(webcrack --version 2>/dev/null | head -1)"
  else
    echo "  ! webcrack install failed; try 'npm install -g webcrack' by hand" >&2
    return 1
  fi
}

install_apktool() {
  if command -v apktool >/dev/null 2>&1 && command -v apksigner >/dev/null 2>&1; then
    echo "apktool/apksigner: already present"
    return 0
  fi
  echo "apktool + apksigner: installing via apt…"
  # Both are JVM tools; apt pulls in a JRE if one is missing.
  if apt_install apktool && apt_install apksigner; then
    echo "apktool: $(apktool --version 2>/dev/null | head -1)"
  else
    echo "  ! apktool/apksigner install failed; see https://apktool.org" >&2
    return 1
  fi
}

install_jadx() {
  if command -v jadx >/dev/null 2>&1; then
    echo "jadx: already present ($(command -v jadx))"
    return 0
  fi
  # jadx is not in the Debian archive, so fetch the pinned release zip. It needs
  # a JRE at runtime; apt above usually already provides one.
  local url zip dest bindir
  url="https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
  zip="$(mktemp -d)/jadx.zip"
  echo "jadx: downloading v${JADX_VERSION}…"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "${zip}" "${url}" || { echo "  ! jadx download failed" >&2; return 1; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "${zip}" "${url}" || { echo "  ! jadx download failed" >&2; return 1; }
  else
    echo "  ! neither curl nor wget found; cannot fetch jadx" >&2
    return 1
  fi
  # Install under /opt when we can write there, else the user's data dir; wire a
  # tiny wrapper onto PATH so the launcher still resolves its own lib/ dir.
  if as_root test -w /opt 2>/dev/null || [[ "$(id -u)" -eq 0 ]]; then
    dest=/opt/jadx
    bindir=/usr/local/bin
    as_root rm -rf "${dest}" && as_root mkdir -p "${dest}"
    as_root unzip -q "${zip}" -d "${dest}" || { echo "  ! jadx unzip failed" >&2; return 1; }
    as_root chmod +x "${dest}/bin/jadx"
    printf '#!/bin/sh\nexec %s/bin/jadx "$@"\n' "${dest}" | as_root tee "${bindir}/jadx" >/dev/null
    as_root chmod +x "${bindir}/jadx"
  else
    dest="${HOME}/.local/share/jadx"
    bindir="${HOME}/.local/bin"
    rm -rf "${dest}" && mkdir -p "${dest}" "${bindir}"
    unzip -q "${zip}" -d "${dest}" || { echo "  ! jadx unzip failed" >&2; return 1; }
    chmod +x "${dest}/bin/jadx"
    printf '#!/bin/sh\nexec %s/bin/jadx "$@"\n' "${dest}" > "${bindir}/jadx"
    chmod +x "${bindir}/jadx"
    echo "  (installed to ${bindir}; ensure it is on PATH)"
  fi
  echo "jadx: $(jadx --version 2>/dev/null | head -1 || echo "installed to ${dest}")"
}

install_chromium() {
  # The Web dynamic gate drives Chromium over CDP through Playwright. Playwright
  # is the Python 'browser' extra, so this only runs when that package is
  # importable; otherwise it points the caller at the extra rather than failing.
  local py="${PYTHON:-python3}"
  if ! "${py}" -c 'import playwright' >/dev/null 2>&1; then
    echo "chromium: skipped (Playwright not importable via ${py}; install the browser extra: pip install '.[browser]')"
    return 0
  fi
  # install-deps apt-installs Chromium's shared libraries and needs root; the
  # browser download itself must run as the invoking user so the cache lands in
  # their home, not root's. 'playwright install' is idempotent.
  echo "chromium: installing OS deps + browser via Playwright…"
  as_root env "PATH=${PATH}" "${py}" -m playwright install-deps chromium \
    || echo "  ! playwright install-deps failed (needs root/apt); browser may still launch" >&2
  if "${py}" -m playwright install chromium >/dev/null 2>&1; then
    echo "chromium: installed (Playwright)"
  else
    echo "  ! playwright chromium download failed; see https://playwright.dev/python" >&2
    return 1
  fi
}

install_ghidra() {
  if [[ -n "${HEADLESS_RE_GHIDRA_HOME:-}" && -x "${HEADLESS_RE_GHIDRA_HOME}/support/analyzeHeadless" ]]; then
    echo "ghidra: already present (${HEADLESS_RE_GHIDRA_HOME})"
    return 0
  fi
  if [[ "${HEADLESS_RE_INSTALL_GHIDRA:-0}" != "1" ]]; then
    echo "ghidra: skipped (set HEADLESS_RE_INSTALL_GHIDRA=1 to fetch ~400MB)"
    return 0
  fi
  if ! command -v java >/dev/null 2>&1; then
    echo "ghidra: installing a JRE via apt first…"
    apt_install default-jre || { echo "  ! could not install a JRE for ghidra" >&2; return 1; }
  fi
  local zip dest
  zip="$(mktemp -d)/ghidra.zip"
  echo "ghidra: downloading… (${GHIDRA_URL##*/})"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "${zip}" "${GHIDRA_URL}" || { echo "  ! ghidra download failed" >&2; return 1; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "${zip}" "${GHIDRA_URL}" || { echo "  ! ghidra download failed" >&2; return 1; }
  else
    echo "  ! neither curl nor wget found; cannot fetch ghidra" >&2
    return 1
  fi
  if as_root test -w /opt 2>/dev/null || [[ "$(id -u)" -eq 0 ]]; then
    dest=/opt/ghidra
    as_root rm -rf "${dest}"
    local tmp; tmp="$(mktemp -d)"
    unzip -q "${zip}" -d "${tmp}" || { echo "  ! ghidra unzip failed" >&2; return 1; }
    as_root mv "$(ls -d "${tmp}"/ghidra_* | head -1)" "${dest}"
  else
    dest="${HOME}/.local/share/ghidra"
    rm -rf "${dest}"; mkdir -p "$(dirname "${dest}")"
    local tmp; tmp="$(mktemp -d)"
    unzip -q "${zip}" -d "${tmp}" || { echo "  ! ghidra unzip failed" >&2; return 1; }
    mv "$(ls -d "${tmp}"/ghidra_* | head -1)" "${dest}"
  fi
  if [[ -x "${dest}/support/analyzeHeadless" ]]; then
    echo "ghidra: installed to ${dest}"
    echo "  -> export HEADLESS_RE_GHIDRA_HOME=${dest}"
  else
    echo "  ! ghidra install did not yield support/analyzeHeadless" >&2
    return 1
  fi
}

install_mingw() {
  # The r2 portability gate builds a real Windows PE on Linux to prove the
  # backend reads PE end to end (image-base -> rva mapping, PE import table)
  # without any Windows tooling; the mingw cross-compiler is what mints that
  # fixture. Only the x86_64 target is needed.
  if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "mingw-w64: already present ($(command -v x86_64-w64-mingw32-gcc))"
    return 0
  fi
  echo "mingw-w64: installing via apt…"
  if apt_install gcc-mingw-w64-x86-64; then
    echo "mingw-w64: $(x86_64-w64-mingw32-gcc --version 2>/dev/null | head -1)"
  else
    echo "  ! mingw-w64 install failed; the r2 PE-portability gate will skip" >&2
    return 1
  fi
}

install_upx() {
  # The portable UPX gate packs a mingw-built PE and drives unpack.upx.* against
  # it; the official CLI ships as upx-ucl on Debian/Ubuntu (binary name: upx).
  if command -v upx >/dev/null 2>&1; then
    echo "upx: already present ($(command -v upx))"
    return 0
  fi
  echo "upx: installing via apt…"
  if apt_install upx-ucl; then
    echo "upx: $(upx --version 2>/dev/null | head -1)"
  else
    echo "  ! upx install failed; the UPX portability gate will skip" >&2
    return 1
  fi
}

echo "Installing non-PE RE backends…"
install_radare2 || failures=$((failures + 1))
install_mingw || failures=$((failures + 1))
install_upx || failures=$((failures + 1))
install_wabt || failures=$((failures + 1))
install_webcrack || failures=$((failures + 1))
install_apktool || failures=$((failures + 1))
install_jadx || failures=$((failures + 1))
install_chromium || failures=$((failures + 1))
install_ghidra || failures=$((failures + 1))

if [[ "${failures}" -gt 0 ]]; then
  echo "Done with ${failures} backend(s) not installed; the rest are ready." >&2
  exit 1
fi
echo "All non-PE backends installed."
