#!/usr/bin/env bash
# Install the optional *portable* reverse-engineering backends on Linux x86_64:
#   radare2   cross-platform disassembler (r2 track)
#   wabt      wasm2wat / wasm-objdump      (Web WASM track)
#   webcrack  JavaScript deobfuscation     (Web JS track)
#   apktool   APK decode/rebuild           (Android repackaging track)
#   apksigner APK signing                  (Android repackaging track)
#   jadx      DEX -> Java decompiler        (Android decompilation track)
# These are the non-PE backends the Web, radare2 and Android tracks depend on;
# without them the matching integration gates skip, and skip != pass. Each tool
# is discovered on PATH by the backend, so this only needs to put them there.
#
# Idempotent: anything already on PATH is left alone. Best-effort per tool: a
# single failure prints a hint and moves on rather than aborting the rest, so a
# machine that can install some of them still gets those.
set -uo pipefail

JADX_VERSION="${JADX_VERSION:-1.5.0}"

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

echo "Installing non-PE RE backends…"
install_radare2 || failures=$((failures + 1))
install_wabt || failures=$((failures + 1))
install_webcrack || failures=$((failures + 1))
install_apktool || failures=$((failures + 1))
install_jadx || failures=$((failures + 1))

if [[ "${failures}" -gt 0 ]]; then
  echo "Done with ${failures} backend(s) not installed; the rest are ready." >&2
  exit 1
fi
echo "All non-PE backends installed."
