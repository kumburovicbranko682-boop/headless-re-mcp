#!/usr/bin/env bash
# Rebuild sample.apk -- the real-DEX, v1-signed APK the androguard static gate
# (tests/integration/test_apk_static_gate.py) parses.
#
# Provenance / why this exists
# ----------------------------
# The committed sample.apk is the canonical artifact: androguard is a pip
# dependency, so the gate needs no Android SDK at test time -- but building the
# fixture does. This script documents exactly how sample.apk was produced so it
# can be regenerated. Byte-for-byte reproduction is NOT expected: apksigner mints
# a fresh debug key and embeds timestamps, so a rebuild differs in the signature
# block and certificate. What matters, and what the gate asserts, is stable:
#   - classes com.example.gate.MainActivity and com.example.gate.Helper,
#   - the string constant "H3adl3ss_marker",
#   - MainActivity.greet calling the external StringBuilder.append (the xrefs
#     gate resolves that caller -- the regression guard for xrefs skipping
#     external methods),
#   - a v1 signature whose subject reads "...Android Debug..." as a human DN.
#
# Requirements: JDK (javac/keytool), Android build-tools (d8, aapt2, zipalign,
# apksigner), and an android.jar. Point the vars below at your install, then run.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${ANDROID_JAR:?set ANDROID_JAR to an android.jar (e.g. platform 30)}"
: "${BUILD_TOOLS:?set BUILD_TOOLS to an Android build-tools dir (has d8, aapt2, ...)}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

javac -source 8 -target 8 -cp "$ANDROID_JAR" -d "$work/classes" \
  "$here"/src/com/example/gate/*.java
"$BUILD_TOOLS/d8" "$work"/classes/com/example/gate/*.class \
  --lib "$ANDROID_JAR" --output "$work"

mkdir -p "$work/compiled"
"$BUILD_TOOLS/aapt2" compile "$here/res/values/strings.xml" -o "$work/compiled/"
"$BUILD_TOOLS/aapt2" link -o "$work/base.apk" -I "$ANDROID_JAR" \
  --manifest "$here/AndroidManifest.xml" "$work"/compiled/values_strings.arsc.flat

python3 - "$work" <<'PY'
import sys, zipfile, shutil
work = sys.argv[1]
shutil.copy(f"{work}/base.apk", f"{work}/withdex.apk")
with zipfile.ZipFile(f"{work}/withdex.apk", "a", zipfile.ZIP_DEFLATED) as z:
    z.write(f"{work}/classes.dex", "classes.dex")
PY

ks="$work/debug.keystore"
keytool -genkeypair -keystore "$ks" -storepass android -keypass android \
  -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=Android Debug,O=Android,C=US"
"$BUILD_TOOLS/zipalign" -f 4 "$work/withdex.apk" "$work/aligned.apk"
"$BUILD_TOOLS/apksigner" sign --ks "$ks" --ks-pass pass:android \
  --ks-key-alias androiddebugkey --key-pass pass:android --min-sdk-version 21 \
  --out "$here/sample.apk" "$work/aligned.apk"

echo "wrote $here/sample.apk"
