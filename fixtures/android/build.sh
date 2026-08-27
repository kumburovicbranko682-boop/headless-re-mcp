#!/usr/bin/env bash
# Build the committed Android static-analysis fixture: sample.apk.
#
# The APK is checked in so the androguard gate needs only androguard at test
# time, never an SDK. Rebuild it with this script when the sources or manifest
# change. Requires, on PATH: javac (JDK 8+), d8, aapt, zipalign, apksigner,
# keytool. On Debian/Ubuntu:
#   sudo apt-get install android-sdk-build-tools android-sdk-platform-23 \
#       aapt apksigner default-jdk
#   sudo apt-get install google-android-build-tools-34.0.0-installer   # d8
#
# The result is deterministic in content but freshly signed each run (the debug
# key and signing time differ), so a rebuild always shows a diff on sample.apk.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
android_jar="${ANDROID_JAR:-/usr/lib/android-sdk/platforms/android-23/android.jar}"
out_apk="${here}/sample.apk"

for tool in javac d8 aapt zipalign apksigner keytool; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "missing tool: ${tool}" >&2; exit 2; }
done
[[ -f "${android_jar}" ]] || { echo "missing android.jar: ${android_jar}" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

echo "[1/6] javac -> .class"
mkdir -p "${work}/classes"
javac --release 8 -d "${work}/classes" \
  "${here}"/src/com/headlessre/sample/*.java

echo "[2/6] d8 -> classes.dex"
d8 --min-api 21 --output "${work}" \
  "${work}"/classes/com/headlessre/sample/*.class

echo "[3/6] aapt package -> binary manifest"
aapt package -f -M "${here}/AndroidManifest.xml" -I "${android_jar}" \
  -F "${work}/base.apk"

echo "[4/6] add classes.dex + a native lib per ABI"
# A tiny bogus ELF header per ABI so native_libs/abis have real entries; the
# gate only reads the zip paths, never loads them.
mkdir -p "${work}/lib/arm64-v8a" "${work}/lib/x86_64"
printf '\x7fELF placeholder' > "${work}/lib/arm64-v8a/libsample.so"
printf '\x7fELF placeholder' > "${work}/lib/x86_64/libsample.so"
( cd "${work}" && aapt add -f base.apk classes.dex \
    lib/arm64-v8a/libsample.so lib/x86_64/libsample.so >/dev/null )

echo "[5/6] zipalign"
zipalign -f 4 "${work}/base.apk" "${work}/aligned.apk"

echo "[6/6] sign (generated debug key; v1+v2)"
keytool -genkeypair -keystore "${work}/debug.keystore" -storepass android \
  -keypass android -alias headlessdebug -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=Headless RE Debug, O=headless-re-mcp, C=US" >/dev/null 2>&1
apksigner sign --ks "${work}/debug.keystore" --ks-pass pass:android \
  --key-pass pass:android --v1-signing-enabled true --v2-signing-enabled true \
  --out "${out_apk}" "${work}/aligned.apk"

echo "wrote ${out_apk} ($(stat -c%s "${out_apk}") bytes)"
