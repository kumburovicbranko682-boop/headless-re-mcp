#!/bin/sh
# Rebuild hello_world.apk from the committed sources. See README.md.
#
# Needs: a JDK, Apktool (APKTOOL_JAR), an aapt2 that matches your Apktool
# (AAPT2, e.g. extracted from the Apktool jar's prebuilt/linux/aapt2_64), and an
# android.jar for the android: namespace (ANDROID_JAR, API 30 is fine).
#
#   APKTOOL_JAR=apktool.jar AAPT2=./aapt2 ANDROID_JAR=android.jar ./build.sh
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

: "${APKTOOL_JAR:?set APKTOOL_JAR to the Apktool jar}"
: "${AAPT2:?set AAPT2 to an aapt2 binary matching Apktool}"
: "${ANDROID_JAR:?set ANDROID_JAR to an android.jar (API 30 works)}"

# 1. Assemble the smali into a real classes.dex via Apktool.
mkdir -p "$work/skel/smali/com/example/hello"
cp "$here/AndroidManifest.xml" "$work/skel/AndroidManifest.xml"
cp "$here/MainActivity.smali" "$work/skel/smali/com/example/hello/MainActivity.smali"
cat > "$work/skel/apktool.yml" <<'YML'
!!brut.androlib.meta.MetaInfo
apkFileName: hello.apk
compressionType: false
doNotCompress: []
isFrameworkApk: false
packageInfo:
  forcedPackageId: '127'
  renameManifestPackage: null
sdkInfo:
  minSdkVersion: '21'
  targetSdkVersion: '30'
sharedLibrary: false
sparseResources: false
unknownFiles: {}
usesFramework:
  ids: []
  tag: null
version: 2.9.3
versionInfo:
  versionCode: '1'
  versionName: '1.0'
YML
java -jar "$APKTOOL_JAR" b "$work/skel" -o "$work/apktool.apk" --use-aapt2 -a "$AAPT2"
unzip -oq "$work/apktool.apk" classes.dex -d "$work"

# 2. Compile the app resources so the packaged resources.arsc carries a real
#    resource package. An empty arsc (what a resource-less link emits) has zero
#    packages, which apktool < 2.9 refuses to decode ("arsc files with zero
#    packages"); a real package keeps the fixture decodable across apktool
#    versions.
"$AAPT2" compile --dir "$here/res" -o "$work/res.zip"

# 3. Compile the manifest to binary AXML (needs the framework) and package the
#    compiled resources into base.apk.
"$AAPT2" link \
  --manifest "$here/AndroidManifest.xml" \
  -I "$ANDROID_JAR" \
  -o "$work/base.apk" \
  --min-sdk-version 21 --target-sdk-version 30 \
  "$work/res.zip"
cp "$work/base.apk" "$here/hello_world.apk"
( cd "$work" && zip -q "$here/hello_world.apk" classes.dex )

echo "wrote $here/hello_world.apk"
