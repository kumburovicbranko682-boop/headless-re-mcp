# Android fixtures

## `static_sample.apk`

A minimal, real, signed APK used by `tests/integration/test_android_static_re_gate.py`.

That gate builds its Android targets at test time (jadx from a JDK-built JAR;
apktool from a hand-written manifest + smali via aapt2). Its **androguard** test
does the same when the `apktool` + `aapt2` build chain is present, but falls back
to this committed APK otherwise — androguard is a pip `[android]` install while
aapt2/apktool usually are not, so the fixture is what keeps the androguard static
facts verifiable without the heavier build chain. It is committed as a binary
fixture like `fixtures/upx/*.exe` and `fixtures/dotnet/minimal_clr_hint.exe`.

The fixture is built to carry the exact constants the gate asserts, so every
assertion holds whether the APK was built at test time or read from here:

- package `com.example.headless`
- declared permission `android.permission.INTERNET`
- launcher activity `com.example.MainActivity`
- one class `com.example.MainActivity` (smali `Lcom/example/MainActivity;`) with
  methods `compute(int, int)` (returns `a * b + 7`) and `run()` (calls
  `compute(2, 3)`), giving a recoverable `run` -> `compute` xref
- an apksigner v1+v2 signature

### How it was built (one-time, with the Android SDK)

```
# MainActivity.java: package com.example; a plain class (no android.* imports, so
# javac needs no android.jar) with compute(a,b)=a*b+7 and run()->compute(2,3).
javac --release 8 -d cls MainActivity.java
d8 --release --min-api 21 --output dex cls/com/example/*.class

# aapt v1 packages the manifest into an APK (binary AXML + resources.arsc); the
# manifest uses only string literals, so no compiled resources are required.
aapt package -f -M AndroidManifest.xml -I <sdk>/platforms/android-34/android.jar -F app-base.apk
aapt add app-base.apk classes.dex

zipalign -f -p 4 app-base.apk app-aligned.apk
keytool -genkeypair -keystore ks.jks -storepass android -keypass android -alias gate \
  -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Headless Gate, O=HeadlessRE, C=US"
apksigner sign --ks ks.jks --ks-pass pass:android --key-pass pass:android \
  --v1-signing-enabled true --v2-signing-enabled true --out static_sample.apk app-aligned.apk
```

The `AndroidManifest.xml` declares `package="com.example.headless"`, the
`uses-permission`, and the `com.example.MainActivity` activity with a
`MAIN`/`LAUNCHER` intent-filter. Regenerating it is only necessary if the constants
in the gate change.
