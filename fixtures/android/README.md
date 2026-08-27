# Android fixture

A tiny, harmless, fully valid APK for exercising the Android static-analysis
line (`apk.*` androguard tools and `jadx`) against real bytes rather than a
synthetic archive. Committed the same way the `dotnet/` and `upx/` binary
fixtures are, so the gate is meaningful without an Android toolchain on the
test machine.

## Contents of `hello_world.apk` (1.4 KB)

- `AndroidManifest.xml` — **binary** AXML (this is what makes androguard parse
  it as a real app, not a plain-text manifest). Declares package
  `com.example.hello`, `versionName` `1.0`, one `INTERNET` permission and a
  single launcher activity `com.example.hello.MainActivity`.
- `resources.arsc` — empty resource table emitted by `aapt2 link`.
- `classes.dex` — one class `com.example.hello.MainActivity` with a
  constructor and a `secretMarker()` method that returns the literal string
  `headless-re-mcp-marker-7f3a`. The gate asserts that class, its methods and
  that marker string come back, so the DEX path (classes/methods/strings) and a
  `jadx` decompile are both exercised.

There is no signature: androguard parses an unsigned APK fine, and the gate
does not assert certificate facts on this fixture.

## Rebuilding

`AndroidManifest.xml` and `MainActivity.smali` are the sources. `build.sh`
rebuilds `hello_world.apk` from them; it needs a JDK, Apktool, and an
`android.jar` (API 30 is fine) for `aapt2` to resolve the `android:` namespace.
The checked-in APK is what the gate uses; rebuilding is only needed to change
the fixture.
