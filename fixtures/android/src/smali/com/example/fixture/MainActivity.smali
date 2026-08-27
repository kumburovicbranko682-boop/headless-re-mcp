# Source for the committed fixtures/android/fixture.apk (a real, harmless APK).
#
# fixture.apk carries a valid binary AXML AndroidManifest.xml plus a real
# classes.dex, so the APK gates can drive the *whole* androguard/jadx/apktool
# surface on genuine inputs -- both the manifest side (package / permissions /
# components, which the synthetic Android RE gate can only assert "degrades
# without crashing" because its manifest is not valid AXML) and the DEX side
# (classes / methods / strings / xrefs, jadx decompile). This is the blind spot
# where a version drift (the frida-17 class of break) hides: it only fails at
# runtime against a real APK, never in a fake-based unit test.
#
# The one class carries a call edge (main -> decryptSecret) and a recoverable
# string constant so every tool has something real to return:
#   manifest    -> package com.example.fixture, INTERNET, activity MainActivity
#   main_activity -> MainActivity carries a MAIN/LAUNCHER intent-filter, so
#                    get_main_activity() resolves it (a distinct parse from the
#                    activity enumeration, and null without a launcher)
#   classes     -> Lcom/example/fixture/MainActivity; (external types filtered)
#   methods     -> <init>, decryptSecret, main
#   strings     -> includes "s3cr3t-flag-value"
#   xrefs       -> decryptSecret's caller is MainActivity->main
#   jadx        -> decompiles to sources/com/example/fixture/MainActivity.java
#
# fixtures/android/fixture-signed.apk is this same APK v1-signed with a throwaway
# self-signed key (see test_apk_certificates_gate.py for the exact recipe), so the
# certificate path can be gated against a real signature.
#
# Rebuild fixture.apk from this src/ tree with apktool 2.10.0 (bundles aapt2):
#   java -jar apktool.jar b fixtures/android/src -o fixtures/android/fixture.apk

.class public Lcom/example/fixture/MainActivity;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static decryptSecret()Ljava/lang/String;
    .registers 1
    const-string v0, "s3cr3t-flag-value"
    return-object v0
.end method

.method public static main([Ljava/lang/String;)V
    .registers 2
    invoke-static {}, Lcom/example/fixture/MainActivity;->decryptSecret()Ljava/lang/String;
    move-result-object v0
    return-void
.end method
