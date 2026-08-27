# Tiny, harmless DEX source for the APK DEX-analysis gate.
#
# It exists so a *real* classes.dex exercises apk.classes / apk.methods /
# apk.strings / apk.xrefs against androguard. The android RE gate's synthetic
# APK carries only a placeholder classes.dex that androguard cannot parse, so
# nothing else in the suite ever drives DEX analysis on a valid DEX -- exactly
# the blind spot that would hide an androguard API drift (the frida-17 class of
# break, where a removed method fails only at runtime).
#
# It defines one internal class (LHello;) with three methods and one call edge
# (main -> decryptSecret) plus a recoverable string constant, so every tool has
# something real to return:
#   classes -> LHello; (external Ljava/lang/Object; is filtered out)
#   methods -> <init>, decryptSecret, main
#   strings -> includes "s3cr3t-flag-value"
#   xrefs decryptSecret -> caller LHello;->main
#
# Rebuild the committed classes.dex from this source with smali 2.5.2:
#   java -jar smali.jar assemble fixtures/android/Hello.smali -o fixtures/android/classes.dex

.class public LHello;
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
    invoke-static {}, LHello;->decryptSecret()Ljava/lang/String;
    move-result-object v0
    return-void
.end method
