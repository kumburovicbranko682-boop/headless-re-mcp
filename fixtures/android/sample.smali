.class public Lcom/example/gate/Sample;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public callee()Ljava/lang/String;
    .registers 2
    const-string v0, "APK_GATE_MARKER_STRING"
    return-object v0
.end method

.method public caller()Ljava/lang/String;
    .registers 2
    invoke-virtual {p0}, Lcom/example/gate/Sample;->callee()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
