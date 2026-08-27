.class public Lcom/example/re/Sample;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public callee()V
    .registers 1
    return-void
.end method

.method public caller()V
    .registers 1
    invoke-virtual {p0}, Lcom/example/re/Sample;->callee()V
    return-void
.end method

.method public alsoCallsCallee()V
    .registers 1
    invoke-virtual {p0}, Lcom/example/re/Sample;->callee()V
    return-void
.end method

.method public lonely()V
    .registers 1
    return-void
.end method
