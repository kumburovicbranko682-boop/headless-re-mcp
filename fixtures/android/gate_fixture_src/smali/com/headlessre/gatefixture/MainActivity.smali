.class public Lcom/headlessre/gatefixture/MainActivity;
.super Landroid/app/Activity;
.source "MainActivity.java"


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    return-void
.end method


# virtual methods
.method public getMarker()Ljava/lang/String;
    .locals 1

    const-string v0, "headless-re apk gate fixture"

    return-object v0
.end method

.method public onResume()V
    .locals 1

    invoke-super {p0}, Landroid/app/Activity;->onResume()V

    invoke-virtual {p0}, Lcom/headlessre/gatefixture/MainActivity;->getMarker()Ljava/lang/String;

    move-result-object v0

    return-void
.end method
