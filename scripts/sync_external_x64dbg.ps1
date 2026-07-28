# Sync built x64dbg Release trees into external/ (packagable runtime).
param(
    [string]$SourceRoot = "artifacts",
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

foreach ($arch in @("x86", "x64")) {
    $src = Join-Path $SourceRoot ("x64dbg-{0}\Release" -f $arch)
    $dst = Join-Path "external" ("x64dbg-{0}" -f $arch)
    if (-not (Test-Path $src)) {
        Write-Warning ("missing {0} — skip" -f $src)
        continue
    }
    if (-not (Test-Path (Join-Path $src "headless.exe"))) {
        Write-Warning ("no headless.exe under {0} — skip" -f $src)
        continue
    }
    Write-Host ("sync {0} -> {1}" -f $src, $dst)
    if ($WhatIf) { continue }
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    Get-ChildItem $dst -Force | Where-Object { $_.Name -notin @("README.md", ".gitkeep") } | Remove-Item -Recurse -Force
    Copy-Item -Recurse -Force (Join-Path $src "*") $dst
    if (-not (Test-Path (Join-Path $dst "headless.exe"))) {
        throw ("sync failed: headless.exe missing in {0}" -f $dst)
    }
}

Write-Host "done. Auto-discover reads external/x64dbg-*/headless.exe"
