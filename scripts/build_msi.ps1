# Build MSI via WiX when candle/light are available (M15.3).
param(
    [string]$OutDir = "artifacts/release",
    [string]$WixDir = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$candle = Get-Command candle -ErrorAction SilentlyContinue
$light = Get-Command light -ErrorAction SilentlyContinue
if (-not $candle -or -not $light) {
    Write-Host "WiX candle/light not found — MSI blocked (template remains under packaging/wix)."
    Write-Host "Install WiX Toolset and re-run this script."
    exit 2
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$wxs = Join-Path $Root "packaging\wix\Product.wxs"
$obj = Join-Path $OutDir "Product.wixobj"
$msi = Join-Path $OutDir "headless-re-mcp.msi"
# Product.wxs references $(var.ProjectDir) for README/LICENSE/notices.
& $candle.Source $wxs "-dProjectDir=$Root" -out $obj
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $light.Source $obj -out $msi
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "MSI written: $msi"
