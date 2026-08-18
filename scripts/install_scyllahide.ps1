# Install official ScyllaHide into the LIVE headless plugins directories.
# Discovers headless from HEADLESS_RE_X64DBG_HEADLESS_{X86,X64} or Settings.load().
# Optionally mirrors into external/x64dbg-*/plugins. Does not claim TitanHide.
#
# Usage:
#   powershell -File scripts\install_scyllahide.ps1
#   powershell -File scripts\install_scyllahide.ps1 -ZipPath D:\downloads\ScyllaHide_2023-03-24_13-03.zip
#   powershell -File scripts\install_scyllahide.ps1 -SkipGate

param(
    [string]$ZipPath = "",
    [string]$ExtractDir = "",
    [string]$ExpectedSha256 = "EDEB0DD203FD1EF38E1404E8A1BD001E05C50B6096E49533F546D13FFDCB7404",
    [switch]$SkipDownload,
    [switch]$SkipGate,
    [switch]$SkipExternalMirror
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

if (-not $ZipPath) {
    $ZipPath = Join-Path $RepoRoot "artifacts\tools\ScyllaHide_2023-03-24_13-03.zip"
}
if (-not $ExtractDir) {
    $ExtractDir = Join-Path $RepoRoot "artifacts\tools\ScyllaHide_v1.4"
}

$releaseUrl = "https://github.com/x64dbg/ScyllaHide/releases/download/v1.4/ScyllaHide_2023-03-24_13-03.zip"
if (-not (Test-Path -LiteralPath $ZipPath)) {
    if ($SkipDownload) {
        Write-Error "ZIP missing: $ZipPath"
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $ZipPath) | Out-Null
    Write-Host "Downloading $releaseUrl"
    Invoke-WebRequest -Uri $releaseUrl -OutFile $ZipPath -UseBasicParsing
}

$hash = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne $ExpectedSha256.ToLowerInvariant()) {
    Write-Error "SHA256 mismatch: got $hash expected $ExpectedSha256"
}

if (Test-Path -LiteralPath $ExtractDir) {
    Remove-Item -LiteralPath $ExtractDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null
Expand-Archive -LiteralPath $ZipPath -DestinationPath $ExtractDir -Force

$srcX86 = Join-Path $ExtractDir "x64dbg\x32\plugins"
$srcX64 = Join-Path $ExtractDir "x64dbg\x64\plugins"
foreach ($src in @($srcX86, $srcX64)) {
    if (-not (Test-Path -LiteralPath $src)) {
        Write-Error "extracted tree missing $src"
    }
}

$x86Headless = $env:HEADLESS_RE_X64DBG_HEADLESS_X86
$x64Headless = $env:HEADLESS_RE_X64DBG_HEADLESS_X64
if (-not $x86Headless -or -not $x64Headless) {
    $py = Join-Path $RepoRoot "artifacts\tools\_discover_headless.py"
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($py, "from headless_re_mcp.config import Settings`ns=Settings.load()`nprint(s.x64dbg_headless_x86 or '')`nprint(s.x64dbg_headless_x64 or '')`n", $utf8)
    $discovered = python $py
    Remove-Item $py -ErrorAction SilentlyContinue
    $lines = @($discovered -split "`r?`n")
    if (-not $x86Headless) { $x86Headless = $lines[0] }
    if (-not $x64Headless) { $x64Headless = $lines[1] }
}

function Install-Into([string]$Headless, [string]$Src) {
    if (-not $Headless) { return $null }
    if (-not (Test-Path -LiteralPath $Headless)) {
        Write-Warning "headless missing: $Headless"
        return $null
    }
    $plugins = Join-Path (Split-Path -Parent $Headless) "plugins"
    New-Item -ItemType Directory -Force -Path $plugins | Out-Null
    Copy-Item -Force (Join-Path $Src "*") $plugins
    Write-Host "installed -> $plugins"
    return $plugins
}

$liveX86 = Install-Into $x86Headless $srcX86
$liveX64 = Install-Into $x64Headless $srcX64

if (-not $SkipExternalMirror) {
    $extX86 = Join-Path $RepoRoot "external\x64dbg-x86\plugins"
    $extX64 = Join-Path $RepoRoot "external\x64dbg-x64\plugins"
    New-Item -ItemType Directory -Force -Path $extX86, $extX64 | Out-Null
    Copy-Item -Force (Join-Path $srcX86 "*") $extX86
    Copy-Item -Force (Join-Path $srcX64 "*") $extX64
    Write-Host "mirrored -> $extX86"
    Write-Host "mirrored -> $extX64"
}

if (-not $SkipGate) {
    if ($x64Headless -and (Test-Path -LiteralPath $x64Headless)) {
        Write-Host "running x64 command-loop gate..."
        python -m headless_re_mcp gate-xdbg --architecture x64
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    if ($x86Headless -and (Test-Path -LiteralPath $x86Headless)) {
        Write-Host "running x86 command-loop gate..."
        python -m headless_re_mcp gate-xdbg --architecture x86
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
}

Write-Host "OK ScyllaHide v1.4 plugins installed next to live headless.exe"
if ($liveX86) { Write-Host "x86 $liveX86" }
if ($liveX64) { Write-Host "x64 $liveX64" }
