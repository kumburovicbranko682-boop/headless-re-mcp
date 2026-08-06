# Source handoff ZIP excluding dumps/samples/unknown tools (M15.4).
param(
    [string]$OutDir = "artifacts/release",
    [string]$Name = "headless-re-mcp-handoff"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$stage = Join-Path $OutDir "_handoff_stage"
$dest = Join-Path $stage $Name
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path $dest | Out-Null

$include = @(
    "src",
    "tests",
    "scripts",
    "packaging",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "upstream.lock.json",
    ".github"
)
foreach ($item in $include) {
    $src = Join-Path $Root $item
    if (Test-Path $src) {
        if ((Get-Item $src).PSIsContainer) {
            Copy-Item -Recurse $src (Join-Path $dest $item)
        } else {
            Copy-Item $src $dest
        }
    }
}

$zip = Join-Path $OutDir "$Name.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path $dest -DestinationPath $zip
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $Name.zip" | Out-File -Encoding ascii (Join-Path $OutDir "$Name.sha256")
Write-Host "Wrote $zip"
Write-Host "SHA256 $hash"
