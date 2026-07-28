# Verify + extract official DIE 3.21 portable into artifacts/tools.
# Usage:
#   powershell -File scripts\install_die_portable.ps1
#   powershell -File scripts\install_die_portable.ps1 -ZipPath D:\downloads\die_win64_portable_3.21_x64.zip

param(
    [string]$ZipPath = "E:\x64dbgmcp\artifacts\tools\die_win64_portable_3.21_x64.zip",
    [string]$DestDir = "E:\x64dbgmcp\artifacts\tools\die_win64_portable_3.21_x64",
    [string]$ExpectedSha256 = "078f2934f267392247f9c7b759a1c2457a48bc2000b25b80c2f129955ee4a3b9"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $ZipPath)) {
    Write-Error "ZIP missing: $ZipPath"
}
$size = (Get-Item -LiteralPath $ZipPath).Length
if ($size -lt 20MB) {
    Write-Error "ZIP looks incomplete ($size bytes). Re-download the full ~24MB asset."
}
$hash = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne $ExpectedSha256.ToLowerInvariant()) {
    Write-Error "SHA256 mismatch: got $hash expected $ExpectedSha256"
}
if (Test-Path -LiteralPath $DestDir) {
    Remove-Item -LiteralPath $DestDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
Expand-Archive -LiteralPath $ZipPath -DestinationPath $DestDir -Force
$diec = Get-ChildItem -LiteralPath $DestDir -Recurse -Filter "diec.exe" | Select-Object -First 1
if ($null -eq $diec) {
    Write-Error "diec.exe not found after extract under $DestDir"
}
Write-Host "OK diec=$($diec.FullName)"
Write-Host "Set: `$env:HEADLESS_RE_DIEC='$($diec.FullName)'"
& $diec.FullName -v
