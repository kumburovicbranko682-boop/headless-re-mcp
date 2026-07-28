# Build sdist + wheel and optional SBOM (M15.1).
param(
    [string]$OutDir = "artifacts/release",
    [switch]$SkipSboms
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
python -m pip install -U build hatchling | Out-Null
python -m build --sdist --wheel --outdir $OutDir

if (-not $SkipSboms) {
    $sbom = Join-Path $OutDir "sbom-pip-freeze.txt"
    python -m pip freeze | Out-File -Encoding utf8 $sbom
    $hashes = Join-Path $OutDir "SHA256SUMS.txt"
    Get-ChildItem $OutDir -File | Where-Object { $_.Name -match '\.(whl|tar\.gz)$' } | ForEach-Object {
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    } | Out-File -Encoding ascii $hashes
}

Write-Host "Release artifacts in $OutDir"
Get-ChildItem $OutDir | Format-Table Name, Length
