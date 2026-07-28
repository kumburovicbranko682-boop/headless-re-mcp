#Requires -Version 5.1
<#
.SYNOPSIS
  Pack harmless PE fixtures with the official UPX CLI (x86 + x64).

.DESCRIPTION
  Reads the official UPX executable from HEADLESS_RE_UPX.
  If the tool is missing, exits 0 with a skip message (CI-friendly).
  Does not mutate the original inputs; packs copies under fixtures/upx/.

  This script is a fixture helper only. Runtime unpack goes through
  headless_re_mcp.unpack.upx (upx -t / upx -d -o), not this script.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"

$upx = $env:HEADLESS_RE_UPX
if ([string]::IsNullOrWhiteSpace($upx) -or -not (Test-Path -LiteralPath $upx)) {
    Write-Host "skip: HEADLESS_RE_UPX is unset or not a file; not packing fixtures."
    exit 0
}

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot "fixtures\upx"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$inputs = @(
    @{ Arch = "x86"; Path = (Join-Path $repoRoot "artifacts\fixtures-x86\console_fixture.exe") },
    @{ Arch = "x64"; Path = (Join-Path $repoRoot "artifacts\fixtures-x64\console_fixture.exe") }
)

$packedAny = $false
foreach ($item in $inputs) {
    $InputPe = $item.Path
    if (-not (Test-Path -LiteralPath $InputPe)) {
        Write-Host "skip missing input: $InputPe"
        continue
    }
    $arch = $item.Arch
    $workCopy = Join-Path $OutputDir ("console_fixture-{0}.pre-upx.exe" -f $arch)
    $packed = Join-Path $OutputDir ("console_fixture-{0}.upx.exe" -f $arch)
    Copy-Item -LiteralPath $InputPe -Destination $workCopy -Force
    if (Test-Path -LiteralPath $packed) {
        Remove-Item -LiteralPath $packed -Force
    }
    Write-Host "Packing $arch with official UPX: $upx"
    & $upx -q -o $packed $workCopy
    if ($LASTEXITCODE -ne 0) {
        Write-Error "upx pack failed for $arch with exit $LASTEXITCODE"
        exit $LASTEXITCODE
    }
    Write-Host "Wrote packed fixture: $packed"
    $packedAny = $true
}

if (-not $packedAny) {
    Write-Host "skip: no input PE available to pack."
    exit 0
}
exit 0
