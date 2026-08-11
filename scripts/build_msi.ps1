# Build a per-user MSI containing the Python package and production browser SPA.
param(
    [string]$OutDir = "artifacts/release",
    [string]$WixDir = ""
)

$ErrorActionPreference = "Stop"
$Root = (Split-Path -Parent $PSScriptRoot)
Set-Location $Root
if (-not $WixDir) {
    $known = "C:\Program Files (x86)\WiX Toolset v3.14\bin"
    if (Test-Path -LiteralPath $known) { $WixDir = $known }
}
function Resolve-WixTool([string]$name) {
    if ($WixDir) {
        $candidate = Join-Path $WixDir "$name.exe"
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $command = Get-Command $name -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    return $null
}
$candle = Resolve-WixTool "candle"
$light = Resolve-WixTool "light"
$heat = Resolve-WixTool "heat"
if (-not $candle -or -not $light -or -not $heat) {
    Write-Host "WiX candle/light/heat not found - MSI build blocked."
    exit 2
}

# The MSI version lives in Product.wxs and the package version in pyproject.toml.
# Nothing links them, so a release could otherwise ship an installer that
# advertises a stale version and defeats MajorUpgrade.
$wxsPath = Join-Path $Root "packaging\wix\Product.wxs"
$projectVersion = ([regex]::Match((Get-Content -LiteralPath (Join-Path $Root "pyproject.toml") -Raw), '(?m)^version\s*=\s*"([^"]+)"')).Groups[1].Value
$msiVersion = ([regex]::Match((Get-Content -LiteralPath $wxsPath -Raw), 'Product[^>]*?Version="([^"]+)"')).Groups[1].Value
if (-not $projectVersion -or -not $msiVersion) { throw "could not read version from pyproject.toml or Product.wxs" }
if ($projectVersion -ne $msiVersion) {
    throw "version mismatch: pyproject.toml is $projectVersion but packaging/wix/Product.wxs is $msiVersion"
}
Write-Host "version $projectVersion"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stageRoot = Join-Path $OutDir "_msi_stage"
$stage = Join-Path $stageRoot "HeadlessReMcp"
$resolvedOut = [IO.Path]::GetFullPath((Join-Path $Root $OutDir))
$resolvedStage = [IO.Path]::GetFullPath((Join-Path $Root $stageRoot))
if (-not $resolvedStage.StartsWith($resolvedOut, [StringComparison]::OrdinalIgnoreCase)) {
    throw "unsafe MSI stage path: $resolvedStage"
}
if (Test-Path -LiteralPath $resolvedStage) { Remove-Item -LiteralPath $resolvedStage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Copy-Item -Recurse "src\headless_re_mcp" (Join-Path $stage "src\headless_re_mcp")
Copy-Item "pyproject.toml","README.md","LICENSE","upstream.lock.json","start_web.py","first_setup.py" $stage
$launcher = @(
  '@echo off', 'setlocal', 'cd /d "%~dp0"', 'set PYTHONPATH=%~dp0src',
  'python start_web.py', 'if errorlevel 1 pause'
) -join "`r`n"
Set-Content -LiteralPath (Join-Path $stage "start_web.cmd") -Value $launcher -Encoding ASCII
Get-ChildItem -LiteralPath $stage -Directory -Recurse -Force |
    Where-Object { $_.Name -in @("__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache") } |
    Sort-Object FullName -Descending |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }
Get-ChildItem -LiteralPath $stage -File -Recurse -Force |
    Where-Object { $_.Extension -in @(".pyc", ".pyo") } |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
if (-not (Test-Path -LiteralPath (Join-Path $stage "src\headless_re_mcp\web\spa\index.html"))) {
    throw "production SPA missing; run: cd webui; npm ci; npm run build"
}
$forbidden = Get-ChildItem -LiteralPath $stage -Recurse -Force | Where-Object {
    $_.Name -in @("node_modules", "agent.db", "providers.json", "config.json") -or
    $_.Extension -in @(".dmp", ".idb", ".i64")
}
if ($forbidden) { throw "forbidden MSI payload: $($forbidden.FullName -join ', ')" }

$harvest = Join-Path $OutDir "ProductFiles.wxs"
$perUserTransform = Join-Path $Root "packaging\wix\PerUserKeyPath.xslt"
& $heat dir $stage -cg ProductFiles -dr INSTALLFOLDER -srd -sreg -gg -var var.StageDir -t $perUserTransform -out $harvest
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$productObj = Join-Path $OutDir "Product.wixobj"
$filesObj = Join-Path $OutDir "ProductFiles.wixobj"
& $candle $wxsPath $harvest "-dStageDir=$stage" -ext WixUtilExtension -out (Join-Path $OutDir "")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$msi = Join-Path $OutDir "headless-re-mcp.msi"
# Harvested per-user subdirectories can remain as empty folders after uninstall;
# suppress only that cleanup ICE and the per-user informational ICE. Component
# key paths still use HKCU registry values and all other validation remains on.
& $light $productObj $filesObj -ext WixUtilExtension -sice:ICE64 -sice:ICE91 -out $msi
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$hash = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  headless-re-mcp.msi" | Set-Content -LiteralPath (Join-Path $OutDir "headless-re-mcp.msi.sha256") -Encoding ascii
Write-Host "MSI written: $msi"
Write-Host "SHA256 $hash"
