# Build a per-user MSI containing the Python package, its runtime and the SPA.
param(
    [string]$OutDir = "artifacts/release",
    [string]$WixDir = "",
    # Pinned because the vendored wheels are built for one interpreter: pydantic
    # ships cp312-only binaries, so the runtime and the packages have to agree.
    [string]$PythonVersion = "3.12.10",
    [string]$CacheDir = "artifacts/tools"
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
Copy-Item "pyproject.toml","README.md","LICENSE","upstream.lock.json","start_web.py","setup.py" $stage
# The interpreter and every dependency travel with the app. Shipping source
# alone produced an installer that unpacked and then failed on the first import,
# because it silently relied on whatever Python the developer happened to have.
$runtime = Join-Path $stage "runtime\python"
$pythonTag = "python" + ($PythonVersion -replace '^(\d+)\.(\d+).*$', '$1$2')
$embedZip = Join-Path $CacheDir "python-$PythonVersion-embed-amd64.zip"
New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
if (-not (Test-Path -LiteralPath $embedZip)) {
    $url = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"
    Write-Host "downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $embedZip -UseBasicParsing
}
Expand-Archive -LiteralPath $embedZip -DestinationPath $runtime -Force
$sitePackages = Join-Path $runtime "Lib\site-packages"
New-Item -ItemType Directory -Force -Path $sitePackages | Out-Null

# The embedded distribution ignores the usual path rules and reads this file
# instead. Paths are relative to python.exe, so the app source sits three levels
# up. Without "import site" the vendored packages are invisible.
@(
    "$pythonTag.zip",
    ".",
    "Lib\site-packages",
    "..\..\src",
    "",
    "import site"
) -join "`r`n" | Set-Content -LiteralPath (Join-Path $runtime "$pythonTag._pth") -Encoding ASCII

$minor = ($PythonVersion -split '\.')[0..1] -join '.'
Write-Host "vendoring dependencies for python $minor"
& python -m pip install `
    --target $sitePackages `
    --only-binary=:all: `
    --python-version $minor `
    --implementation cp `
    --platform win_amd64 `
    --no-compile `
    --quiet `
    ".[web,pe]"
if ($LASTEXITCODE -ne 0) { throw "vendoring dependencies failed" }
# pip installs the project itself alongside its dependencies; the app is served
# from src/ so a second copy would shadow it and go stale.
Get-ChildItem -LiteralPath $sitePackages -Directory |
    Where-Object { $_.Name -eq "headless_re_mcp" -or $_.Name -like "headless_re_mcp-*" } |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }

# -B keeps the interpreter from writing bytecode beside the installed files.
# Those files do not exist at install time, so the installer cannot track them
# and uninstall leaves them behind; the bytecode is precompiled below instead.
$launcher = @(
  '@echo off', 'setlocal', 'cd /d "%~dp0"',
  '"%~dp0runtime\python\python.exe" -B start_web.py', 'if errorlevel 1 pause'
) -join "`r`n"
Set-Content -LiteralPath (Join-Path $stage "start_web.cmd") -Value $launcher -Encoding ASCII
$cli = @(
  '@echo off', 'setlocal', 'cd /d "%~dp0"',
  '"%~dp0runtime\python\python.exe" -B -m headless_re_mcp %*'
) -join "`r`n"
Set-Content -LiteralPath (Join-Path $stage "headless-re-mcp.cmd") -Value $cli -Encoding ASCII
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

# Compile now so the bytecode ships as tracked files and uninstall takes it away
# again. unchecked-hash stops the interpreter from invalidating it over install
# timestamps, which would defeat -B and make every start recompile in memory.
& python -m compileall -q -f --invalidation-mode unchecked-hash `
    (Join-Path $stage "src") $sitePackages | Out-Null
if (-not (Get-ChildItem -LiteralPath (Join-Path $stage "src") -Recurse -Filter *.pyc)) {
    throw "bytecode precompilation produced nothing"
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
