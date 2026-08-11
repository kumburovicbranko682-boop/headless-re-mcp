# Install the built MSI, exercise the installed copy, uninstall, and assert the
# machine is left exactly as it was. A packaged build that cannot round-trip is
# not releasable, so this runs in the release workflow before anything is
# published.
param(
    [string]$Msi = "artifacts/release/headless-re-mcp.msi"
)

$ErrorActionPreference = "Stop"
$Root = (Split-Path -Parent $PSScriptRoot)
Set-Location $Root
$msiPath = (Resolve-Path -LiteralPath $Msi).Path

function Get-MsiProperty([string]$path, [string]$name) {
    # Product Id="*" means the ProductCode is generated at build time, so read it
    # from the package itself. Win32_Product would also work but it reconfigures
    # every installed product as a side effect.
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($path, 0))
    $sql = 'SELECT `Value` FROM `Property` WHERE `Property`=' + "'$name'"
    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @($sql))
    $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
    $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
    if (-not $record) { throw "MSI property $name not found in $path" }
    return $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @(1))
}

function Invoke-Msiexec([string[]]$arguments, [string]$label) {
    $proc = Start-Process msiexec -ArgumentList $arguments -Wait -PassThru
    if ($proc.ExitCode -ne 0) { throw "$label failed with msiexec exit code $($proc.ExitCode)" }
}

$productCode = Get-MsiProperty $msiPath "ProductCode"
$installDir = Join-Path $env:LOCALAPPDATA "HeadlessReMcp"
Write-Host "product code $productCode"

if (Test-Path -LiteralPath $installDir) {
    throw "install folder already exists before the test: $installDir"
}

$logDir = Split-Path -Parent $msiPath
Invoke-Msiexec @("/i", "`"$msiPath`"", "/qn", "/l*v", "`"$(Join-Path $logDir 'verify-install.log')`"") "install"

foreach ($relative in @("start_web.cmd", "src\headless_re_mcp\__init__.py", "src\headless_re_mcp\web\spa\index.html")) {
    if (-not (Test-Path -LiteralPath (Join-Path $installDir $relative))) {
        throw "installed tree is missing $relative"
    }
}
$installedCount = (Get-ChildItem -LiteralPath $installDir -Recurse -File -Force).Count
Write-Host "installed $installedCount files"

# Run the installed copy the way a user would: through its own launcher, with a
# PATH that has no interpreter and an environment that leaks nothing from this
# checkout. Borrowing the developer machine's site-packages is what let an
# installer ship with no dependencies at all and still pass this check.
$launcher = Join-Path $installDir "start_web.cmd"
$bundledPython = Join-Path $installDir "runtime\python\python.exe"
if (-not (Test-Path -LiteralPath $bundledPython)) {
    throw "the install ships no interpreter at runtime\python\python.exe, so it cannot run on a machine without a matching Python and its dependencies"
}
$probeCmd = Join-Path $installDir "verify_probe.cmd"
$importProbe = Join-Path $installDir "verify_imports.py"
# config generate alone only proves the core imports resolve. The browser
# workbench is the reason most of the payload exists, so its stack has to be
# present too or the install is still a shell for the feature people use.
Set-Content -LiteralPath $importProbe -Encoding ascii -Value @(
    'import fastapi, uvicorn, httpx, mcp, pydantic, platformdirs, pefile',
    'from headless_re_mcp.mcp.server import create_server',
    'from headless_re_mcp.web.app import create_app',
    'print("web stack ok")'
)
$probeBody = @(
    '@echo off',
    'setlocal',
    'cd /d "%~dp0"',
    'call "%~dp0runtime\python\python.exe" -B verify_imports.py || exit /b 1',
    'call "%~dp0runtime\python\python.exe" -B -m headless_re_mcp config generate --skip-doctor --no-examples',
    'exit /b %ERRORLEVEL%'
) -join "`r`n"
Set-Content -LiteralPath $probeCmd -Value $probeBody -Encoding ASCII

$clean = @{
    PYTHONPATH = $null
    PYTHONHOME = $null
    VIRTUAL_ENV = $null
}
$saved = @{}
foreach ($name in $clean.Keys) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name)
    [Environment]::SetEnvironmentVariable($name, $null)
}
$savedPath = $env:PATH
# Strip every interpreter from PATH so a bundled runtime is the only one that can
# answer; if the payload has none, this fails, which is the point.
$env:PATH = "$env:SystemRoot\system32;$env:SystemRoot"
try {
    $output = & cmd /c "`"$probeCmd`"" 2>&1
    $exit = $LASTEXITCODE
} finally {
    $env:PATH = $savedPath
    foreach ($name in $saved.Keys) {
        [Environment]::SetEnvironmentVariable($name, $saved[$name])
    }
    Remove-Item -LiteralPath $probeCmd -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $importProbe -Force -ErrorAction SilentlyContinue
}
if (($output | Out-String) -notmatch "web stack ok") {
    Write-Host ($output | Out-String)
    throw "the bundled runtime is missing part of the browser workbench stack"
}
if ($exit -ne 0) {
    Write-Host ($output | Out-String)
    throw "the installed copy cannot run on its own (exit $exit); it needs a runtime it does not ship"
}
if (($output | Out-String) -notmatch '"ok"\s*:\s*true') {
    Write-Host ($output | Out-String)
    throw "installed copy ran but did not report a healthy config"
}
foreach ($required in @("start_web.cmd", "headless-re-mcp.cmd")) {
    if (-not (Test-Path -LiteralPath (Join-Path $installDir $required))) {
        throw "$required is missing from the install"
    }
}
Write-Host "installed copy runs standalone with its own runtime and web stack"

Invoke-Msiexec @("/x", "`"$productCode`"", "/qn", "/l*v", "`"$(Join-Path $logDir 'verify-uninstall.log')`"") "uninstall"

if (Test-Path -LiteralPath $installDir) {
    $leftover = Get-ChildItem -LiteralPath $installDir -Recurse -File -Force
    Write-Host ($leftover | ForEach-Object { $_.FullName } | Out-String)
    throw "uninstall left $($leftover.Count) files behind in $installDir"
}
Write-Host "MSI round-trip clean: installed, ran, uninstalled, no residue"
