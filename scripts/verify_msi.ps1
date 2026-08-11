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

# Importing the installed copy both proves the payload is complete and makes
# Python write __pycache__, which is the residue this check exists to catch.
$previousPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = Join-Path $installDir "src"
$probe = Join-Path ([IO.Path]::GetTempPath()) "headless_re_mcp_msi_probe.py"
Set-Content -LiteralPath $probe -Encoding ascii -Value @(
    'import pathlib',
    'import headless_re_mcp',
    'print(pathlib.Path(headless_re_mcp.__file__).resolve())'
)
try {
    Push-Location $installDir
    # A development checkout is usually pip-installed on the same machine, and an
    # editable install can win over PYTHONPATH. Without this the check could pass
    # while exercising the repository instead of the package under test.
    $resolved = (& python $probe 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "installed copy failed to import: $resolved" }
    if (-not $resolved.StartsWith($installDir, [StringComparison]::OrdinalIgnoreCase)) {
        Pop-Location
        throw "import resolved to $resolved instead of the installed tree under $installDir"
    }
    $output = & python -m headless_re_mcp config generate --skip-doctor --no-examples 2>&1
    $exit = $LASTEXITCODE
    Pop-Location
} finally {
    $env:PYTHONPATH = $previousPythonPath
    Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
}
if ($exit -ne 0) {
    Write-Host ($output | Out-String)
    throw "installed copy failed to run (exit $exit)"
}
if (($output | Out-String) -notmatch '"ok"\s*:\s*true') {
    Write-Host ($output | Out-String)
    throw "installed copy ran but did not report a healthy config"
}
$bytecode = (Get-ChildItem -LiteralPath $installDir -Recurse -File -Force -Filter *.pyc).Count
Write-Host "installed copy runs; wrote $bytecode bytecode files"

Invoke-Msiexec @("/x", "`"$productCode`"", "/qn", "/l*v", "`"$(Join-Path $logDir 'verify-uninstall.log')`"") "uninstall"

if (Test-Path -LiteralPath $installDir) {
    $leftover = Get-ChildItem -LiteralPath $installDir -Recurse -File -Force
    Write-Host ($leftover | ForEach-Object { $_.FullName } | Out-String)
    throw "uninstall left $($leftover.Count) files behind in $installDir"
}
Write-Host "MSI round-trip clean: installed, ran, uninstalled, no residue"
