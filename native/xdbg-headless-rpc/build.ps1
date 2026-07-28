[CmdletBinding()]
param(
    [ValidateSet("x86", "x64", "all")]
    [string]$Architecture = "all",
    [string]$SourceRoot = "",
    [string]$BuildRoot = "",
    [switch]$SkipConfigure,
    [switch]$ConfigureOnly,
    [switch]$RunGate,
    [double]$GateTimeout = 60.0,
    [ValidateRange(1, 64)]
    [int]$BuildParallelism = 2,
    [switch]$AllowPinnedDownloadThroughLocalProxy
)

$ErrorActionPreference = "Stop"
$scriptRoot = $PSScriptRoot
$projectRoot = (Resolve-Path (Join-Path $scriptRoot "../..")).Path
$pythonExecutable = (Get-Command python -ErrorAction Stop).Source
$cmakeExecutable = (Get-Command cmake -ErrorAction Stop).Source

if (-not $SourceRoot) {
    $SourceRoot = Join-Path $projectRoot "upstream/x64dbg"
}
$SourceRoot = (Resolve-Path $SourceRoot).Path
if (-not (Test-Path (Join-Path $SourceRoot "src/headless/headless.cpp"))) {
    throw "official x64dbg headless source is missing under $SourceRoot"
}

if (-not $BuildRoot) {
    $BuildRoot = Join-Path $projectRoot "artifacts"
}
if (-not (Test-Path $BuildRoot)) {
    New-Item -ItemType Directory -Path $BuildRoot | Out-Null
}
$BuildRoot = (Resolve-Path $BuildRoot).Path

function Invoke-Checked([string]$Description, [scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

function Build-Headless([string]$Arch) {
    $platform = if ($Arch -eq "x64") { "x64" } else { "Win32" }
    $buildDirectory = Join-Path $BuildRoot "x64dbg-$Arch"

    if (-not $SkipConfigure) {
        $previousTlsVerify = $env:CMAKE_TLS_VERIFY
        try {
            if ($AllowPinnedDownloadThroughLocalProxy) {
                # x64dbg pins both Qt archives with URL_HASH in FindQt5.cmake.
                $env:CMAKE_TLS_VERIFY = "0"
            }
            Invoke-Checked "x64dbg $Arch configure" {
                & $cmakeExecutable -S $SourceRoot -B $buildDirectory `
                    -G "Visual Studio 17 2022" -A $platform `
                    -DX64DBG_BUILD_IN_TREE=OFF `
                    "-DHEADLESS_RE_XDBG_RPC_SOURCE_DIR=$($scriptRoot -replace '\\', '/')" `
                    "-DCMAKE_PROJECT_INCLUDE=$((Join-Path $scriptRoot 'inject.cmake') -replace '\\', '/')"
            }
        }
        finally {
            $env:CMAKE_TLS_VERIFY = $previousTlsVerify
        }
    }

    if ($ConfigureOnly) {
        return
    }

    Invoke-Checked "x64dbg $Arch headless build" {
        & $cmakeExecutable --build $buildDirectory --config Release `
            --target headless --parallel $BuildParallelism
    }

    # x86 Release builds are memory-sensitive on small hosts; one automatic retry
    # with parallelism=1 if the first build failed due to compiler/linker OOM.
    if (-not (Test-Path (Join-Path (Join-Path $buildDirectory "Release") "headless.exe"))) {
        if ($Arch -eq "x86" -and $BuildParallelism -gt 1) {
            Write-Warning "x86 headless missing after parallel build; retrying with -BuildParallelism 1"
            Invoke-Checked "x64dbg x86 headless build (serial retry)" {
                & $cmakeExecutable --build $buildDirectory --config Release `
                    --target headless --parallel 1
            }
        }
    }

    $runtimeDirectory = Join-Path $buildDirectory "Release"
    $localRuntimeDependencies = @(
        (Join-Path $buildDirectory "src/third_party/TitanEngine/Release/TitanEngine.dll")
    )
    foreach ($dependency in $localRuntimeDependencies) {
        if (-not (Test-Path $dependency)) {
            throw "x64dbg $Arch runtime dependency is missing: $dependency"
        }
        Copy-Item -Path $dependency -Destination $runtimeDirectory -Force
    }

    $headless = Join-Path $runtimeDirectory "headless.exe"
    if (-not (Test-Path $headless)) {
        throw "x64dbg $Arch build completed without $headless"
    }
    Invoke-Checked "x64dbg $Arch PE validation" {
        & $pythonExecutable (Join-Path $projectRoot "fixtures/native/verify.py") `
            --architecture $Arch $headless
    }

    [PSCustomObject]@{
        architecture = $Arch
        executable = (Resolve-Path $headless).Path
        environment = if ($Arch -eq "x64") {
            "HEADLESS_RE_X64DBG_HEADLESS_X64"
        }
        else {
            "HEADLESS_RE_X64DBG_HEADLESS_X86"
        }
    }
}

$architectures = if ($Architecture -eq "all") { @("x86", "x64") } else { @($Architecture) }
$outputs = @($architectures | ForEach-Object { Build-Headless $_ })
$outputs

if ($RunGate -and -not $ConfigureOnly) {
    $previousEnvironment = @{}
    try {
        foreach ($output in $outputs) {
            $name = $output.environment
            $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
            [Environment]::SetEnvironmentVariable($name, $output.executable, "Process")
        }
        Invoke-Checked "x64dbg $Architecture headless gate" {
            & $pythonExecutable -m headless_re_mcp gate-xdbg `
                --architecture $Architecture --timeout $GateTimeout
        }
    }
    finally {
        foreach ($entry in $previousEnvironment.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
        }
    }
}