[CmdletBinding()]
param(
    [ValidateSet("x86", "x64", "all")]
    [string]$Architecture = "all",
    [string]$BuildRoot = ""
)

$ErrorActionPreference = "Stop"
$sourceRoot = $PSScriptRoot
$projectRoot = (Resolve-Path (Join-Path $sourceRoot "../..")).Path
$pythonExecutable = (Get-Command python -ErrorAction Stop).Source
if (-not $BuildRoot) {
    $BuildRoot = Join-Path $projectRoot "artifacts"
}

function Resolve-VisualStudioInstance {
    if ($env:HEADLESS_RE_FIXTURE_VS_INSTANCE) {
        $instance = (Resolve-Path $env:HEADLESS_RE_FIXTURE_VS_INSTANCE).Path
        if (-not (Test-Path (Join-Path $instance "VC/Tools/MSVC"))) {
            throw "Visual Studio instance lacks MSVC tools: $instance"
        }
        return $instance
    }

    $installerRoot = [Environment]::GetFolderPath("ProgramFilesX86")
    $vswhere = Join-Path $installerRoot "Microsoft Visual Studio/Installer/vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        return $null
    }
    $instances = @(& $vswhere -latest -products * -property installationPath)
    if ($LASTEXITCODE -ne 0 -or $instances.Count -eq 0) {
        return $null
    }
    $resolved = (Resolve-Path $instances[0].Trim()).Path
    if (-not (Test-Path (Join-Path $resolved "VC/Tools/MSVC"))) {
        return $null
    }
    return $resolved
}

function Resolve-Compiler([string]$Arch) {
    if ($Arch -eq "x86") {
        if ($env:HEADLESS_RE_FIXTURE_CC_X86) {
            return (Resolve-Path $env:HEADLESS_RE_FIXTURE_CC_X86).Path
        }
        $mingw32 = "C:\msys64\mingw32\bin\gcc.exe"
        if (Test-Path $mingw32) {
            return $mingw32
        }
        throw "x86 compiler missing; install MSVC or MSYS2 mingw-w64-i686-gcc, or set HEADLESS_RE_FIXTURE_CC_X86"
    }

    if ($env:HEADLESS_RE_FIXTURE_CC_X64) {
        return (Resolve-Path $env:HEADLESS_RE_FIXTURE_CC_X64).Path
    }
    $command = Get-Command clang -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw "x64 compiler missing; install MSVC or Clang, or set HEADLESS_RE_FIXTURE_CC_X64"
}

function Build-Fixture([string]$Arch) {
    $buildDir = Join-Path $BuildRoot "fixtures-$Arch"
    $explicitCompiler = if ($Arch -eq "x86") {
        $env:HEADLESS_RE_FIXTURE_CC_X86
    } else {
        $env:HEADLESS_RE_FIXTURE_CC_X64
    }
    $vsInstance = if ($explicitCompiler) { $null } else { Resolve-VisualStudioInstance }
    $oldPath = $env:PATH
    try {
        $configureArguments = @("--fresh", "-S", $sourceRoot, "-B", $buildDir)
        if ($vsInstance) {
            $platform = if ($Arch -eq "x86") { "Win32" } else { "x64" }
            $configureArguments += @(
                "-G", "Visual Studio 17 2022",
                "-A", $platform,
                "-DCMAKE_GENERATOR_INSTANCE:PATH=$vsInstance"
            )
            Write-Output "fixture compiler[$Arch]: MSVC at $vsInstance"
        } else {
            $compiler = Resolve-Compiler $Arch
            $compilerDir = Split-Path $compiler -Parent
            $env:PATH = "$compilerDir;$oldPath"
            $configureArguments += @(
                "-G", "Ninja",
                "-DCMAKE_C_COMPILER:FILEPATH=$compiler",
                "-DCMAKE_BUILD_TYPE=Release"
            )
            Write-Output "fixture compiler[$Arch]: $compiler"
        }

        & cmake @configureArguments
        if ($LASTEXITCODE -ne 0) {
            throw "CMake configure failed for $Arch"
        }
        & cmake --build $buildDir --config Release --parallel 2 --verbose
        if ($LASTEXITCODE -ne 0) {
            throw "CMake build failed for $Arch"
        }

        $console = Join-Path $buildDir "console_fixture.exe"
        $headless = Join-Path $buildDir "headless_fixture.exe"
        $gui = Join-Path $buildDir "gui_fixture.exe"
        $eventDll = Join-Path $buildDir "event_fixture.dll"
        $output = (& $console) -join "`n"
        if ($LASTEXITCODE -ne 0 -or $output -notmatch "^HEADLESS_RE_FIXTURE ") {
            throw "console fixture validation failed for $Arch"
        }

        Start-Sleep -Milliseconds 500
        if (
            -not (Test-Path $headless) -or
            -not (Test-Path $gui) -or
            -not (Test-Path $eventDll)
        ) {
            throw "fixture artifact was removed after linking for $Arch; use MSVC or configure an alternate trusted compiler"
        }

        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $headless
        $startInfo.Arguments = "--module-cycle"
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $headlessProcess = [System.Diagnostics.Process]::Start($startInfo)
        $headlessProcess.WaitForExit()
        if ($headlessProcess.ExitCode -ne 0) {
            throw "headless fixture validation failed for $Arch"
        }
        $headlessProcess.Dispose()

        & $pythonExecutable (Join-Path $sourceRoot "verify.py") `
            --architecture $Arch $console $headless $gui $eventDll
        if ($LASTEXITCODE -ne 0) {
            throw "PE architecture validation failed for $Arch"
        }
        Write-Output $output
    }
    finally {
        $env:PATH = $oldPath
    }
}

$architectures = if ($Architecture -eq "all") { @("x86", "x64") } else { @($Architecture) }
foreach ($arch in $architectures) {
    Build-Fixture $arch
}