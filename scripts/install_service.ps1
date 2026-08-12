#Requires -Version 5.1
<#
.SYNOPSIS
  Register (or remove) the unattended Headless RE-MCP service as a per-user
  scheduled task that starts at logon and is kept alive by the supervisor.

.DESCRIPTION
  A scheduled task rather than a Windows service, deliberately. The debugger
  backends need an interactive desktop session and a user profile that holds the
  IDA licence; a session 0 service has neither, and the analysers would fail in
  ways that look like product bugs.

  Crash recovery is the supervisor's job, not the scheduler's: it understands
  readiness, backoff and crash loops, whereas Task Scheduler can only restart a
  process that exited. The task exists to start the supervisor and to bring it
  back after a reboot.

.EXAMPLE
  powershell -File scripts/install_service.ps1 -Action install
  powershell -File scripts/install_service.ps1 -Action status
  powershell -File scripts/install_service.ps1 -Action uninstall
#>
[CmdletBinding()]
param(
    [ValidateSet("install", "uninstall", "status")]
    [string]$Action = "install",
    [string]$TaskName = "HeadlessReMcp",
    [string]$Python = "",
    [string]$Config = "",
    [int]$Port = 0
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

function Resolve-Python {
    if ($Python) { return $Python }
    $candidate = Get-Command python -ErrorAction SilentlyContinue
    if ($candidate) { return $candidate.Source }
    throw "python not found on PATH; pass -Python <path>"
}

function Get-Task {
    Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}

switch ($Action) {
    "status" {
        $task = Get-Task
        if (-not $task) {
            Write-Host "not installed: $TaskName"
            exit 1
        }
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
        [pscustomobject]@{
            TaskName       = $task.TaskName
            State          = $task.State
            LastRunTime    = $info.LastRunTime
            LastTaskResult = $info.LastTaskResult
            NextRunTime    = $info.NextRunTime
        } | Format-List
        exit 0
    }
    "uninstall" {
        if (-not (Get-Task)) {
            Write-Host "nothing to remove: $TaskName"
            exit 0
        }
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "removed scheduled task $TaskName"
        exit 0
    }
}

$exe = Resolve-Python
$argumentList = @("-m", "headless_re_mcp")
if ($Config) { $argumentList += @("--config", $Config) }
$argumentList += "supervise"
if ($Port -gt 0) { $argumentList += @("--port", "$Port") }
$arguments = ($argumentList | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join " "

$action = New-ScheduledTaskAction -Execute $exe -Argument $arguments -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
# The supervisor is long-lived by design, so no execution time limit, and only
# one instance: a second supervisor would fight the first over the same port.
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -DontStopOnIdleEnd `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew `
    -RestartCount 3 `
    -RestartInterval ([TimeSpan]::FromMinutes(1))
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

if (Get-Task) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null

Write-Host "registered scheduled task $TaskName"
Write-Host "  runs: $exe $arguments"
Write-Host "  from: $Root"
Write-Host "start now with: Start-ScheduledTask -TaskName $TaskName"