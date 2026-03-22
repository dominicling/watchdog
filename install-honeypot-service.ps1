#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install HoneypotMonitor as an NSSM service.

.NOTES
  Run from the watchdog directory as Administrator.
  Requires: nssm.exe in PATH, node.exe in PATH.

  TELEGRAM_BOT_TOKEN_MIRROR must be set as a Machine-level environment variable
  before running this script. The service inherits all Machine env vars.

  Run setup-honeypot.ps1 first to deploy files and configure NTFS auditing.
#>

$ErrorActionPreference = 'Stop'

$ServiceName  = 'HoneypotMonitor'
$WatchdogDir  = $PSScriptRoot
$ScriptPath   = Join-Path $WatchdogDir 'honeypot-monitor.js'
$LogDir       = Join-Path $WatchdogDir 'logs'

$NodeExe = (Get-Command node -ErrorAction Stop).Source
$NssmExe = (Get-Command nssm -ErrorAction Stop).Source

Write-Host "Installing $ServiceName..."
Write-Host "  Node  : $NodeExe"
Write-Host "  Script: $ScriptPath"
Write-Host "  NSSM  : $NssmExe"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Remove existing service if present
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Removing existing service..."
    & $NssmExe stop   $ServiceName confirm 2>$null
    & $NssmExe remove $ServiceName confirm
}

# Install: NSSM runs node.exe directly — no PowerShell, no ExecutionPolicy issues
& $NssmExe install $ServiceName $NodeExe

# AppParameters: embed script path directly (GPO resets ExecutionPolicy but this is pure Node)
& $NssmExe set $ServiceName AppParameters      "`"$ScriptPath`""
& $NssmExe set $ServiceName AppDirectory       $WatchdogDir
& $NssmExe set $ServiceName DisplayName        'Honeypot Credential Monitor'
& $NssmExe set $ServiceName Description        'Monitors honeypot credential files via Security event log (Event 4663); kills reading process and sends Telegram alert.'
& $NssmExe set $ServiceName Start              SERVICE_AUTO_START
& $NssmExe set $ServiceName ObjectName         LocalSystem

# NSSM log rotation
& $NssmExe set $ServiceName AppStdout          (Join-Path $LogDir 'honeypot-stdout.log')
& $NssmExe set $ServiceName AppStderr          (Join-Path $LogDir 'honeypot-stderr.log')
& $NssmExe set $ServiceName AppRotateFiles     1
& $NssmExe set $ServiceName AppRotateOnline    1
& $NssmExe set $ServiceName AppRotateSeconds   86400
& $NssmExe set $ServiceName AppRotateBytes     10485760

# Restart policy: restart on crash after 5s
& $NssmExe set $ServiceName AppExit            Default Restart
& $NssmExe set $ServiceName AppRestartDelay    5000

# Start the service
& $NssmExe start $ServiceName

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "$ServiceName installed and running." -ForegroundColor Green
} else {
    Write-Warning "$ServiceName may not have started. Check: nssm status $ServiceName"
}
