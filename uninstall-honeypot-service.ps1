#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Uninstall HoneypotMonitor NSSM service.
#>

$ErrorActionPreference = 'Stop'
$ServiceName = 'HoneypotMonitor'
$NssmExe     = (Get-Command nssm -ErrorAction Stop).Source

Write-Host "Uninstalling $ServiceName..."
& $NssmExe stop   $ServiceName confirm 2>$null
& $NssmExe remove $ServiceName confirm
Write-Host "$ServiceName removed." -ForegroundColor Yellow
