#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$ServiceName = 'WatchdogService'
$NssmExe = (Get-Command nssm -ErrorAction Stop).Source

Write-Host "Stopping and removing $ServiceName..."
& $NssmExe stop   $ServiceName confirm 2>$null
& $NssmExe remove $ServiceName confirm

Write-Host "$ServiceName removed." -ForegroundColor Yellow
