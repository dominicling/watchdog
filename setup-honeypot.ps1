<#
.SYNOPSIS
  Deploy honeypot credential files, enable NTFS file system auditing,
  and set per-file SACLs so that any read triggers Windows Security Event 4663.

.NOTES
  Must run as Administrator. The script self-elevates via Shell.Application
  COM if not already elevated.

  Run once on ttt02 after pulling the watchdog repo.
  Re-run any time you need to re-deploy or refresh SACLs.
#>

# ── Self-elevation ────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Host "Not running as Administrator — re-launching elevated via UAC..."
    $shell = New-Object -ComObject Shell.Application
    $shell.ShellExecute(
        'powershell.exe',
        "-ExecutionPolicy Bypass -NonInteractive -File `"$PSCommandPath`"",
        '',
        'runas',
        1
    )
    exit
}

$ErrorActionPreference = 'Stop'
$ScriptDir = $PSScriptRoot

# ── Honeypot file map: source (in repo) → destination (on disk) ───────────────
$Honeypots = @(
    @{
        Source = Join-Path $ScriptDir 'honeypots\bsw-credentials.json'
        Dest   = 'C:\Users\USER\Documents\GitHub\bsw-pipeline\credentials.json'
        Id     = 'HP-BSW-001'
    },
    @{
        Source = Join-Path $ScriptDir 'honeypots\infisical-config.json'
        Dest   = 'C:\Users\USER\Documents\infisical\infisical-config.json'
        Id     = 'HP-INF-001'
    },
    @{
        Source = Join-Path $ScriptDir 'honeypots\root-env'
        Dest   = 'C:\Users\USER\Documents\GitHub\.env'
        Id     = 'HP-ENV-001'
    }
)

# ── Step 1: Enable Object Access auditing (file system subcategory) ───────────
Write-Host "`n[1/3] Enabling file system audit policy..."
$auditResult = & auditpol /set /subcategory:"File System" /success:enable 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Warning "auditpol returned $LASTEXITCODE`: $auditResult"
} else {
    Write-Host "     File System auditing: SUCCESS enabled" -ForegroundColor Green
}

# ── Step 2: Deploy honeypot files ─────────────────────────────────────────────
Write-Host "`n[2/3] Deploying honeypot files..."
foreach ($h in $Honeypots) {
    $destDir = Split-Path $h.Dest
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    Copy-Item -Path $h.Source -Destination $h.Dest -Force
    Write-Host "     Deployed [$($h.Id)]: $($h.Dest)" -ForegroundColor Cyan
}

# ── Step 3: Set SACL (audit rule) on each honeypot file ──────────────────────
Write-Host "`n[3/3] Setting SACLs..."
foreach ($h in $Honeypots) {
    try {
        $acl = Get-Acl -Path $h.Dest -Audit

        # Audit Everyone reading the file (ReadData = 0x1; using FileSystemRights.Read
        # which covers ReadData + ReadAttributes + ReadExtendedAttributes + ReadPermissions)
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            'Everyone',
            [System.Security.AccessControl.FileSystemRights]::Read,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AuditFlags]::Success
        )

        $acl.SetAuditRule($auditRule)
        Set-Acl -Path $h.Dest -AclObject $acl
        Write-Host "     SACL set  [$($h.Id)]: $($h.Dest)" -ForegroundColor Green
    } catch {
        Write-Warning "     SACL FAILED [$($h.Id)]: $($h.Dest) — $_"
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host "`n======================================================"
Write-Host " Honeypot setup complete." -ForegroundColor Green
Write-Host " Next step: install and start HoneypotMonitor service"
Write-Host "   cd $ScriptDir"
Write-Host "   powershell -ExecutionPolicy Bypass -File install-honeypot-service.ps1"
Write-Host "======================================================"
