#Requires -Version 5.1
<#
.SYNOPSIS
    Weekly Claude Code session/snapshot/memory cleanup.
    Runs as a Windows Scheduled Task on ttt02.
#>

param(
    [int]$RetentionDays = 7
)

$ErrorActionPreference = 'Continue'

# ── Config ────────────────────────────────────────────────────────────────────
$CHAT_ID    = '-1003781345255'
$BOT_TOKEN  = $env:TELEGRAM_BOT_TOKEN_MIRROR
$HOSTNAME   = $env:COMPUTERNAME
$CUTOFF     = (Get-Date).AddDays(-$RetentionDays)

$SESSION_DIR  = 'C:\Users\USER\.claude\projects'
$SNAPSHOT_DIR = 'C:\Users\USER\.claude\shell-snapshots'
$MEMORY_DIR   = 'C:\Users\USER\.claude\projects\C--Users-USER-Documents-GitHub\memory'

# ── Helpers ──────────────────────────────────────────────────────────────────
function Send-Telegram {
    param([string]$Text)
    if (-not $BOT_TOKEN) { Write-Warning 'TELEGRAM_BOT_TOKEN_MIRROR not set'; return }
    $body = @{ chat_id = $CHAT_ID; text = $Text; parse_mode = 'HTML' } | ConvertTo-Json -Compress
    try {
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" `
            -Method POST -ContentType 'application/json' -Body $body | Out-Null
    } catch {
        Write-Warning "Telegram send failed: $_"
    }
}

function Remove-OldFiles {
    param([string]$Dir, [bool]$AllFiles = $false, [string]$Label)
    if (-not (Test-Path $Dir)) { return 0 }

    if ($AllFiles) {
        $files = Get-ChildItem -Path $Dir -Recurse -File
    } else {
        $files = Get-ChildItem -Path $Dir -Recurse -File |
                 Where-Object { $_.LastWriteTime -lt $CUTOFF }
    }

    $count = 0
    foreach ($f in $files) {
        try {
            Remove-Item -Path $f.FullName -Force
            $count++
        } catch {
            Write-Warning "Could not delete $($f.FullName): $_"
        }
    }
    Write-Host "[$Label] Deleted $count file(s)"
    return $count
}

# ── Main ─────────────────────────────────────────────────────────────────────
Write-Host "=== Claude Code weekly cleanup starting $(Get-Date -Format 'u') ==="

$deletedSessions   = Remove-OldFiles -Dir $SESSION_DIR   -AllFiles $false -Label 'Sessions'
$deletedSnapshots  = Remove-OldFiles -Dir $SNAPSHOT_DIR  -AllFiles $false -Label 'Snapshots'
$deletedMemory     = Remove-OldFiles -Dir $MEMORY_DIR    -AllFiles $true  -Label 'Memory'

$report = @"
[ttt02] Weekly Claude Code cleanup complete.

Sessions (>7d deleted): $deletedSessions files
Snapshots (>7d deleted): $deletedSnapshots files
Memory (all deleted): $deletedMemory files

Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') SGT
"@

Write-Host $report
Send-Telegram -Text $report

Write-Host '=== Cleanup complete ==='
