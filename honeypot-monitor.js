'use strict';

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');
const os = require('os');

// ── Config ────────────────────────────────────────────────────────────────────
const CHAT_ID = '-1003781345255';
const LOG_DIR = path.join(__dirname, 'logs');
const BOOKMARK_FILE = path.join(LOG_DIR, 'honeypot-bookmark.json');
const MACHINE_HOSTNAME = os.hostname();
const POLL_INTERVAL_MS = 2000;
const POLL_WINDOW_SECONDS = 6; // look-back window per poll (with 1s overlap handled via dedup)
const MAX_PROCESSED_IDS = 500; // cap on dedup set size

// Honeypot file paths — lowercase for case-insensitive matching
const HONEYPOT_MAP = {
  'c:\\users\\user\\documents\\github\\bsw-pipeline\\credentials.json': 'HP-BSW-001',
  'c:\\users\\user\\documents\\infisical\\infisical-config.json':        'HP-INF-001',
  'c:\\users\\user\\documents\\github\\.env':                            'HP-ENV-001',
};

// System processes that must never be killed
const PROTECTED_PROCESS_NAMES = new Set([
  'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
  'services.exe', 'lsass.exe', 'svchost.exe', 'lsm.exe', 'dwm.exe',
]);

// ── Logging ───────────────────────────────────────────────────────────────────
function ensureLogDir() {
  if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
}

function log(message, level = 'INFO') {
  const timestamp = new Date().toISOString();
  const line = `[${timestamp}] [${level}] ${message}\n`;
  process.stdout.write(line);
  try {
    const logFile = path.join(LOG_DIR, `honeypot-${timestamp.slice(0, 10)}.log`);
    fs.appendFileSync(logFile, line);
  } catch (_) {}
}

// ── Telegram ──────────────────────────────────────────────────────────────────
function sendTelegram(text) {
  const token = process.env.TELEGRAM_BOT_TOKEN_MIRROR;
  if (!token) {
    log('TELEGRAM_BOT_TOKEN_MIRROR not set — skipping alert', 'WARN');
    return;
  }

  const body = JSON.stringify({ chat_id: CHAT_ID, text, parse_mode: 'HTML' });
  const options = {
    hostname: 'api.telegram.org',
    path: `/bot${token}/sendMessage`,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
  };

  const req = https.request(options, (res) => {
    if (res.statusCode !== 200) log(`Telegram API responded ${res.statusCode}`, 'ERROR');
  });
  req.on('error', (err) => log(`Telegram send error: ${err.message}`, 'ERROR'));
  req.write(body);
  req.end();
}

// ── Bookmark (last poll timestamp, persisted across restarts) ─────────────────
function loadBookmark() {
  try {
    const data = JSON.parse(fs.readFileSync(BOOKMARK_FILE, 'utf8'));
    return data.lastPollTime ? new Date(data.lastPollTime) : null;
  } catch (_) {
    return null;
  }
}

function saveBookmark(date) {
  try {
    fs.writeFileSync(BOOKMARK_FILE, JSON.stringify({ lastPollTime: date.toISOString() }));
  } catch (e) {
    log(`Failed to save bookmark: ${e.message}`, 'ERROR');
  }
}

// ── Dedup set (prevents re-firing on same event from overlapping poll windows) ─
const processedIds = new Set();

function markProcessed(recordId) {
  processedIds.add(recordId);
  if (processedIds.size > MAX_PROCESSED_IDS) {
    // Evict oldest entry
    processedIds.delete(processedIds.values().next().value);
  }
}

// ── Incident handler ──────────────────────────────────────────────────────────
function handleAccess(evt) {
  const filePath = (evt.ObjectName || '').toLowerCase();
  const honeypotId = HONEYPOT_MAP[filePath];
  if (!honeypotId) return; // not a honeypot file

  const processName = path.basename(evt.ProcessName || 'unknown').toLowerCase();
  const pid = parseInt(evt.ProcessId, 10);
  const timestamp = evt.TimeCreated ? new Date(evt.TimeCreated).toISOString() : new Date().toISOString();

  log(
    `HONEYPOT ACCESS — ${honeypotId} | File: ${evt.ObjectName} | ` +
    `Process: ${evt.ProcessName} (PID ${pid}) | User: ${evt.SubjectUserName}`,
    'ALERT',
  );

  const safeToKill = pid > 4 && !PROTECTED_PROCESS_NAMES.has(processName);

  if (safeToKill) {
    exec(`taskkill /PID ${pid} /F`, (killErr) => {
      const killResult = killErr
        ? `kill FAILED: ${killErr.message}`
        : `PID ${pid} killed`;

      log(`${killResult} (${evt.ProcessName})`, killErr ? 'ERROR' : 'ALERT');
      fireAlert(honeypotId, evt, pid, timestamp, killResult);
    });
  } else {
    const killResult = `PID ${pid} skipped (protected or system)`;
    log(killResult, 'WARN');
    fireAlert(honeypotId, evt, pid, timestamp, killResult);
  }
}

function fireAlert(honeypotId, evt, pid, timestamp, killResult) {
  const alertText =
    `🍯 <b>HONEYPOT TRIGGERED</b> — <code>${MACHINE_HOSTNAME}</code>\n\n` +
    `<b>File:</b> <code>${evt.ObjectName}</code>\n` +
    `<b>Honeypot ID:</b> <code>${honeypotId}</code>\n` +
    `<b>Process:</b> <code>${evt.ProcessName}</code>\n` +
    `<b>PID:</b> ${pid}\n` +
    `<b>User:</b> ${evt.SubjectUserName || 'unknown'}\n` +
    `<b>Action:</b> ${killResult}\n` +
    `<b>Time:</b> ${timestamp}`;

  sendTelegram(alertText);

  // Structured log
  const incident = {
    timestamp,
    machine: MACHINE_HOSTNAME,
    honeypotId,
    file: evt.ObjectName,
    processName: evt.ProcessName,
    pid,
    user: evt.SubjectUserName,
    killResult,
  };
  try {
    fs.appendFileSync(
      path.join(LOG_DIR, 'honeypot-incidents.jsonl'),
      JSON.stringify(incident) + '\n',
    );
  } catch (e) {
    log(`Failed to write incident log: ${e.message}`, 'ERROR');
  }
}

// ── Event log polling via Get-WinEvent ────────────────────────────────────────
let lastPollTime = null;
let polling = false;

function buildPsCommand(startTime) {
  // Select only the fields we need; Properties indices for EventID 4663:
  //   [5]=ObjectType  [6]=ObjectName  [9]=AccessMask  [10]=ProcessId  [11]=ProcessName
  // SubjectUserName is in Properties[1]
  const iso = startTime.toISOString();
  return (
    `$events = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4663;StartTime='${iso}'} ` +
    `-ErrorAction SilentlyContinue; ` +
    `if ($events) { ` +
    `$events | Select-Object RecordId,TimeCreated,` +
    `@{N='SubjectUserName';E={$_.Properties[1].Value}},` +
    `@{N='ObjectType';E={$_.Properties[5].Value}},` +
    `@{N='ObjectName';E={$_.Properties[6].Value}},` +
    `@{N='AccessMask';E={$_.Properties[9].Value}},` +
    `@{N='ProcessId';E={$_.Properties[10].Value}},` +
    `@{N='ProcessName';E={$_.Properties[11].Value}} ` +
    `| Where-Object { $_.ObjectType -eq 'File' } ` +
    `| ConvertTo-Json -Depth 2 -Compress }`
  );
}

function poll() {
  if (polling) return; // skip if previous poll still running
  polling = true;

  // On first poll, look back POLL_WINDOW_SECONDS to catch anything since startup
  const startTime = lastPollTime
    ? new Date(lastPollTime.getTime() - 1000) // 1s overlap to avoid boundary gaps
    : new Date(Date.now() - POLL_WINDOW_SECONDS * 1000);

  const nowBeforePoll = new Date();

  exec(
    `powershell.exe -ExecutionPolicy Bypass -NonInteractive -Command "${buildPsCommand(startTime)}"`,
    { maxBuffer: 10 * 1024 * 1024, timeout: 15000 },
    (err, stdout) => {
      polling = false;

      if (err) {
        log(`Poll error: ${err.message}`, 'ERROR');
        lastPollTime = nowBeforePoll;
        saveBookmark(nowBeforePoll);
        return;
      }

      const raw = (stdout || '').trim();
      if (raw) {
        try {
          const parsed = JSON.parse(raw);
          const events = Array.isArray(parsed) ? parsed : [parsed];

          for (const evt of events) {
            const recordId = String(evt.RecordId);
            if (processedIds.has(recordId)) continue;
            markProcessed(recordId);
            handleAccess(evt);
          }
        } catch (parseErr) {
          log(`JSON parse error: ${parseErr.message} — raw: ${raw.slice(0, 200)}`, 'ERROR');
        }
      }

      lastPollTime = nowBeforePoll;
      saveBookmark(nowBeforePoll);
    },
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────
ensureLogDir();

// Resume from saved bookmark if present
const savedTime = loadBookmark();
if (savedTime) {
  lastPollTime = savedTime;
  log(`Resuming from bookmark: ${savedTime.toISOString()}`);
}

log(`Honeypot monitor starting on ${MACHINE_HOSTNAME}`);
log(`Watching ${Object.keys(HONEYPOT_MAP).length} honeypot paths via Security event log (Event ID 4663)`);
log(`Poll interval: ${POLL_INTERVAL_MS}ms`);

setInterval(poll, POLL_INTERVAL_MS);
poll(); // immediate first poll

process.on('SIGTERM', () => { log('Honeypot monitor stopping (SIGTERM)'); process.exit(0); });
process.on('SIGINT',  () => { log('Honeypot monitor stopping (SIGINT)');  process.exit(0); });
process.on('uncaughtException',  (err) => log(`Uncaught exception: ${err.stack}`, 'ERROR'));
process.on('unhandledRejection', (r)   => log(`Unhandled rejection: ${r}`, 'ERROR'));
