'use strict';

const chokidar = require('chokidar');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');
const os = require('os');

// ── Config ────────────────────────────────────────────────────────────────────
const CHAT_ID = '-1003781345255';
const LOG_DIR = path.join(__dirname, 'logs');
const MACHINE_HOSTNAME = os.hostname();
const TARGET_PROCESS = 'bash.exe';
const HANDLE_EXE = process.env.HANDLE_EXE_PATH || 'C:\\tools\\handle64.exe';
const HANDLE_SCAN_INTERVAL_MS = 10000;

// Patterns that, if matched by handle.exe output for bash.exe, trigger a kill
const SENSITIVE_HANDLE_PATTERNS = [
  /infisical/i,
  /\\\.env(\b|$)/i,
  /claude-/i,
];

// Paths watched by chokidar (any filesystem event fires an immediate check)
const WATCH_PATHS = [
  'C:/Users/USER/Documents/infisical/**',
  'C:/Users/USER/Documents/GitHub/**/.env',
  'C:/Users/USER/AppData/Local/Temp/claude-*',
];

// ── Logging ───────────────────────────────────────────────────────────────────
function ensureLogDir() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}

function log(message, level = 'INFO') {
  const timestamp = new Date().toISOString();
  const line = `[${timestamp}] [${level}] ${message}\n`;
  process.stdout.write(line);
  try {
    const logFile = path.join(LOG_DIR, `watchdog-${timestamp.slice(0, 10)}.log`);
    fs.appendFileSync(logFile, line);
  } catch (_) { /* log dir might not exist yet */ }
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
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
  };

  const req = https.request(options, (res) => {
    if (res.statusCode !== 200) {
      log(`Telegram API responded ${res.statusCode}`, 'ERROR');
    }
  });
  req.on('error', (err) => log(`Telegram send error: ${err.message}`, 'ERROR'));
  req.write(body);
  req.end();
}

// ── Incident handler ──────────────────────────────────────────────────────────
// Deduplicate: don't fire multiple alerts within 5 seconds for the same path
const recentIncidents = new Map();
const DEDUP_WINDOW_MS = 5000;

function handleIncident(reason, triggeredPath) {
  const key = `${reason}|${triggeredPath}`;
  const now = Date.now();
  if (recentIncidents.has(key) && now - recentIncidents.get(key) < DEDUP_WINDOW_MS) return;
  recentIncidents.set(key, now);

  exec(
    `tasklist /FI "IMAGENAME eq ${TARGET_PROCESS}" /FO CSV /NH`,
    (err, stdout) => {
      if (err) {
        log(`tasklist error: ${err.message}`, 'ERROR');
        return;
      }

      const lines = (stdout || '').trim().split('\n')
        .filter((l) => l.toLowerCase().includes(TARGET_PROCESS.toLowerCase()));

      if (lines.length === 0) {
        log(`No ${TARGET_PROCESS} processes found during incident check (path: ${triggeredPath})`, 'INFO');
        return;
      }

      const pids = lines
        .map((line) => parseInt(line.replace(/"/g, '').split(',')[1], 10))
        .filter((pid) => !isNaN(pid));

      log(
        `INCIDENT — ${TARGET_PROCESS} running during protected-path access. ` +
        `Reason: ${reason}. Path: ${triggeredPath}. PIDs: ${pids.join(', ')}`,
        'ALERT',
      );

      let killResults = [];
      let pending = pids.length;

      pids.forEach((pid) => {
        exec(`taskkill /PID ${pid} /F`, (killErr) => {
          if (killErr) {
            log(`Failed to kill PID ${pid}: ${killErr.message}`, 'ERROR');
            killResults.push(`PID ${pid}: FAILED`);
          } else {
            log(`Killed ${TARGET_PROCESS} PID ${pid}`, 'ALERT');
            killResults.push(`PID ${pid}: killed`);
          }
          pending--;
          if (pending === 0) finishIncident(reason, triggeredPath, pids, killResults);
        });
      });
    },
  );
}

function finishIncident(reason, triggeredPath, pids, killResults) {
  const timestamp = new Date().toISOString();

  const alertText =
    `🚨 <b>WATCHDOG ALERT</b> — <code>${MACHINE_HOSTNAME}</code>\n\n` +
    `<b>Process:</b> ${TARGET_PROCESS}\n` +
    `<b>Trigger:</b> ${reason}\n` +
    `<b>Path:</b> <code>${triggeredPath}</code>\n` +
    `<b>PIDs:</b> ${killResults.join(', ')}\n` +
    `<b>Time:</b> ${timestamp}`;

  sendTelegram(alertText);

  // Structured incident log
  const incident = {
    timestamp,
    machine: MACHINE_HOSTNAME,
    process: TARGET_PROCESS,
    pids,
    killResults,
    triggeredPath,
    reason,
  };
  try {
    fs.appendFileSync(path.join(LOG_DIR, 'incidents.jsonl'), JSON.stringify(incident) + '\n');
  } catch (e) {
    log(`Failed to write incident log: ${e.message}`, 'ERROR');
  }
}

// ── Handle scanner (Sysinternals handle.exe) ──────────────────────────────────
let handleExeAvailable = null; // null = untested, true/false after first run

function checkHandles() {
  if (handleExeAvailable === false) return; // already confirmed unavailable

  exec(
    `"${HANDLE_EXE}" -p bash -accepteula -nobanner 2>nul`,
    { timeout: 8000 },
    (err, stdout) => {
      if (err && !stdout) {
        if (handleExeAvailable === null) {
          log(`handle.exe not found at ${HANDLE_EXE} — periodic handle scanning disabled`, 'WARN');
          handleExeAvailable = false;
        }
        return;
      }

      if (handleExeAvailable === null) {
        log(`handle.exe found — periodic handle scanning active (${HANDLE_SCAN_INTERVAL_MS / 1000}s interval)`, 'INFO');
        handleExeAvailable = true;
      }

      if (!stdout || !stdout.trim()) return;

      for (const pattern of SENSITIVE_HANDLE_PATTERNS) {
        const match = stdout.split('\n').find((line) => pattern.test(line));
        if (match) {
          handleIncident(
            `handle.exe detected open handle matching ${pattern}`,
            match.trim(),
          );
          return; // one incident per scan cycle
        }
      }
    },
  );
}

// ── Filesystem watcher ────────────────────────────────────────────────────────
function startWatcher() {
  log(`Watchdog starting on ${MACHINE_HOSTNAME}`);
  log(`Watching ${WATCH_PATHS.length} path patterns`);

  const watcher = chokidar.watch(WATCH_PATHS, {
    persistent: true,
    ignoreInitial: true,
    followSymlinks: false,
    usePolling: false,
    awaitWriteFinish: { stabilityThreshold: 200, pollInterval: 100 },
    depth: 10,
  });

  watcher
    .on('add',    (p) => handleIncident(`chokidar: file created`, p))
    .on('change', (p) => handleIncident(`chokidar: file changed`, p))
    .on('unlink', (p) => handleIncident(`chokidar: file deleted`, p))
    .on('addDir', (p) => handleIncident(`chokidar: directory created`, p))
    .on('error',  (e) => log(`Watcher error: ${e.message}`, 'ERROR'))
    .on('ready',  ()  => log('Filesystem watcher ready'));

  // Periodic handle scan
  setInterval(checkHandles, HANDLE_SCAN_INTERVAL_MS);

  log('Watchdog active.');
}

// ── Main ──────────────────────────────────────────────────────────────────────
ensureLogDir();
startWatcher();

process.on('SIGTERM', () => { log('Watchdog stopping (SIGTERM)'); process.exit(0); });
process.on('SIGINT',  () => { log('Watchdog stopping (SIGINT)');  process.exit(0); });
process.on('uncaughtException', (err) => log(`Uncaught exception: ${err.stack}`, 'ERROR'));
process.on('unhandledRejection', (reason) => log(`Unhandled rejection: ${reason}`, 'ERROR'));
