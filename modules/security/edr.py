import os
import signal
import time
import logging
import threading
import sqlite3
from pathlib import Path
from modules.core.memory import LTM, DB_PATH
from modules.core.i18n import i18n

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# KONFIGURASI EDR
# ─────────────────────────────────────────────

# Interval scan (detik)
SCAN_INTERVAL = 5

# User-user web server yang TIDAK BOLEH menjalankan shell/tools
RESTRICTED_USERS = {"www-data", "nginx", "apache", "nobody"}

# Binary yang dianggap berbahaya jika dijalankan oleh restricted users
DANGEROUS_BINARIES = {
    "bash", "sh", "dash", "zsh", "csh", "ksh",           # Shells
    "nc", "ncat", "netcat", "socat",                      # Reverse shell tools
    "python", "python3", "perl", "ruby", "php",           # Script interpreters
    "wget", "curl",                                        # Downloaders
}

# Direktori staging area yang sering dipakai attacker
SUSPICIOUS_EXEC_DIRS = {"/tmp", "/dev/shm", "/var/tmp", "/dev"}

# Pola command line yang mencurigakan (substring matching)
SUSPICIOUS_CMDLINE_PATTERNS = [
    "base64 -d",
    "base64 --decode",
    "/dev/tcp/",
    "| bash",
    "| sh",
    "python -c",
    "perl -e",
    "ruby -e",
    "mkfifo",
    "0<&196",
    "/bin/sh -i",
    "exec 5<>/dev/tcp",
]

# PID whitelist (ditambah saat runtime jika perlu)
# Proses-proses Heimdall sendiri tidak boleh di-kill
WHITELISTED_PIDS = set()


class ProcessMonitor:
    """
    Endpoint Detection & Response (EDR) Module.
    Memantau proses-proses berjalan di server secara real-time.
    Jika mendeteksi proses berbahaya (reverse shell, web shell, post-exploitation),
    langsung SIGKILL dan alert admin.
    """

    def __init__(self):
        self._running = False
        self._thread = None
        self._killed_today = []
        self._lock = threading.Lock()
        # Whitelist PID Heimdall sendiri
        WHITELISTED_PIDS.add(os.getpid())

    def start(self):
        """Mulai monitoring di background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._thread.start()
        logger.info("[EDR] Process Monitor aktif. Scan interval: %ds", SCAN_INTERVAL)

    def stop(self):
        """Hentikan monitoring."""
        self._running = False
        logger.info("[EDR] Process Monitor dihentikan.")

    def _scan_loop(self):
        """Main loop yang berjalan di background."""
        while self._running:
            try:
                self._scan_processes()
            except Exception as e:
                logger.error(f"[EDR] Scan error: {e}")
            time.sleep(SCAN_INTERVAL)

    def _scan_processes(self):
        """Scan /proc untuk mendeteksi proses mencurigakan."""
        try:
            import psutil
        except ImportError:
            logger.error("[EDR] psutil belum terinstall! Jalankan: pip install psutil")
            self._running = False
            return

        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'exe', 'ppid']):
            try:
                info = proc.info
                pid = info['pid']

                # Skip proses Heimdall sendiri & proses sistem
                if pid in WHITELISTED_PIDS or pid <= 2:
                    continue

                username = info.get('username', '') or ''
                name = info.get('name', '') or ''
                cmdline = info.get('cmdline') or []
                exe = info.get('exe', '') or ''
                cmdline_str = ' '.join(cmdline)

                threat = self._check_threat(username, name, exe, cmdline_str)

                if threat:
                    self._respond(proc, info, threat)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def _check_threat(self, username: str, name: str, exe: str, cmdline: str) -> str:
        """
        Cek apakah proses ini merupakan ancaman.
        Returns: deskripsi ancaman, atau None jika aman.
        """
        # Rule 1: Restricted user menjalankan shell/tools
        if username in RESTRICTED_USERS and name in DANGEROUS_BINARIES:
            return f"Restricted user '{username}' running '{name}'"

        # Rule 2: Eksekusi dari staging directory (tempat attacker simpan payload)
        if exe:
            for sus_dir in SUSPICIOUS_EXEC_DIRS:
                if exe.startswith(sus_dir):
                    return f"Execution from suspicious directory: {exe}"

        # Rule 3: Command line patterns mencurigakan
        if cmdline:
            cmdline_lower = cmdline.lower()
            for pattern in SUSPICIOUS_CMDLINE_PATTERNS:
                if pattern in cmdline_lower:
                    return f"Suspicious command pattern: '{pattern}' in '{cmdline[:100]}'"

        return None

    def _respond(self, proc, info: dict, threat: str):
        """Kill proses berbahaya dan alert admin. Di Safe Mode: alert saja."""
        from modules.core.safe_mode import safe_mode

        pid = info['pid']
        username = info.get('username', '?')
        name = info.get('name', '?')
        cmdline = ' '.join(info.get('cmdline') or [])[:200]

        if safe_mode.is_enabled:
            # Safe Mode ON: hanya alert, TIDAK kill
            action = "ALERT_ONLY"
            logger.warning(f"[EDR] ⚠️ SAFE-MODE: Threat detected PID {pid} but NOT killed: {threat}")
        else:
            # Safe Mode OFF: Kill proses — mode langsung (SIGKILL)
            try:
                os.kill(pid, signal.SIGKILL)
                action = "KILLED"
                logger.warning(f"[EDR] 🔴 KILLED PID {pid}: {threat}")
            except PermissionError:
                action = "KILL_FAILED"
                logger.error(f"[EDR] ❌ Cannot kill PID {pid} (permission denied)")
            except ProcessLookupError:
                action = "ALREADY_DEAD"
                logger.info(f"[EDR] PID {pid} already terminated")

        # Record kill
        with self._lock:
            record = {
                "pid": pid,
                "user": username,
                "process": name,
                "cmdline": cmdline,
                "threat": threat,
                "action": action,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._killed_today.append(record)

        # Log ke LTM
        try:
            LTM.add_incident(
                ip="localhost",
                threat_type="EDR_PROCESS",
                action=action,
                reason=f"PID {pid} | User: {username} | {threat}",
                confidence=0.95,
            )
        except Exception:
            pass

    def get_status(self) -> dict:
        """Dapatkan status EDR saat ini."""
        with self._lock:
            today = time.strftime("%Y-%m-%d")
            today_kills = [k for k in self._killed_today if k["timestamp"].startswith(today)]
            return {
                "active": self._running,
                "scan_interval": SCAN_INTERVAL,
                "kills_today": len(today_kills),
                "recent_kills": today_kills[-5:],
            }

    def format_status_report(self) -> str:
        """Format laporan status EDR untuk Telegram."""
        status = self.get_status()

        active_str = "🟢 ACTIVE" if status["active"] else "🔴 INACTIVE"

        report = [f"{i18n.t('edr_title')}\n"]
        report.append(f"{i18n.t('edr_status')}: {active_str}")
        report.append(f"{i18n.t('edr_interval')}: {status['scan_interval']}s")
        report.append(f"{i18n.t('edr_kills_today')}: {status['kills_today']}")

        if status["recent_kills"]:
            report.append(f"\n{i18n.t('edr_recent_title')}")
            for k in status["recent_kills"]:
                report.append(
                    f"  • `{k['timestamp']}` — PID {k['pid']} "
                    f"({k['user']}/{k['process']}) → {k['action']}"
                )
        else:
            report.append(f"\n{i18n.t('edr_no_kills')}")

        return "\n".join(report)

    def format_log_report(self) -> str:
        """Format log detail untuk Telegram."""
        with self._lock:
            if not self._killed_today:
                return i18n.t("edr_log_empty")

            report = [f"{i18n.t('edr_log_title')}\n"]
            for k in self._killed_today[-10:]:
                report.append(
                    f"🔴 `{k['timestamp']}`\n"
                    f"  PID: {k['pid']} | User: {k['user']}\n"
                    f"  Process: {k['process']}\n"
                    f"  Cmd: `{k['cmdline'][:80]}`\n"
                    f"  Threat: {k['threat']}\n"
                    f"  Action: {k['action']}\n"
                )
            return "\n".join(report)


# Singleton Instance
process_monitor = ProcessMonitor()
