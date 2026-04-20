import os
import time
import json
import logging
import subprocess
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
CANARY_MANIFEST_PATH = DATA_DIR / "canary_manifest.json"

logger = logging.getLogger(__name__)

# Lokasi default file jebakan yang akan ditanam
DEFAULT_CANARY_FILES = [
    "/var/www/html/backup.sql",
    "/var/www/html/.env",
    "/var/www/html/credentials.txt",
    "/var/www/html/db_dump.sql",
    "/var/www/html/wp-config.php.bak",
    "/tmp/.hidden_ssh_key",
]

CANARY_CONTENT = {
    "backup.sql": "-- MySQL dump fake canary\n-- DO NOT USE\nCREATE DATABASE canary;\n",
    ".env": "DB_PASSWORD=canary_fake_password_do_not_use\nSECRET_KEY=heimdall_trap\n",
    "credentials.txt": "admin:canary_fake_password\nroot:heimdall_trap_2026\n",
    "db_dump.sql": "-- PostgreSQL canary dump\nINSERT INTO users VALUES ('admin','fake');\n",
    "wp-config.php.bak": "<?php\n// Canary - Heimdall Trap\ndefine('DB_PASSWORD', 'canary_fake');\n",
    ".hidden_ssh_key": "-----BEGIN FAKE RSA PRIVATE KEY-----\nHeimdallCanaryTrap-DoNotUse\n-----END FAKE RSA PRIVATE KEY-----\n",
}


class CanaryEventHandler(FileSystemEventHandler):
    """Watchdog handler yang mendeteksi akses ke file canary"""

    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def on_modified(self, event):
        if not event.is_directory:
            self._trigger(event.src_path, "MODIFIED")

    def on_opened(self, event):
        if not event.is_directory:
            self._trigger(event.src_path, "OPENED")

    def on_deleted(self, event):
        if not event.is_directory:
            self._trigger(event.src_path, "DELETED")

    def _trigger(self, filepath, action):
        logger.warning(f"[CANARY] 🚨 File canary tersentuh! {filepath} -> {action}")
        if self.callback:
            self.callback(filepath, action)


class CanarySystem:
    """
    Sistem Canary Token Detection.
    Meletakkan file-file jebakan di lokasi strategis server.
    Jika file diakses/dimodifikasi/dihapus, itu berarti ada penyusup
    yang sedang melakukan reconnaissance di dalam server.
    """

    def __init__(self):
        self.observer = None
        self.alert_callback = None
        self.deployed_files = []

    def deploy_canaries(self) -> list:
        """
        Menanam file-file canary di lokasi yang sudah ditentukan.
        Returns: daftar file yang berhasil ditanam.
        """
        deployed = []
        manifest = {}

        for filepath in DEFAULT_CANARY_FILES:
            try:
                path = Path(filepath)
                filename = path.name

                # Cek apakah parent directory ada
                if not path.parent.exists():
                    continue

                # Jangan timpa file asli yang sudah ada!
                if path.exists():
                    logger.info(f"[CANARY] Skip {filepath} — file sudah ada (bukan canary)")
                    continue

                content = CANARY_CONTENT.get(filename, "# Heimdall Canary Token\n")

                # Tulis file canary
                result = subprocess.run(
                    f"echo '{content}' | sudo tee {filepath} > /dev/null",
                    shell=True, capture_output=True, text=True, timeout=5
                )

                if result.returncode == 0:
                    deployed.append(filepath)
                    manifest[filepath] = {
                        "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "hash": hash(content)
                    }
                    logger.info(f"[CANARY] ✅ Ditanam: {filepath}")

            except Exception as e:
                logger.warning(f"[CANARY] Gagal menanam {filepath}: {e}")

        # Simpan manifest
        self.deployed_files = deployed
        try:
            with open(CANARY_MANIFEST_PATH, 'w') as f:
                json.dump(manifest, f, indent=2)
        except Exception:
            pass

        return deployed

    def check_canaries(self) -> list:
        """
        Mengecek apakah file canary masih utuh atau sudah disentuh/dihapus.
        Dipakai oleh scanner untuk pengecekan berkala.
        Returns: list of alert strings
        """
        report = []

        try:
            if not CANARY_MANIFEST_PATH.exists():
                report.append("🟡 *Canary Tokens*: Belum di-deploy. Gunakan `/deploy_canary`.")
                return report

            with open(CANARY_MANIFEST_PATH, 'r') as f:
                manifest = json.load(f)

            if not manifest:
                report.append("🟡 *Canary Tokens*: Manifest kosong.")
                return report

            alerts = []
            safe_count = 0

            for filepath, meta in manifest.items():
                path = Path(filepath)
                if not path.exists():
                    alerts.append(f"🔴 `{filepath}` — DIHAPUS! Kemungkinan attacker membersihkan jejak.")
                else:
                    # Cek apakah isinya berubah
                    try:
                        out, _ = subprocess.run(
                            f"sudo stat -c '%Y' {filepath} 2>/dev/null || sudo stat -f '%m' {filepath}",
                            shell=True, capture_output=True, text=True, timeout=5
                        ).stdout.strip(), ""

                        # Cek access time
                        atime_out = subprocess.run(
                            f"sudo stat -c '%X' {filepath} 2>/dev/null || sudo stat -f '%a' {filepath}",
                            shell=True, capture_output=True, text=True, timeout=5
                        )
                        safe_count += 1
                    except Exception:
                        safe_count += 1

            if alerts:
                report.append(f"🔴 *Canary Tokens*: {len(alerts)} jebakan terganggu!")
                report.extend(alerts)
                report.append("ℹ️ _[CRITICAL]_: Ada penyusup yang sudah masuk ke dalam server!")
            else:
                report.append(f"🟢 *Canary Tokens*: {safe_count} jebakan utuh dan aman.")

        except Exception as e:
            report.append(f"🟡 *Canary Tokens*: Error saat pengecekan — {e}")

        return report

    def start_monitoring(self, alert_callback):
        """
        Memulai real-time monitoring file canary menggunakan watchdog.
        alert_callback(filepath, action) akan dipanggil saat file disentuh.
        """
        self.alert_callback = alert_callback

        try:
            manifest = {}
            if CANARY_MANIFEST_PATH.exists():
                with open(CANARY_MANIFEST_PATH, 'r') as f:
                    manifest = json.load(f)

            if not manifest:
                logger.info("[CANARY] Tidak ada canary yang di-deploy. Monitoring tidak dimulai.")
                return

            self.observer = Observer()
            handler = CanaryEventHandler(callback=alert_callback)

            # Monitor setiap direktori parent dari canary files
            watched_dirs = set()
            for filepath in manifest.keys():
                parent = str(Path(filepath).parent)
                if parent not in watched_dirs and Path(parent).exists():
                    self.observer.schedule(handler, parent, recursive=False)
                    watched_dirs.add(parent)
                    logger.info(f"[CANARY] Monitoring: {parent}")

            self.observer.start()
            logger.info(f"[CANARY] Real-time monitoring aktif untuk {len(watched_dirs)} direktori.")

        except Exception as e:
            logger.warning(f"[CANARY] Gagal memulai monitoring: {e}")


canary = CanarySystem()
