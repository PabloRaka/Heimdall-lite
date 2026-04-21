import os
import hashlib
import shutil
import time
import logging
import subprocess
import sqlite3
from pathlib import Path
from modules.core.memory import DB_PATH
from modules.core.i18n import i18n

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
BACKUP_DIR = BASE_DIR / "data" / "backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────
# KONFIGURASI SELF-HEALING
# ─────────────────────────────────────────────

# File kritis yang akan di-backup dan di-monitor
# Format: filepath -> service yang harus di-restart setelah restore
CRITICAL_FILES = {
    "/etc/ssh/sshd_config":       "sshd",
    "/etc/nginx/nginx.conf":      "nginx",
    "/etc/apache2/apache2.conf":  "apache2",
    "/etc/crontab":               "cron",
    "/etc/hosts":                 None,      # Tidak perlu restart
    "/etc/sudoers":               None,
}

# File yang TERLALU SENSITIF untuk auto-restore
# Hanya alert CRITICAL tanpa restore (karena admin mungkin sah menambah user)
ALERT_ONLY_FILES = {
    "/etc/passwd",
    "/etc/shadow",
}


def _sha256_file(filepath: str) -> str:
    """Hitung SHA-256 hash dari file."""
    try:
        result = subprocess.run(
            f"sudo sha256sum {filepath}",
            shell=True, capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split()[0]
    except Exception:
        pass
    return ""


def _read_file_content(filepath: str) -> bytes:
    """Baca konten file menggunakan sudo."""
    try:
        result = subprocess.run(
            f"sudo cat {filepath}",
            shell=True, capture_output=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass
    return b""


def _write_file_content(filepath: str, content: bytes) -> bool:
    """Tulis konten file menggunakan sudo."""
    try:
        # Tulis ke temp file dulu, lalu move (atomic write)
        temp_path = f"/tmp/heimdall_restore_{int(time.time())}"
        with open(temp_path, "wb") as f:
            f.write(content)

        result = subprocess.run(
            f"sudo cp {temp_path} {filepath}",
            shell=True, capture_output=True, timeout=10
        )

        # Bersihkan temp file
        try:
            os.remove(temp_path)
        except Exception:
            pass

        return result.returncode == 0
    except Exception as e:
        logger.error(f"[SELF-HEAL] Write error for {filepath}: {e}")
        return False


class SelfHealer:
    """
    Auto-Rollback & Self-Healing Module.

    Membuat backup dari file-file kritis saat pertama kali dijalankan.
    Ketika mendeteksi perubahan (via hash comparison), secara otomatis:
    1. Menyimpan file yang diubah sebagai evidensi forensic
    2. Me-restore file dari backup
    3. Me-restart service terkait
    4. Alert admin via Telegram
    """

    def create_backup_snapshot(self) -> dict:
        """
        Buat backup snapshot dari semua file kritis.
        Returns: dict berisi hasil operasi per file.
        """
        logger.info("[SELF-HEAL] Creating backup snapshot...")
        results = {}

        all_files = list(CRITICAL_FILES.keys()) + list(ALERT_ONLY_FILES)

        for filepath in all_files:
            if not Path(filepath).exists():
                # Cek via sudo
                out = subprocess.run(
                    f"sudo test -f {filepath} && echo EXISTS",
                    shell=True, capture_output=True, text=True, timeout=5
                )
                if "EXISTS" not in (out.stdout or ""):
                    results[filepath] = "SKIPPED (not found)"
                    continue

            # Baca konten
            content = _read_file_content(filepath)
            if not content:
                results[filepath] = "SKIPPED (cannot read)"
                continue

            # Hash
            file_hash = hashlib.sha256(content).hexdigest()

            # Simpan backup
            safe_name = filepath.replace("/", "_").lstrip("_")
            backup_path = BACKUP_DIR / f"{safe_name}.bak"

            try:
                with open(backup_path, "wb") as f:
                    f.write(content)

                # Simpan metadata hash
                meta_path = BACKUP_DIR / f"{safe_name}.meta"
                with open(meta_path, "w") as f:
                    f.write(f"{file_hash}\n{time.strftime('%Y-%m-%dT%H:%M:%S')}\n")

                results[filepath] = f"OK (hash: {file_hash[:12]}...)"
                logger.info(f"[SELF-HEAL] ✅ Backed up: {filepath}")

            except Exception as e:
                results[filepath] = f"ERROR: {e}"
                logger.error(f"[SELF-HEAL] Backup error for {filepath}: {e}")

        return results

    def check_and_heal(self) -> list:
        """
        Membandingkan file saat ini dengan backup.
        Jika berbeda: restore file (kecuali ALERT_ONLY), restart service, alert admin.
        Returns: list of action descriptions.
        """
        logger.info("[SELF-HEAL] Running integrity check and heal...")
        actions = []

        all_files = list(CRITICAL_FILES.keys()) + list(ALERT_ONLY_FILES)

        for filepath in all_files:
            safe_name = filepath.replace("/", "_").lstrip("_")
            backup_path = BACKUP_DIR / f"{safe_name}.bak"
            meta_path = BACKUP_DIR / f"{safe_name}.meta"

            # Cek apakah ada backup
            if not backup_path.exists() or not meta_path.exists():
                continue

            # Baca hash dari backup
            try:
                with open(meta_path, "r") as f:
                    lines = f.readlines()
                backup_hash = lines[0].strip()
            except Exception:
                continue

            # Cek apakah file masih ada di sistem
            out = subprocess.run(
                f"sudo test -f {filepath} && echo EXISTS",
                shell=True, capture_output=True, text=True, timeout=5
            )
            if "EXISTS" not in (out.stdout or ""):
                # File dihapus — ini SANGAT mencurigakan
                actions.append({
                    "filepath": filepath,
                    "action": "ALERT_DELETED",
                    "detail": f"Critical file DELETED: {filepath}",
                })
                self._log_healing(filepath, "ALERT_DELETED", backup_hash, "FILE_MISSING")
                continue

            # Hash saat ini
            current_hash = _sha256_file(filepath)
            if not current_hash:
                continue

            # Bandingkan
            if current_hash == backup_hash:
                continue  # File tidak berubah, aman

            # ═══ FILE BERUBAH! ═══
            logger.warning(f"[SELF-HEAL] 🔴 CHANGE DETECTED: {filepath}")

            if filepath in ALERT_ONLY_FILES:
                # Terlalu sensitif untuk auto-restore — hanya alert
                actions.append({
                    "filepath": filepath,
                    "action": "ALERT_ONLY",
                    "detail": f"CRITICAL file changed: {filepath} (auto-restore disabled for safety)",
                    "old_hash": backup_hash[:12],
                    "new_hash": current_hash[:12],
                })
                self._log_healing(filepath, "ALERT_ONLY", backup_hash, current_hash)

            else:
                # Auto-restore dari backup
                try:
                    # 1. Simpan file yang berubah sebagai evidensi
                    evidence_content = _read_file_content(filepath)
                    evidence_path = BACKUP_DIR / f"{safe_name}.evidence.{int(time.time())}"
                    with open(evidence_path, "wb") as f:
                        f.write(evidence_content)

                    # 2. Restore dari backup
                    with open(backup_path, "rb") as f:
                        backup_content = f.read()

                    success = _write_file_content(filepath, backup_content)

                    if success:
                        # 3. Restart service jika ada
                        service = CRITICAL_FILES.get(filepath)
                        restart_msg = ""
                        if service:
                            restart_result = subprocess.run(
                                f"sudo systemctl restart {service}",
                                shell=True, capture_output=True, timeout=15
                            )
                            restart_msg = (
                                f" + {service} restarted"
                                if restart_result.returncode == 0
                                else f" + {service} restart FAILED"
                            )

                        actions.append({
                            "filepath": filepath,
                            "action": "RESTORED",
                            "detail": f"Auto-restored: {filepath}{restart_msg}",
                            "old_hash": backup_hash[:12],
                            "new_hash": current_hash[:12],
                        })
                        self._log_healing(filepath, "RESTORED", backup_hash, current_hash)
                        logger.info(f"[SELF-HEAL] ✅ RESTORED: {filepath}{restart_msg}")

                    else:
                        actions.append({
                            "filepath": filepath,
                            "action": "RESTORE_FAILED",
                            "detail": f"Failed to restore: {filepath}",
                        })
                        self._log_healing(filepath, "RESTORE_FAILED", backup_hash, current_hash)

                except Exception as e:
                    actions.append({
                        "filepath": filepath,
                        "action": "ERROR",
                        "detail": f"Self-heal error for {filepath}: {e}",
                    })
                    logger.error(f"[SELF-HEAL] Error: {e}")

        return actions

    def _log_healing(self, filepath: str, action: str, old_hash: str, new_hash: str):
        """Log aksi self-healing ke database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO healing_log (filepath, action, old_hash, new_hash, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (filepath, action, old_hash, new_hash, time.strftime("%Y-%m-%dT%H:%M:%S")),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"[SELF-HEAL] DB logging error: {e}")

    def format_backup_report(self) -> str:
        """Format laporan backup snapshot untuk Telegram."""
        results = self.create_backup_snapshot()

        report = [f"{i18n.t('heal_backup_title')}\n"]
        ok_count = 0
        skip_count = 0

        for filepath, status in results.items():
            if status.startswith("OK"):
                report.append(f"  ✅ `{filepath}`")
                ok_count += 1
            else:
                report.append(f"  ⏭️ `{filepath}` — {status}")
                skip_count += 1

        report.append(f"\n{i18n.t('heal_backup_summary', ok=ok_count, skipped=skip_count)}")
        report.append(f"🕐 _{time.strftime('%Y-%m-%d %H:%M:%S')}_")

        return "\n".join(report)

    def format_heal_report(self) -> str:
        """Format laporan self-heal check untuk Telegram."""
        actions = self.check_and_heal()

        if not actions:
            return i18n.t("heal_all_ok")

        report = [f"{i18n.t('heal_title')}\n"]

        for a in actions:
            action = a["action"]
            filepath = a["filepath"]
            detail = a["detail"]

            if action == "RESTORED":
                report.append(f"🔄 `{filepath}`\n  {i18n.t('heal_restored')}")
                report.append(f"  Hash: {a.get('old_hash', '?')}... → {a.get('new_hash', '?')}...")
            elif action == "ALERT_ONLY":
                report.append(f"🔴 `{filepath}`\n  {i18n.t('heal_alert_only')}")
                report.append(f"  Hash: {a.get('old_hash', '?')}... → {a.get('new_hash', '?')}...")
            elif action == "ALERT_DELETED":
                report.append(f"🔴 `{filepath}`\n  {i18n.t('heal_deleted')}")
            else:
                report.append(f"❌ `{filepath}`\n  {detail}")

        report.append(f"\n🕐 _{time.strftime('%Y-%m-%d %H:%M:%S')}_")

        return "\n".join(report)


# Singleton Instance
self_healer = SelfHealer()
