"""
Safe Mode — Global protection toggle untuk Heimdall-lite.

Saat Safe Mode AKTIF:
  - Semua aksi destruktif (block IP, kill proses, restore file, remediate)
    hanya menjadi ALERT-ONLY (tidak dieksekusi).
  - Berguna untuk trust awal user, observasi, atau debugging.

Saat Safe Mode NONAKTIF:
  - Semua aksi berjalan otomatis seperti biasa.

Konfigurasi:
  1. Via .env:  SAFE_MODE=true
  2. Via Telegram:  /safemode  (toggle on/off)
  3. Via DB: settings table, key='safe_mode', value='true'/'false'

Prioritas: DB > .env > default (true)
"""

import os
import sqlite3
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "security_archive.db"


class SafeMode:
    """
    Singleton yang mengelola status Safe Mode.
    Thread-safe untuk dibaca dari pipeline manapun.
    """

    def __init__(self):
        self._enabled: bool = True  # Default: Safe Mode ON (aman untuk user baru)
        self._load()

    def _load(self):
        """
        Muat status safe_mode.
        Prioritas: DB > .env > default (true).
        """
        # 1. Coba baca dari DB
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings WHERE key = 'safe_mode'")
            row = cursor.fetchone()
            conn.close()

            if row:
                self._enabled = row[0].lower() in ("true", "1", "yes")
                logger.info(f"[SAFE_MODE] Loaded from DB: {'ON' if self._enabled else 'OFF'}")
                return
        except Exception as e:
            logger.debug(f"[SAFE_MODE] DB read failed: {e}")

        # 2. Fallback ke .env
        env_val = os.getenv("SAFE_MODE", "").strip().lower()
        if env_val:
            self._enabled = env_val in ("true", "1", "yes")
            logger.info(f"[SAFE_MODE] Loaded from .env: {'ON' if self._enabled else 'OFF'}")
            return

        # 3. Default: ON (aman)
        self._enabled = True
        logger.info("[SAFE_MODE] Default: ON (safe mode aktif)")

    @property
    def is_enabled(self) -> bool:
        """Cek apakah Safe Mode sedang aktif."""
        return self._enabled

    def toggle(self) -> bool:
        """
        Toggle safe mode dan simpan ke DB.
        Returns: status baru (True = ON, False = OFF).
        """
        self._enabled = not self._enabled
        self._save_to_db()
        logger.info(f"[SAFE_MODE] Toggled to: {'ON' if self._enabled else 'OFF'}")
        return self._enabled

    def set(self, enabled: bool):
        """Set safe mode secara eksplisit dan simpan ke DB."""
        self._enabled = enabled
        self._save_to_db()
        logger.info(f"[SAFE_MODE] Set to: {'ON' if self._enabled else 'OFF'}")

    def _save_to_db(self):
        """Simpan status ke tabel settings."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('safe_mode', ?)",
                ("true" if self._enabled else "false",),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"[SAFE_MODE] DB write failed: {e}")

    def check(self, action_name: str) -> bool:
        """
        Cek apakah aksi boleh dieksekusi.

        Args:
            action_name: Nama aksi (untuk logging), misal "BLOCK_UFW", "EDR_KILL"

        Returns:
            True  = aksi BOLEH dieksekusi (safe mode OFF)
            False = aksi DIBLOKIR (safe mode ON, hanya alert)
        """
        if self._enabled:
            logger.info(f"[SAFE_MODE] ⚠️ Blocked action: {action_name} (safe mode ON)")
            return False
        return True


# Singleton Instance
safe_mode = SafeMode()
