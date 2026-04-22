import sqlite3
from pathlib import Path

# Base directory (micro-soc/)
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "security_archive.db"

def init_db():
    """Inisialisasi database SQLite (LTM - Long Term Memory)"""
    # Pastikan direktori data sudah ada
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    print(f"Menginisialisasi database di {DB_PATH}...")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Tabel 1: incidents - Rekam jejak insiden yang sudah terjadi
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ip          TEXT NOT NULL,
        timestamp   TEXT NOT NULL,
        threat_type TEXT,
        action      TEXT,
        reason      TEXT,
        confidence  REAL,
        country     TEXT,
        country_code TEXT,
        region      TEXT,
        city        TEXT,
        isp         TEXT
    )
    """)

    # Tabel 2: trusted_devices - Whitelist (kebal dari auto-block)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS trusted_devices (
        ip          TEXT PRIMARY KEY,
        label       TEXT,
        added_by    TEXT,
        added_at    TEXT
    )
    """)

    # Tabel 3: false_positives - IP yang pernah salah diblokir
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS false_positives (
        ip          TEXT PRIMARY KEY,
        unblocked_at TEXT,
        note        TEXT
    )
    """)

    # Tabel 4: daily_summary - Ringkasan harian dari Autodream
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS daily_summary (
        date        TEXT PRIMARY KEY,
        summary     TEXT,
        top_threats TEXT,
        total_blocks INTEGER
    )
    """)

    # Tabel 5: settings - Konfigurasi global (termasuk bahasa laporan)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key     TEXT PRIMARY KEY,
        value   TEXT NOT NULL
    )
    """)

    # Isi default language: English
    cursor.execute("""
    INSERT OR IGNORE INTO settings (key, value) VALUES ('language', 'en')
    """)

    # Isi default safe_mode: true (aman untuk user baru)
    cursor.execute("""
    INSERT OR IGNORE INTO settings (key, value) VALUES ('safe_mode', 'true')
    """)

    # Tabel 6: honeypot_logs - Log koneksi ke port honeypot
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS honeypot_logs (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        ip        TEXT NOT NULL,
        port      INTEGER,
        service   TEXT,
        payload   TEXT,
        timestamp TEXT NOT NULL
    )
    """)

    # Tabel 7: healing_log - Log aksi self-healing / auto-rollback
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS healing_log (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        filepath     TEXT NOT NULL,
        action       TEXT NOT NULL,
        old_hash     TEXT,
        new_hash     TEXT,
        timestamp    TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()
    
    print("✅ Inisialisasi selesai! Tabel berhasil dibuat.")

if __name__ == "__main__":
    init_db()
