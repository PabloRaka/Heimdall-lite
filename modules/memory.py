import sqlite3
import json
import time
from pathlib import Path

# Paths Setup
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "security_archive.db"
STM_PATH = DATA_DIR / "stm_context.json"
GM_PATH = DATA_DIR / "global_rules.json"

# Inisialisasi file STM jika belum ada
if not STM_PATH.exists():
    with open(STM_PATH, 'w') as f:
        json.dump({}, f)

class STM:
    """Short-Term Memory - Runtime Context (JSON file)"""
    
    @classmethod
    def _read_stm(cls) -> dict:
        try:
            with open(STM_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            return {}

    @classmethod
    def _write_stm(cls, data: dict):
        with open(STM_PATH, 'w') as f:
            json.dump(data, f, indent=2)

    @classmethod
    def get(cls, ip: str) -> dict:
        stm = cls._read_stm()
        return stm.get(ip, None)

    @classmethod
    def set(cls, ip: str, data: dict):
        stm = cls._read_stm()
        stm[ip] = data
        cls._write_stm(stm)

    @classmethod
    def increment(cls, ip: str, failed_attempts=1, path=None, service=None):
        stm = cls._read_stm()
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        
        if ip not in stm:
            stm[ip] = {
                "failed_attempts": 0,
                "last_seen": now,
                "paths_accessed": [],
                "service": service or "unknown"
            }
            
        stm[ip]["failed_attempts"] += failed_attempts
        stm[ip]["last_seen"] = now
        
        if service:
            stm[ip]["service"] = service
            
        if path and path not in stm[ip]["paths_accessed"]:
            stm[ip]["paths_accessed"].append(path)
            
        cls._write_stm(stm)

    @classmethod
    def flush(cls, ip: str):
        stm = cls._read_stm()
        if ip in stm:
            del stm[ip]
            cls._write_stm(stm)


class LTM:
    """Long-Term Memory - SQLite DB"""
    
    @classmethod
    def _get_db_connection(cls):
        return sqlite3.connect(DB_PATH)

    @classmethod
    def is_whitelisted(cls, ip: str) -> bool:
        conn = cls._get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM trusted_devices WHERE ip = ?", (ip,))
        result = cursor.fetchone()
        conn.close()
        return bool(result)

    @classmethod
    def add_whitelist(cls, ip: str, label: str = "Manual Whitelist", added_by: str = "admin"):
        conn = cls._get_db_connection()
        cursor = conn.cursor()
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        cursor.execute("""
            INSERT OR REPLACE INTO trusted_devices (ip, label, added_by, added_at)
            VALUES (?, ?, ?, ?)
        """, (ip, label, added_by, now))
        conn.commit()
        conn.close()

    @classmethod
    def get_incident_history(cls, ip: str, limit=5) -> list:
        conn = cls._get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE ip = ? ORDER BY id DESC LIMIT ?", (ip, limit))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    @classmethod
    def add_incident(cls, ip: str, threat_type: str, action: str, reason: str, confidence: float):
        conn = cls._get_db_connection()
        cursor = conn.cursor()
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        cursor.execute("""
            INSERT INTO incidents (ip, timestamp, threat_type, action, reason, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ip, now, threat_type, action, reason, confidence))
        conn.commit()
        conn.close()

    @classmethod
    def add_false_positive(cls, ip: str, note: str = ""):
        conn = cls._get_db_connection()
        cursor = conn.cursor()
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        # Menggunakan INSERT OR REPLACE karena ip adalah PRIMARY KEY
        cursor.execute("""
            INSERT OR REPLACE INTO false_positives (ip, unblocked_at, note)
            VALUES (?, ?, ?)
        """, (ip, now, note))
        conn.commit()
        conn.close()


class GM:
    """Global Memory - Static Rules (JSON file)"""
    
    @classmethod
    def _get_rules(cls) -> dict:
        try:
            with open(GM_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            return {
                "blacklist_paths": [],
                "forbidden_usernames": [],
                "known_malicious_ips": []
            }

    @classmethod
    def is_blacklisted_path(cls, path: str) -> bool:
        rules = cls._get_rules()
        return path in rules.get("blacklist_paths", [])

    @classmethod
    def is_forbidden_user(cls, user: str) -> bool:
        rules = cls._get_rules()
        return user in rules.get("forbidden_usernames", [])

    @classmethod
    def is_known_bad_ip(cls, ip: str) -> bool:
        rules = cls._get_rules()
        return ip in rules.get("known_malicious_ips", [])
