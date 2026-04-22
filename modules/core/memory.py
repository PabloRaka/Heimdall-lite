import sqlite3
import json
import time
import threading
import ipaddress
from pathlib import Path

# Paths Setup
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "security_archive.db"
STM_PATH = DATA_DIR / "stm_context.json"
GM_PATH = DATA_DIR / "global_rules.json"

_stm_lock = threading.Lock()
_db_lock = threading.Lock()
_gm_cache = None

# Inisialisasi file STM jika belum ada
if not STM_PATH.exists():
    with open(STM_PATH, 'w') as f:
        json.dump({}, f)

class STM:
    """Short-Term Memory - Runtime Context (JSON file)"""
    
    @classmethod
    def _read_stm(cls) -> dict:
        try:
            with _stm_lock:
                with open(STM_PATH, 'r') as f:
                    data = json.load(f)
            # Hapus entri yang sudah lebih dari 60 menit
            now = time.time()
            cutoff = 3600  # 60 menit
            cleaned = {
                ip: v for ip, v in data.items()
                if (now - time.mktime(time.strptime(v["last_seen"], "%Y-%m-%dT%H:%M:%S"))) < cutoff
            }
            return cleaned
        except Exception:
            return {}

    @classmethod
    def _write_stm(cls, data: dict):
        with _stm_lock:
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
    _incident_schema_checked = False
    
    @classmethod
    def _get_db_connection(cls):
        conn = sqlite3.connect(DB_PATH)
        cls._ensure_incident_schema(conn)
        return conn

    @classmethod
    def _ensure_incident_schema(cls, conn):
        if cls._incident_schema_checked:
            return

        with _db_lock:
            if cls._incident_schema_checked:
                return

            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(incidents)")
            existing_columns = {row[1] for row in cursor.fetchall()}

            geo_columns = {
                "country": "TEXT",
                "country_code": "TEXT",
                "region": "TEXT",
                "city": "TEXT",
                "isp": "TEXT",
            }
            for column, column_type in geo_columns.items():
                if column not in existing_columns:
                    cursor.execute(
                        f"ALTER TABLE incidents ADD COLUMN {column} {column_type}"
                    )

            conn.commit()
            cls._incident_schema_checked = True

    @staticmethod
    def _is_public_ip(ip: str) -> bool:
        try:
            parsed = ipaddress.ip_address(ip)
            return parsed.is_global
        except ValueError:
            return False

    @classmethod
    def _get_geo_context(cls, ip: str) -> dict:
        if not cls._is_public_ip(ip):
            return {
                "country": "Unknown",
                "country_code": "??",
                "region": "",
                "city": "",
                "isp": "",
            }

        try:
            from modules.intel.threat_intel import threat_intel

            intel = threat_intel.get_geoip(ip)
            return {
                "country": intel.get("country", "Unknown"),
                "country_code": intel.get("countryCode", "??"),
                "region": intel.get("region", ""),
                "city": intel.get("city", ""),
                "isp": intel.get("isp", ""),
            }
        except Exception:
            return {
                "country": "Unknown",
                "country_code": "??",
                "region": "",
                "city": "",
                "isp": "",
            }

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
        geo = cls._get_geo_context(ip)
        cursor.execute("""
            INSERT INTO incidents (
                ip, timestamp, threat_type, action, reason, confidence,
                country, country_code, region, city, isp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip, now, threat_type, action, reason, confidence,
            geo["country"], geo["country_code"], geo["region"], geo["city"], geo["isp"],
        ))
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

    @classmethod
    def is_false_positive(cls, ip: str) -> bool:
        conn = cls._get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM false_positives WHERE ip = ?", (ip,))
        result = cursor.fetchone()
        conn.close()
        return bool(result)


class GM:
    """Global Memory - Static Rules (JSON file)"""
    
    @classmethod
    def _get_rules(cls) -> dict:
        global _gm_cache
        if _gm_cache is None:
            try:
                with open(GM_PATH, 'r') as f:
                    _gm_cache = json.load(f)
            except Exception:
                _gm_cache = {
                    "blacklist_paths": [],
                    "forbidden_usernames": [],
                    "known_malicious_ips": []
                }
        return _gm_cache

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
