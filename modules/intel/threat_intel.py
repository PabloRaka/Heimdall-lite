import os
import requests
import logging
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

logger = logging.getLogger(__name__)


class ThreatIntel:
    """
    Modul Threat Intelligence & GeoIP.
    Menghubungkan Heimdall ke sumber intelijen eksternal:
    - AbuseIPDB: Reputasi IP global (apakah IP sudah dilaporkan ribuan kali?)
    - GeoIP (ip-api.com): Mengetahui negara asal serangan
    """

    # Cache agar tidak query berulang untuk IP yang sama
    _cache = {}

    @classmethod
    def _get_cached(cls, ip: str) -> dict:
        return cls._cache.get(ip)

    @classmethod
    def _set_cached(cls, ip: str, data: dict):
        # Limit cache size agar tidak membengkak
        if len(cls._cache) > 5000:
            cls._cache.clear()
        cls._cache[ip] = data

    # ─────────────────────────────────────────────
    # ABUSEIPDB — Reputasi IP Global
    # ─────────────────────────────────────────────
    @classmethod
    def check_abuseipdb(cls, ip: str) -> dict:
        """
        Mengecek reputasi IP di AbuseIPDB.
        Returns: dict berisi abuse_score (0-100), total_reports, country, is_dangerous
        """
        if not ABUSEIPDB_API_KEY:
            return {"error": "ABUSEIPDB_API_KEY not configured", "is_dangerous": False}

        # Cek cache dulu
        cached = cls._get_cached(f"abuse_{ip}")
        if cached:
            return cached

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90
            }

            res = requests.get(url, headers=headers, params=params, timeout=5)
            res.raise_for_status()
            data = res.json().get("data", {})

            result = {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "??"),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", ""),
                "is_tor": data.get("isTor", False),
                "is_dangerous": data.get("abuseConfidenceScore", 0) >= 50
            }

            cls._set_cached(f"abuse_{ip}", result)
            logger.info(f"[THREAT-INTEL] AbuseIPDB: {ip} -> score={result['abuse_score']}, reports={result['total_reports']}")
            return result

        except Exception as e:
            logger.warning(f"[THREAT-INTEL] AbuseIPDB error: {e}")
            return {"error": str(e), "is_dangerous": False}

    # ─────────────────────────────────────────────
    # GEOIP — Lokasi Geografis IP
    # ─────────────────────────────────────────────
    @classmethod
    def get_geoip(cls, ip: str) -> dict:
        """
        Mendapatkan informasi geolokasi IP menggunakan ip-api.com (gratis, tanpa API key).
        Returns: dict berisi country, countryCode, city, isp, org
        """
        # Cek cache
        cached = cls._get_cached(f"geo_{ip}")
        if cached:
            return cached

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,org,as"
            res = requests.get(url, timeout=5)
            res.raise_for_status()
            data = res.json()

            if data.get("status") == "fail":
                return {"country": "Unknown", "countryCode": "??", "city": "", "isp": "", "org": ""}

            result = {
                "country": data.get("country", "Unknown"),
                "countryCode": data.get("countryCode", "??"),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "as": data.get("as", "")
            }

            cls._set_cached(f"geo_{ip}", result)
            logger.info(f"[THREAT-INTEL] GeoIP: {ip} -> {result['country']} ({result['city']})")
            return result

        except Exception as e:
            logger.warning(f"[THREAT-INTEL] GeoIP error: {e}")
            return {"country": "Unknown", "countryCode": "??", "city": "", "isp": "", "org": ""}

    # ─────────────────────────────────────────────
    # ENRICHMENT — Gabungkan semua data intelijen
    # ─────────────────────────────────────────────
    @classmethod
    def enrich(cls, ip: str) -> dict:
        """
        Menggabungkan seluruh intelijen ke dalam satu paket data.
        Dipakai oleh Brain sebagai context tambahan dalam analisis.
        """
        geo = cls.get_geoip(ip)
        abuse = cls.check_abuseipdb(ip)

        return {
            "ip": ip,
            "country": geo.get("country", "Unknown"),
            "country_code": geo.get("countryCode", "??"),
            "city": geo.get("city", ""),
            "isp": geo.get("isp", ""),
            "abuse_score": abuse.get("abuse_score", 0),
            "total_reports": abuse.get("total_reports", 0),
            "is_tor": abuse.get("is_tor", False),
            "is_dangerous": abuse.get("is_dangerous", False)
        }

    @classmethod
    def format_intel_report(cls, ip: str) -> str:
        """Format human-readable untuk Telegram"""
        data = cls.enrich(ip)
        
        danger = "🔴 BERBAHAYA" if data["is_dangerous"] else "🟢 Aman"
        tor = "⚠️ Ya (TOR Node)" if data["is_tor"] else "Tidak"

        return (
            f"🌐 *Threat Intelligence: `{ip}`*\n"
            f"Negara: {data['country']} ({data['country_code']})\n"
            f"Kota: {data['city'] or '-'}\n"
            f"ISP: {data['isp'] or '-'}\n"
            f"Abuse Score: {data['abuse_score']}/100\n"
            f"Total Reports: {data['total_reports']}\n"
            f"TOR Node: {tor}\n"
            f"Status: {danger}"
        )


threat_intel = ThreatIntel()
