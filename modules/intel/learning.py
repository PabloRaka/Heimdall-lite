import json
import time
import logging
from collections import Counter
from pathlib import Path
from modules.core.memory import LTM, GM, DB_PATH, GM_PATH

logger = logging.getLogger(__name__)

# Konfigurasi threshold untuk adaptive learning
LEARNING_THRESHOLD = 3       # Berapa kali pattern muncul sebelum dipelajari
LEARNING_WINDOW_DAYS = 30    # Window waktu analisis (hari)


class AdaptiveLearning:
    """
    Modul Adaptive Learning.
    Menganalisis riwayat insiden di LTM untuk secara otomatis
    menambahkan pattern serangan baru ke Global Memory (GM).
    
    Semakin lama Heimdall berjalan, semakin pintar deteksinya.
    """

    @classmethod
    def learn_from_incidents(cls) -> dict:
        """
        Menganalisis semua insiden untuk menemukan pattern berulang.
        Returns: dict berisi new_rules yang ditambahkan.
        """
        logger.info("[LEARNING] Memulai adaptive learning dari insiden...")
        
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Ambil insiden dalam window waktu tertentu
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%S",
                               time.localtime(time.time() - LEARNING_WINDOW_DAYS * 86400))

        cursor.execute("""
            SELECT ip, threat_type, action, reason 
            FROM incidents 
            WHERE timestamp >= ? AND action LIKE '%BLOCK%'
        """, (cutoff,))
        incidents = [dict(row) for row in cursor.fetchall()]
        conn.close()

        if not incidents:
            return {"learned_ips": 0, "learned_paths": 0, "total_analyzed": 0}

        # ── Analisis 1: IP yang berulang kali diblokir ──
        ip_counter = Counter(inc["ip"] for inc in incidents)
        repeat_offenders = [ip for ip, count in ip_counter.items() if count >= LEARNING_THRESHOLD]

        # ── Analisis 2: Path yang berulang kali muncul di reason ──
        path_counter = Counter()
        for inc in incidents:
            reason = inc.get("reason", "")
            # Ekstrak path dari reason (e.g., "Honeypot trap: accessed /wp-login.php")
            for token in reason.split():
                if token.startswith("/") and len(token) > 1:
                    path_counter[token] += 1

        frequent_paths = [path for path, count in path_counter.items() if count >= LEARNING_THRESHOLD]

        # ── Update Global Memory ──
        new_ips = 0
        new_paths = 0

        try:
            rules = {}
            if GM_PATH.exists():
                with open(GM_PATH, 'r') as f:
                    rules = json.load(f)

            current_ips = set(rules.get("known_malicious_ips", []))
            current_paths = set(rules.get("blacklist_paths", []))

            # Tambah IP baru
            for ip in repeat_offenders:
                if ip not in current_ips:
                    current_ips.add(ip)
                    new_ips += 1
                    logger.info(f"[LEARNING] 🧠 IP baru ditambahkan ke GM: {ip}")

            # Tambah path baru
            for path in frequent_paths:
                if path not in current_paths:
                    current_paths.add(path)
                    new_paths += 1
                    logger.info(f"[LEARNING] 🧠 Path baru ditambahkan ke GM: {path}")

            if new_ips > 0 or new_paths > 0:
                rules["known_malicious_ips"] = list(current_ips)
                rules["blacklist_paths"] = list(current_paths)
                rules["last_learning_update"] = time.strftime("%Y-%m-%dT%H:%M:%S")

                with open(GM_PATH, 'w') as f:
                    json.dump(rules, f, indent=2)

                # Invalidate GM cache
                import modules.core.memory as mem
                mem._gm_cache = None

                logger.info(f"[LEARNING] ✅ GM diperbarui: +{new_ips} IP, +{new_paths} paths")

        except Exception as e:
            logger.warning(f"[LEARNING] Error saat update GM: {e}")

        return {
            "learned_ips": new_ips,
            "learned_paths": new_paths,
            "total_analyzed": len(incidents),
            "repeat_offender_ips": repeat_offenders[:20],
            "frequent_paths": frequent_paths[:20]
        }

    @classmethod
    def format_report(cls) -> str:
        """Format laporan learning untuk Telegram"""
        result = cls.learn_from_incidents()

        report = ["🧠 *ADAPTIVE LEARNING REPORT*\n"]
        report.append(f"Insiden dianalisis: {result['total_analyzed']}")
        report.append(f"IP baru dipelajari: {result['learned_ips']}")
        report.append(f"Path baru dipelajari: {result['learned_paths']}")

        if result.get("repeat_offender_ips"):
            ips = ", ".join([f"`{ip}`" for ip in result["repeat_offender_ips"][:10]])
            report.append(f"\n*Repeat Offender IPs:* {ips}")

        if result.get("frequent_paths"):
            paths = ", ".join([f"`{p}`" for p in result["frequent_paths"][:10]])
            report.append(f"*Frequent Attack Paths:* {paths}")

        if result["learned_ips"] == 0 and result["learned_paths"] == 0:
            report.append("\nℹ️ Tidak ada rule baru yang perlu ditambahkan. GM sudah up-to-date.")
        else:
            report.append(f"\n✅ Global Memory telah diperbarui secara otomatis.")

        report.append(f"\n🕐 _{time.strftime('%Y-%m-%d %H:%M:%S')}_")
        return "\n".join(report)


adaptive_learning = AdaptiveLearning()
