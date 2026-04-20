import time
import logging
from modules.core.memory import LTM, STM

logger = logging.getLogger(__name__)


class ForensicTimeline:
    """
    Modul Forensic Timeline Generator.
    Menghasilkan kronologi serangan lengkap untuk suatu IP berdasarkan
    data dari LTM (incidents DB) dan STM (real-time context).
    """

    @classmethod
    def generate(cls, ip: str) -> str:
        """
        Merakit laporan forensik lengkap untuk IP tertentu.
        Returns: string berformat Markdown untuk Telegram.
        """
        logger.info(f"[FORENSIC] Generating timeline for {ip}")

        report = [f"🕵️ *FORENSIC TIMELINE: `{ip}`*\n"]

        # ── Ambil data dari STM (aktivitas real-time) ──
        stm_data = STM.get(ip)
        if stm_data:
            report.append("📋 *Aktivitas Real-Time (STM):*")
            report.append(f"  Failed Attempts: {stm_data.get('failed_attempts', 0)}")
            report.append(f"  Last Seen: {stm_data.get('last_seen', '-')}")
            report.append(f"  Service: {stm_data.get('service', '-')}")

            paths = stm_data.get("paths_accessed", [])
            if paths:
                paths_str = ", ".join([f"`{p}`" for p in paths[:10]])
                report.append(f"  Paths Accessed: {paths_str}")
        else:
            report.append("📋 *Aktivitas Real-Time (STM):* Tidak ada data aktif.")

        report.append("")

        # ── Ambil data dari LTM (riwayat insiden historis) ──
        incidents = LTM.get_incident_history(ip, limit=20)
        if incidents:
            report.append(f"📜 *Riwayat Insiden ({len(incidents)} record):*")
            for i, inc in enumerate(incidents, 1):
                ts = inc.get("timestamp", "?")
                action = inc.get("action", "?")
                reason = inc.get("reason", "-")
                confidence = inc.get("confidence", 0)
                threat = inc.get("threat_type", "?")
                report.append(
                    f"  {i}. `{ts}` — {threat} → {action}\n"
                    f"      Reason: {reason}\n"
                    f"      Confidence: {confidence}"
                )
        else:
            report.append("📜 *Riwayat Insiden:* Bersih, tidak ada catatan.")

        report.append("")

        # ── Status Whitelist & False Positive ──
        is_whitelisted = LTM.is_whitelisted(ip)
        is_fp = LTM.is_false_positive(ip)
        report.append("📌 *Status:*")
        report.append(f"  Whitelist: {'✅ Ya' if is_whitelisted else '❌ Tidak'}")
        report.append(f"  False Positive: {'✅ Ya' if is_fp else '❌ Tidak'}")

        report.append("")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        report.append(f"🕐 _Report generated: {timestamp}_")

        return "\n".join(report)


forensic = ForensicTimeline()
