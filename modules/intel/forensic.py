import time
import logging
from modules.core.memory import LTM, STM
from modules.core.i18n import i18n

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

        report = [f"{i18n.t('forensic_title', ip=ip)}\n"]

        # ── Ambil data dari STM (aktivitas real-time) ──
        stm_data = STM.get(ip)
        if stm_data:
            report.append(i18n.t("forensic_stm_title"))
            report.append(f"{i18n.t('forensic_failed_attempts')}: {stm_data.get('failed_attempts', 0)}")
            report.append(f"{i18n.t('forensic_last_seen')}: {stm_data.get('last_seen', '-')}")
            report.append(f"{i18n.t('forensic_service')}: {stm_data.get('service', '-')}")

            paths = stm_data.get("paths_accessed", [])
            if paths:
                paths_str = ", ".join([f"`{p}`" for p in paths[:10]])
                report.append(f"{i18n.t('forensic_paths')}: {paths_str}")
        else:
            report.append(i18n.t("forensic_stm_empty"))

        report.append("")

        # ── Ambil data dari LTM (riwayat insiden historis) ──
        incidents = LTM.get_incident_history(ip, limit=20)
        if incidents:
            report.append(i18n.t("forensic_history_title", count=len(incidents)))
            for i, inc in enumerate(incidents, 1):
                ts = inc.get("timestamp", "?")
                action = inc.get("action", "?")
                reason = inc.get("reason", "-")
                confidence = inc.get("confidence", 0)
                threat = inc.get("threat_type", "?")
                report.append(
                    f"  {i}. `{ts}` — {threat} → {action}\n"
                    f"{i18n.t('forensic_reason')}: {reason}\n"
                    f"{i18n.t('forensic_confidence')}: {confidence}"
                )
        else:
            report.append(i18n.t("forensic_history_empty"))

        report.append("")

        # ── Status Whitelist & False Positive ──
        is_whitelisted = LTM.is_whitelisted(ip)
        is_fp = LTM.is_false_positive(ip)
        report.append(i18n.t("forensic_status_title"))
        wl_val = i18n.t("forensic_whitelist_yes") if is_whitelisted else i18n.t("forensic_whitelist_no")
        fp_val = i18n.t("forensic_whitelist_yes") if is_fp else i18n.t("forensic_whitelist_no")
        report.append(f"{i18n.t('forensic_whitelist')}: {wl_val}")
        report.append(f"{i18n.t('forensic_fp')}: {fp_val}")

        report.append("")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        report.append(i18n.t("forensic_generated", timestamp=timestamp))

        return "\n".join(report)


forensic = ForensicTimeline()
