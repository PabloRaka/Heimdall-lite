import logging
import time
from modules.core.i18n import i18n
from modules.core.host_runtime import run_host_command

logger = logging.getLogger(__name__)


class AutoRemediation:
    """
    Modul Auto-Remediation.
    Secara otomatis memperbaiki celah keamanan yang ditemukan oleh scanner.
    Setiap perbaikan dicatat dan dilaporkan.
    """

    @staticmethod
    def _run_cmd(cmd: str) -> tuple:
        try:
            result = run_host_command(cmd, timeout=15)
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except Exception as e:
            return "", str(e), 1

    @classmethod
    def remediate_all(cls) -> str:
        """
        Menjalankan seluruh remediasi otomatis.
        Returns: string laporan tindakan yang dilakukan.
        """
        from modules.core.safe_mode import safe_mode
        if safe_mode.is_enabled:
            logger.info("[REMEDIATION] Safe Mode ON — remediation skipped (alert-only)")
            return i18n.t("safemode_remediate_skip")

        logger.info("[REMEDIATION] Memulai auto-remediation...")
        actions = []

        # 1. Fix Firewall
        result = cls._fix_firewall()
        if result:
            actions.append(result)

        # 2. Fix SSH
        ssh_results = cls._fix_ssh()
        actions.extend(ssh_results)

        # 3. Fix Failed Services
        result = cls._fix_failed_services()
        if result:
            actions.append(result)

        if not actions:
            return i18n.t("remediate_ok")

        report = [i18n.t("remediate_title") + "\n"]
        report.extend(actions)
        report.append(f"\n{i18n.t('remediate_done_at', timestamp=time.strftime('%Y-%m-%d %H:%M:%S'))}")

        logger.info(f"[REMEDIATION] Selesai. {len(actions)} tindakan dilakukan.")
        return "\n\n".join(report)

    @classmethod
    def _fix_firewall(cls) -> str:
        """Mengaktifkan UFW jika mati"""
        out, err, code = cls._run_cmd("ufw status")

        if "inactive" in out.lower():
            logger.warning("[REMEDIATION] UFW inactive — mengaktifkan...")
            out2, err2, code2 = cls._run_cmd("ufw --force enable")

            if code2 == 0:
                logger.info("[REMEDIATION] ✅ UFW berhasil diaktifkan")
                return i18n.t("remediate_fw_ok")
            else:
                logger.warning(f"[REMEDIATION] ❌ Gagal mengaktifkan UFW: {err2}")
                return i18n.t("remediate_fw_fail", error=err2)

        return ""

    @classmethod
    def _fix_ssh(cls) -> list:
        """Memperbaiki konfigurasi SSH yang lemah"""
        results = []
        out, err, code = cls._run_cmd("sshd -T | grep -iE '^permitrootlogin|^passwordauthentication'")

        if not out:
            return results

        sshd_config = "/etc/ssh/sshd_config"
        needs_reload = False

        if "permitrootlogin yes" in out.lower():
            logger.warning("[REMEDIATION] PermitRootLogin yes detected — memperbaiki...")
            _, _, rc = cls._run_cmd(
                f"sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' {sshd_config} && "
                f"sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' {sshd_config}"
            )
            if rc == 0:
                results.append(i18n.t("remediate_ssh_root_ok"))
                needs_reload = True
            else:
                results.append(i18n.t("remediate_ssh_root_fail"))

        if "passwordauthentication yes" in out.lower():
            logger.warning("[REMEDIATION] PasswordAuthentication yes detected — memperbaiki...")
            _, _, rc = cls._run_cmd(
                f"sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' {sshd_config} && "
                f"sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' {sshd_config}"
            )
            if rc == 0:
                results.append(i18n.t("remediate_ssh_pass_ok"))
                needs_reload = True
            else:
                results.append(i18n.t("remediate_ssh_pass_fail"))

        if needs_reload:
            _, _, rc = cls._run_cmd("systemctl reload sshd 2>/dev/null || systemctl reload ssh")
            if rc == 0:
                results.append(i18n.t("remediate_sshd_reload_ok"))
            else:
                results.append(i18n.t("remediate_sshd_reload_fail"))

        return results

    @classmethod
    def _fix_failed_services(cls) -> str:
        """Mencoba restart service yang gagal"""
        out, err, code = cls._run_cmd("systemctl --failed --no-pager --plain")

        failed_services = []
        if out:
            for line in out.split('\n'):
                if 'loaded failed failed' in line:
                    parts = line.split()
                    if parts:
                        failed_services.append(parts[0])

        if not failed_services:
            return ""

        fixed = []
        still_broken = []

        for svc in failed_services[:5]:  # Limit ke 5 service
            logger.info(f"[REMEDIATION] Mencoba restart {svc}...")
            _, _, rc = cls._run_cmd(f"systemctl restart {svc}")

            if rc == 0:
                fixed.append(svc)
            else:
                still_broken.append(svc)

        result_parts = []
        if fixed:
            result_parts.append(i18n.t("remediate_svc_fixed", services=', '.join(fixed)))
        if still_broken:
            result_parts.append(i18n.t("remediate_svc_broken", services=', '.join(still_broken)))

        return "\n".join(result_parts) if result_parts else ""


remediation = AutoRemediation()
