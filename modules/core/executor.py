import os
import ipaddress
import requests
import shlex
from dotenv import load_dotenv
from pathlib import Path
from modules.core.host_runtime import HOST_DEFENSE_MODE, run_host_command

# Load env variables
BASE_DIR = Path(__file__).resolve().parent.parent.parent
env_path = BASE_DIR / ".env"
load_dotenv(env_path)

CF_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
CF_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")

# DRY_RUN MODE: Jika True, hanya akan print perintah tanpa eksekusi betulan
DRY_RUN = os.getenv("HEIMDALL_DRY_RUN", "0").lower() in {"1", "true", "yes", "on"}
NFT_FALLBACK_ENABLED = os.getenv("HEIMDALL_FIREWALL_FALLBACK_NFT", "0").lower() in {"1", "true", "yes", "on"}
NFT_TABLE_NAME = os.getenv("HEIMDALL_NFT_TABLE", "heimdall")
NFT_CHAIN_NAME = os.getenv("HEIMDALL_NFT_CHAIN", "input")

class Executor:
    """
    Modul untuk mengeksekusi blokir/unblock IP.
    Mendukung Cloudflare WAF (L7), UFW, dan fallback nftables opsional (L3/L4).
    """

    _ufw_disabled_reason = ""
    _nft_ready = False

    @staticmethod
    def block_cloudflare(ip: str, reason: str = "Micro-SOC Auto Block") -> bool:
        """Blokir IP di Cloudflare WAF menggunakan Access Rules"""
        from modules.core.safe_mode import safe_mode
        if not safe_mode.check(f"BLOCK_CF {ip}"):
            print(f"  [SAFE-MODE] ⚠️ CF block for {ip} skipped (alert-only)")
            return True  # Return True agar pipeline tetap berjalan

        print(f"[EXECUTOR] [CF] Mencoba blokir {ip}...")
        
        if DRY_RUN:
            print(f"  [DRY-RUN] POST https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/firewall/access_rules/rules")
            print(f"  [DRY-RUN] Payload: mode=block, target=ip, value={ip}, notes='{reason}'")
            return True

        if not CF_TOKEN or not CF_ZONE_ID:
            print("  [ERROR] Cloudflare Token/ZoneID tidak ditemukan!")
            return False

        url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/firewall/access_rules/rules"
        headers = {
            "Authorization": f"Bearer {CF_TOKEN}",
            "Content-Type": "application/json"
        }
        data = {
            "mode": "block",
            "configuration": {"target": "ip", "value": ip},
            "notes": reason
        }
        
        try:
            res = requests.post(url, json=data, headers=headers, timeout=5)
            res.raise_for_status()
            print(f"  [SUCCESS] IP {ip} diblokir di Cloudflare.")
            return True
        except requests.exceptions.RequestException as e:
            print(f"  [ERROR] CF Block Failed: {e}")
            return False

    @staticmethod
    def unblock_cloudflare(ip: str) -> bool:
        """
        Membuka blokir IP di Cloudflare.
        Butuh 2 step: GET id rule berdasarkan IP, lalu DELETE id rule tersebut.
        """
        print(f"[EXECUTOR] [CF] Mencoba unblock {ip}...")
        
        if DRY_RUN:
            print(f"  [DRY-RUN] GET https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/firewall/access_rules/rules?configuration_value={ip}")
            print(f"  [DRY-RUN] DELETE https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/firewall/access_rules/rules/<RULE_ID>")
            return True

        if not CF_TOKEN or not CF_ZONE_ID:
            return False

        headers = {
            "Authorization": f"Bearer {CF_TOKEN}",
            "Content-Type": "application/json"
        }
        
        # Step 1: Cari Rule ID
        url_search = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/firewall/access_rules/rules?configuration_value={ip}"
        try:
            res = requests.get(url_search, headers=headers, timeout=5)
            res.raise_for_status()
            data = res.json()
            rules = data.get("result", [])
            
            if not rules:
                print(f"  [INFO] Rule blokir untuk IP {ip} tidak ditemukan di CF.")
                return True # Anggap sukses jika tidak ada yang diblokir
                
            rule_id = rules[0]["id"]
            
            # Step 2: Hapus Rule ID
            url_delete = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/firewall/access_rules/rules/{rule_id}"
            res_del = requests.delete(url_delete, headers=headers, timeout=5)
            res_del.raise_for_status()
            
            print(f"  [SUCCESS] IP {ip} di-unblock dari Cloudflare.")
            return True
            
        except Exception as e:
            print(f"  [ERROR] CF Unblock Failed: {e}")
            return False

    @classmethod
    def _run_firewall_command(cls, cmd: str):
        return run_host_command(cmd, timeout=15)

    @staticmethod
    def _format_firewall_error(stdout: str, stderr: str) -> str:
        return " | ".join(part.strip() for part in [stderr, stdout] if part and part.strip())

    @classmethod
    def _disable_ufw(cls, reason: str, detail: str = ""):
        if cls._ufw_disabled_reason:
            return

        cls._ufw_disabled_reason = reason
        print("  [WARN] UFW tidak dapat dipakai di host ini.")
        print("  [INFO] Host tampaknya memakai firewall lain atau backend firewall yang berbeda.")
        if detail:
            print(f"  [DETAIL] {detail}")
        print("  [INFO] Percobaan UFW berikutnya akan dilewati.")
        if NFT_FALLBACK_ENABLED:
            print("  [INFO] Fallback nftables aktif.")

    @classmethod
    def _classify_ufw_failure(cls, stdout: str, stderr: str) -> tuple[bool, str]:
        detail = cls._format_firewall_error(stdout, stderr)
        combined = detail.lower()
        fallback_signals = (
            "ufw: not found",
            "command not found",
            "not found",
            "problem running",
            "iptables",
            "ip6tables",
            "nf_tables",
            "nftables",
            "could not fetch rule set generation id",
            "could not load logging rules",
        )
        permission_signals = (
            "permission denied",
            "must be root",
            "operation not permitted",
        )

        if any(signal in combined for signal in permission_signals):
            return False, detail

        if any(signal in combined for signal in fallback_signals):
            return True, detail

        return False, detail

    @classmethod
    def _get_nft_set_name(cls, ip: str) -> str:
        parsed = ipaddress.ip_address(ip)
        return "blocked_ipv6" if parsed.version == 6 else "blocked_ipv4"

    @classmethod
    def _run_nft_statement(cls, statement: str):
        return cls._run_firewall_command(f"nft {shlex.quote(statement)}")

    @classmethod
    def _ensure_nft_ready(cls) -> bool:
        if cls._nft_ready:
            return True

        checks = [
            (
                f"nft list table inet {NFT_TABLE_NAME}",
                f"add table inet {NFT_TABLE_NAME}",
            ),
            (
                f"nft list chain inet {NFT_TABLE_NAME} {NFT_CHAIN_NAME}",
                f"add chain inet {NFT_TABLE_NAME} {NFT_CHAIN_NAME} {{ type filter hook input priority 0; policy accept; }}",
            ),
            (
                f"nft list set inet {NFT_TABLE_NAME} blocked_ipv4",
                f"add set inet {NFT_TABLE_NAME} blocked_ipv4 {{ type ipv4_addr; }}",
            ),
            (
                f"nft list set inet {NFT_TABLE_NAME} blocked_ipv6",
                f"add set inet {NFT_TABLE_NAME} blocked_ipv6 {{ type ipv6_addr; }}",
            ),
        ]

        for check_cmd, create_stmt in checks:
            result = cls._run_firewall_command(check_cmd)
            if result.returncode == 0:
                continue

            created = cls._run_nft_statement(create_stmt)
            if created.returncode != 0:
                detail = cls._format_firewall_error(created.stdout, created.stderr)
                print(f"  [ERROR] Gagal menyiapkan nftables: {detail or create_stmt}")
                return False

        chain_rules = cls._run_firewall_command(f"nft list chain inet {NFT_TABLE_NAME} {NFT_CHAIN_NAME}")
        if chain_rules.returncode != 0:
            detail = cls._format_firewall_error(chain_rules.stdout, chain_rules.stderr)
            print(f"  [ERROR] Gagal membaca chain nftables: {detail}")
            return False

        expected_rules = {
            f"ip saddr @blocked_ipv4 drop": f"add rule inet {NFT_TABLE_NAME} {NFT_CHAIN_NAME} ip saddr @blocked_ipv4 drop",
            f"ip6 saddr @blocked_ipv6 drop": f"add rule inet {NFT_TABLE_NAME} {NFT_CHAIN_NAME} ip6 saddr @blocked_ipv6 drop",
        }
        rendered_rules = chain_rules.stdout or ""

        for marker, create_stmt in expected_rules.items():
            if marker in rendered_rules:
                continue

            created = cls._run_nft_statement(create_stmt)
            if created.returncode != 0:
                detail = cls._format_firewall_error(created.stdout, created.stderr)
                print(f"  [ERROR] Gagal menambah rule nftables: {detail or create_stmt}")
                return False

        cls._nft_ready = True
        return True

    @classmethod
    def _block_nft(cls, ip: str) -> bool:
        print(f"[EXECUTOR] [NFT] Mencoba blokir {ip}...")
        if not cls._ensure_nft_ready():
            return False

        try:
            set_name = cls._get_nft_set_name(ip)
        except ValueError:
            print(f"  [ERROR] IP tidak valid untuk nftables: {ip}")
            return False

        statement = f"add element inet {NFT_TABLE_NAME} {set_name} {{ {ip} }}"
        result = cls._run_nft_statement(statement)
        detail = cls._format_firewall_error(result.stdout, result.stderr)

        if result.returncode == 0 or "file exists" in detail.lower():
            print(f"  [SUCCESS] IP {ip} diblokir via nftables.")
            return True

        print(f"  [ERROR] NFT Block Failed: {detail or statement}")
        return False

    @classmethod
    def _unblock_nft(cls, ip: str) -> bool:
        print(f"[EXECUTOR] [NFT] Mencoba unblock {ip}...")
        if not cls._ensure_nft_ready():
            return False

        try:
            set_name = cls._get_nft_set_name(ip)
        except ValueError:
            print(f"  [ERROR] IP tidak valid untuk nftables: {ip}")
            return False

        statement = f"delete element inet {NFT_TABLE_NAME} {set_name} {{ {ip} }}"
        result = cls._run_nft_statement(statement)
        detail = cls._format_firewall_error(result.stdout, result.stderr)

        if result.returncode == 0 or "no such file or directory" in detail.lower():
            print(f"  [SUCCESS] IP {ip} di-unblock via nftables.")
            return True

        print(f"  [ERROR] NFT Unblock Failed: {detail or statement}")
        return False

    @classmethod
    def _maybe_fallback_to_nft(cls, action: str, ip: str) -> bool:
        if not NFT_FALLBACK_ENABLED:
            return False
        return cls._block_nft(ip) if action == "block" else cls._unblock_nft(ip)

    @classmethod
    def block_ufw(cls, ip: str) -> bool:
        """Blokir IP di level Local Firewall (UFW)"""
        from modules.core.safe_mode import safe_mode
        if not safe_mode.check(f"BLOCK_UFW {ip}"):
            print(f"  [SAFE-MODE] ⚠️ UFW block for {ip} skipped (alert-only)")
            return True

        cmd = "ufw insert 1 deny from {ip} to any".format(ip=ip)
        print(f"[EXECUTOR] [UFW] Mencoba blokir {ip}...")

        if DRY_RUN:
            print(f"  [DRY-RUN] Menjalankan perintah: {cmd}")
            return True

        if cls._ufw_disabled_reason:
            print(f"  [INFO] UFW dilewati: {cls._ufw_disabled_reason}.")
            return cls._maybe_fallback_to_nft("block", ip)

        result = cls._run_firewall_command(cmd)
        if result.returncode == 0:
            print(f"  [SUCCESS] IP {ip} diblokir via UFW.")
            return True

        disable_ufw, detail = cls._classify_ufw_failure(result.stdout, result.stderr)
        if disable_ufw:
            cls._disable_ufw("unsupported-or-other-firewall", detail)
            return cls._maybe_fallback_to_nft("block", ip)

        print(f"  [ERROR] UFW Block Failed: {detail or 'unknown error'}")
        if HOST_DEFENSE_MODE:
            print("  [HINT] Host-defense mode membutuhkan namespace host + capability NET_ADMIN/SYS_ADMIN.")
        return False

    @classmethod
    def unblock_ufw(cls, ip: str) -> bool:
        """Buka blokir IP di UFW"""
        cmd = "ufw delete deny from {ip} to any".format(ip=ip)
        print(f"[EXECUTOR] [UFW] Mencoba unblock {ip}...")

        if DRY_RUN:
            print(f"  [DRY-RUN] Menjalankan perintah: {cmd}")
            return True

        if cls._ufw_disabled_reason:
            print(f"  [INFO] UFW dilewati: {cls._ufw_disabled_reason}.")
            return cls._maybe_fallback_to_nft("unblock", ip)

        result = cls._run_firewall_command(cmd)
        if result.returncode == 0:
            print(f"  [SUCCESS] IP {ip} di-unblock via UFW.")
            return True

        disable_ufw, detail = cls._classify_ufw_failure(result.stdout, result.stderr)
        if disable_ufw:
            cls._disable_ufw("unsupported-or-other-firewall", detail)
            return cls._maybe_fallback_to_nft("unblock", ip)

        print(f"  [ERROR] UFW Unblock Failed: {detail or 'unknown error'}")
        return False

# Singleton instance
executor = Executor()
