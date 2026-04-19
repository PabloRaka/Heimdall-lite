import os
import subprocess
import requests
from dotenv import load_dotenv
from pathlib import Path

# Load env variables
BASE_DIR = Path(__file__).resolve().parent.parent
env_path = BASE_DIR / ".env"
load_dotenv(env_path)

CF_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
CF_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")

# DRY_RUN MODE: Jika True, hanya akan print perintah tanpa eksekusi betulan
DRY_RUN = True

class Executor:
    """
    Modul untuk mengeksekusi blokir/unblock IP.
    Mendukung Cloudflare WAF (L7) dan UFW (L3/L4).
    """

    @staticmethod
    def block_cloudflare(ip: str, reason: str = "Micro-SOC Auto Block") -> bool:
        """Blokir IP di Cloudflare WAF menggunakan Access Rules"""
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

    @staticmethod
    def block_ufw(ip: str) -> bool:
        """Blokir IP di level Local Firewall (UFW)"""
        cmd = ["sudo", "ufw", "insert", "1", "deny", "from", ip, "to", "any"]
        print(f"[EXECUTOR] [UFW] Mencoba blokir {ip}...")
        
        if DRY_RUN:
            print(f"  [DRY-RUN] Menjalankan perintah: {' '.join(cmd)}")
            return True

        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"  [SUCCESS] IP {ip} diblokir via UFW.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"  [ERROR] UFW Block Failed (Coba jalankan agent sebagai root/dengan NOPASSWD sudo).")
            return False

    @staticmethod
    def unblock_ufw(ip: str) -> bool:
        """Buka blokir IP di UFW"""
        cmd = ["sudo", "ufw", "delete", "deny", "from", ip, "to", "any"]
        print(f"[EXECUTOR] [UFW] Mencoba unblock {ip}...")
        
        if DRY_RUN:
            print(f"  [DRY-RUN] Menjalankan perintah: {' '.join(cmd)}")
            return True

        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"  [SUCCESS] IP {ip} di-unblock via UFW.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"  [ERROR] UFW Unblock Failed.")
            return False

# Singleton instance
executor = Executor()
