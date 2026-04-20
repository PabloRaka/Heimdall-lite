import subprocess
import hashlib
import json
import time
import logging
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
FIM_SNAPSHOT_PATH = DATA_DIR / "fim_snapshot.json"

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    filename=LOG_DIR / "agent.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# File-file kritis yang harus diawasi integritasnya (File Integrity Monitoring)
CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/crontab",
    "/etc/nginx/nginx.conf",
    "/etc/apache2/apache2.conf",
]

# Lokasi-lokasi authorized_keys yang harus diaudit
SSH_KEY_PATHS = [
    "/root/.ssh/authorized_keys",
    "/home/*/.ssh/authorized_keys",
]


class ServerScanner:
    """
    Modul Host-Based Vulnerability Scanner yang bersifat defensif.
    Mengaudit postur keamanan server melalui 6 lapis pemeriksaan:
    1. Firewall (UFW)
    2. SSH Security (sshd_config)
    3. Exposed Public Ports (ss)
    4. Failed System Services (systemctl)
    5. File Integrity Monitoring / FIM (SHA-256 hash comparison)
    6. SSH Authorized Keys Audit (backdoor detection)
    7. Outdated Security Packages (apt)
    """
    
    @staticmethod
    def _run_cmd(cmd: str) -> tuple:
        try:
            result = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=15)
            return result.stdout.strip(), result.stderr.strip()
        except Exception as e:
            return "", str(e)

    # ─────────────────────────────────────────────
    # 1. FIREWALL CHECK
    # ─────────────────────────────────────────────
    @classmethod
    def _check_firewall(cls) -> list:
        report = []
        out, err = cls._run_cmd("sudo ufw status")
        if "inactive" in out.lower() or "not found" in err.lower():
            report.append("🔴 *Firewall (UFW)*: Tidak Aktif atau Tidak Ditemukan! Server terekspos langsung ke dunia luar tanpa filter.")
        else:
            report.append("🟢 *Firewall (UFW)*: Aktif")
        return report

    # ─────────────────────────────────────────────
    # 2. SSH SECURITY AUDIT
    # ─────────────────────────────────────────────
    @classmethod
    def _check_ssh(cls) -> list:
        report = []
        out, err = cls._run_cmd("sudo sshd -T | grep -iE '^permitrootlogin|^passwordauthentication'")
        ssh_issues = []
        if out:
            lines = out.split('\n')
            for line in lines:
                if 'permitrootlogin yes' in line.lower():
                    ssh_issues.append("Root Login Diizinkan (Meningkatkan risiko takeover penuh)")
                if 'passwordauthentication yes' in line.lower():
                    ssh_issues.append("Password Authentication Aktif (Sangat rentan botnet SSH Brute-Force)")
        
        if ssh_issues:
            report.append("🔴 *Celah SSH Security*:\\n- " + "\\n- ".join(ssh_issues))
            report.append("ℹ️ _[Solusi]_: Edit `/etc/ssh/sshd_config` menjadi `PermitRootLogin no` dan `PasswordAuthentication no` (gunakan SSH Key).")
        elif out:
            report.append("🟢 *SSH Security*: Konfigurasi Aman (Root/Password tertutup)")
        else:
            report.append("🟡 *SSH Security*: Gagal membaca status konfigurasi lokal SSHD.")
        return report

    # ─────────────────────────────────────────────
    # 3. EXPOSED PUBLIC PORTS
    # ─────────────────────────────────────────────
    @classmethod
    def _check_ports(cls) -> list:
        report = []
        out, err = cls._run_cmd("ss -tuln | grep -iE '0\\.0\\.0\\.0:|:::'")
        if out:
            ports = []
            for line in out.split('\n'):
                parts = line.split()
                if len(parts) >= 5:
                    port = parts[4].split(':')[-1]
                    if port and port not in ports:
                        ports.append(port)
            if ports:
                report.append(f"🟡 *Exposed Public Ports*: `{', '.join(ports[:15])}` {'...' if len(ports)>15 else ''}")
                report.append("ℹ️ _[Peringatan]_: Pastikan port-port di atas memang disengaja untuk dibuka untuk publik.")
        return report

    # ─────────────────────────────────────────────
    # 4. FAILED SYSTEM SERVICES
    # ─────────────────────────────────────────────
    @classmethod
    def _check_services(cls) -> list:
        report = []
        out, err = cls._run_cmd("systemctl --failed --no-pager --plain")
        failed_count = 0
        if out:
            for line in out.split('\n'):
                if 'loaded failed failed' in line:
                    failed_count += 1
        
        if failed_count > 0:
            report.append(f"🔴 *Failed System Services*: Ada {failed_count} service krusial gagal memuat.")
        else:
            report.append("🟢 *System Services*: Semua Normal berjalan mulus.")
        return report

    # ─────────────────────────────────────────────
    # 5. FILE INTEGRITY MONITORING (FIM)
    # ─────────────────────────────────────────────
    @classmethod
    def _hash_file(cls, filepath: str) -> str:
        """Menghitung SHA-256 hash dari sebuah file"""
        try:
            out, err = cls._run_cmd(f"sudo sha256sum {filepath}")
            if out:
                return out.split()[0]
        except Exception:
            pass
        return ""

    @classmethod
    def _load_fim_snapshot(cls) -> dict:
        try:
            if FIM_SNAPSHOT_PATH.exists():
                with open(FIM_SNAPSHOT_PATH, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    @classmethod
    def _save_fim_snapshot(cls, snapshot: dict):
        with open(FIM_SNAPSHOT_PATH, 'w') as f:
            json.dump(snapshot, f, indent=2)

    @classmethod
    def _check_file_integrity(cls) -> list:
        report = []
        old_snapshot = cls._load_fim_snapshot()
        new_snapshot = {}
        changed_files = []
        new_files = []

        for filepath in CRITICAL_FILES:
            # Cek apakah file ada di sistem
            out, err = cls._run_cmd(f"test -f {filepath} && echo EXISTS")
            if "EXISTS" not in out:
                continue

            file_hash = cls._hash_file(filepath)
            if not file_hash:
                continue

            new_snapshot[filepath] = {
                "hash": file_hash,
                "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S")
            }

            if filepath in old_snapshot:
                if old_snapshot[filepath]["hash"] != file_hash:
                    changed_files.append(filepath)
            else:
                new_files.append(filepath)

        # Simpan snapshot terbaru
        cls._save_fim_snapshot(new_snapshot)

        if not old_snapshot:
            report.append("🟡 *File Integrity (FIM)*: Snapshot awal berhasil dibuat. Pemeriksaan perubahan dimulai dari scan berikutnya.")
        elif changed_files:
            file_list = "\\n- ".join(changed_files)
            report.append(f"🔴 *File Integrity (FIM)*: Terdeteksi perubahan pada file kritis!\\n- {file_list}")
            report.append("ℹ️ _[Peringatan]_: Pastikan perubahan ini disengaja. Bisa jadi indikasi backdoor!")
        else:
            monitored = len(new_snapshot)
            report.append(f"🟢 *File Integrity (FIM)*: {monitored} file kritis aman, tidak ada perubahan terdeteksi.")

        return report

    # ─────────────────────────────────────────────
    # 6. SSH AUTHORIZED KEYS AUDIT
    # ─────────────────────────────────────────────
    @classmethod
    def _check_authorized_keys(cls) -> list:
        report = []
        total_keys = 0
        key_details = []

        for pattern in SSH_KEY_PATHS:
            # Gunakan glob untuk expand wildcard /home/*
            out, err = cls._run_cmd(f"sudo bash -c 'for f in {pattern}; do [ -f \"$f\" ] && echo \"$f\"; done'")
            if not out:
                continue
            
            for keyfile in out.split('\n'):
                keyfile = keyfile.strip()
                if not keyfile:
                    continue
                
                # Hitung jumlah key di dalam file
                count_out, _ = cls._run_cmd(f"sudo grep -c '' {keyfile}")
                try:
                    count = int(count_out.strip())
                except (ValueError, AttributeError):
                    count = 0
                
                if count > 0:
                    total_keys += count
                    key_details.append(f"`{keyfile}` ({count} key)")

        if total_keys == 0:
            report.append("🟢 *SSH Keys Audit*: Tidak ditemukan authorized keys terdaftar.")
        elif total_keys <= 3:
            details = ", ".join(key_details)
            report.append(f"🟡 *SSH Keys Audit*: Ditemukan {total_keys} key — {details}")
            report.append("ℹ️ _[Info]_: Pastikan semua key tersebut milik admin yang sah.")
        else:
            details = ", ".join(key_details)
            report.append(f"🔴 *SSH Keys Audit*: Ditemukan {total_keys} key! — {details}")
            report.append("ℹ️ _[Peringatan]_: Jumlah key terlalu banyak! Bisa jadi ada key asing yang ditanam attacker.")

        return report

    # ─────────────────────────────────────────────
    # 7. OUTDATED SECURITY PACKAGES
    # ─────────────────────────────────────────────
    @classmethod
    def _check_outdated_packages(cls) -> list:
        report = []
        
        # Deteksi package manager (apt untuk Debian/Ubuntu)
        out, err = cls._run_cmd("which apt-get")
        if out:
            update_out, _ = cls._run_cmd("sudo apt-get -s upgrade 2>/dev/null | grep -i 'security' | head -20")
            count_out, _ = cls._run_cmd("sudo apt-get -s upgrade 2>/dev/null | grep '^Inst' | grep -ci 'security'")
            try:
                sec_count = int(count_out.strip())
            except (ValueError, AttributeError):
                sec_count = 0

            if sec_count > 0:
                report.append(f"🔴 *Security Patches*: Ada {sec_count} paket keamanan yang belum diperbarui!")
                report.append("ℹ️ _[Solusi]_: Jalankan `sudo apt-get update && sudo apt-get upgrade` segera.")
            else:
                report.append("🟢 *Security Patches*: Semua paket keamanan sudah terbaru.")
        else:
            # Coba yum/dnf untuk RHEL/CentOS
            out, err = cls._run_cmd("which yum")
            if out:
                count_out, _ = cls._run_cmd("sudo yum check-update --security 2>/dev/null | grep -c '^[a-zA-Z]'")
                try:
                    sec_count = int(count_out.strip())
                except (ValueError, AttributeError):
                    sec_count = 0
                
                if sec_count > 0:
                    report.append(f"🔴 *Security Patches*: Ada {sec_count} paket keamanan yang belum diperbarui!")
                else:
                    report.append("🟢 *Security Patches*: Semua paket keamanan sudah terbaru.")
            else:
                report.append("🟡 *Security Patches*: Tidak dapat mendeteksi package manager (apt/yum).")

        return report

    # ─────────────────────────────────────────────
    # MAIN SCAN ORCHESTRATOR
    # ─────────────────────────────────────────────
    @classmethod
    def scan_all(cls) -> str:
        """Menjalankan seluruh modul pemindaian dan merakit laporan akhir"""
        logging.info("[SCANNER] Memulai full vulnerability scan...")
        
        report = ["🛡️ *HEIMDALL VULNERABILITY SCANNER* 🛡️\n"]

        report.extend(cls._check_firewall())
        report.extend(cls._check_ssh())
        report.extend(cls._check_ports())
        report.extend(cls._check_services())
        report.extend(cls._check_file_integrity())
        report.extend(cls._check_authorized_keys())
        report.extend(cls._check_outdated_packages())

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        report.append(f"\n🕐 _Scan selesai: {timestamp}_")

        logging.info("[SCANNER] Full scan selesai.")
        return "\n\n".join(report)

    @classmethod
    def scan_silent(cls) -> str:
        """
        Silent Scan — hanya mengembalikan laporan jika ADA masalah.
        Digunakan untuk auto-scan terjadwal agar tidak spam Telegram.
        Returns: string laporan jika ada issues, atau string kosong jika aman.
        """
        logging.info("[SCANNER] Memulai silent scan...")
        
        issues = []

        # Jalankan semua check
        for check_fn in [cls._check_firewall, cls._check_ssh, cls._check_ports,
                         cls._check_services, cls._check_file_integrity,
                         cls._check_authorized_keys, cls._check_outdated_packages]:
            results = check_fn()
            for line in results:
                if "🔴" in line:
                    issues.append(line)

        if not issues:
            logging.info("[SCANNER] Silent scan selesai — semua aman.")
            return ""

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        report = ["⚠️ *HEIMDALL AUTO-SCAN ALERT* ⚠️\n"]
        report.append(f"Terdeteksi {len(issues)} masalah keamanan:\n")
        report.extend(issues)
        report.append(f"\n🕐 _Auto-scan: {timestamp}_")
        report.append("ℹ️ Gunakan /scan untuk laporan lengkap.")

        logging.info(f"[SCANNER] Silent scan selesai — {len(issues)} masalah terdeteksi.")
        return "\n\n".join(report)


scanner = ServerScanner()
