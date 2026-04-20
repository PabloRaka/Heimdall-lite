import os
import subprocess
import logging
import time
import yaml
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

logger = logging.getLogger(__name__)


class RemoteServer:
    """Representasi satu remote server"""

    def __init__(self, name: str, host: str, user: str = "root", port: int = 22, key_path: str = ""):
        self.name = name
        self.host = host
        self.user = user
        self.port = port
        self.key_path = key_path or os.getenv("SSH_KEY_PATH", "~/.ssh/id_rsa")

    def _build_ssh_cmd(self, remote_cmd: str) -> str:
        """Membangun perintah SSH yang aman"""
        key_opt = f"-i {self.key_path}" if self.key_path else ""
        return (
            f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
            f"-p {self.port} {key_opt} {self.user}@{self.host} "
            f"'{remote_cmd}'"
        )

    def execute(self, remote_cmd: str) -> tuple:
        """Menjalankan perintah di remote server via SSH"""
        ssh_cmd = self._build_ssh_cmd(remote_cmd)
        try:
            result = subprocess.run(
                ssh_cmd, shell=True, text=True,
                capture_output=True, timeout=15
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout", 1
        except Exception as e:
            return "", str(e), 1

    def is_reachable(self) -> bool:
        """Cek apakah server bisa dijangkau"""
        out, err, code = self.execute("echo OK")
        return "OK" in out


class MultiServerManager:
    """
    Modul Multi-Server Support.
    Mengelola beberapa server sekaligus melalui SSH.
    
    Konfigurasi di config.yaml:
    ```yaml
    servers:
      - name: "Web Server"
        host: "192.168.1.10"
        user: "root"
        port: 22
      - name: "DB Server"
        host: "192.168.1.11"
        user: "root"
        port: 22
    ```
    """

    def __init__(self):
        self.servers = []
        self._load_servers()

    def _load_servers(self):
        """Memuat daftar server dari config.yaml"""
        config_path = BASE_DIR / "config.yaml"
        try:
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f) or {}

                servers_config = config.get("servers", [])
                for srv in servers_config:
                    self.servers.append(RemoteServer(
                        name=srv.get("name", srv.get("host", "unknown")),
                        host=srv["host"],
                        user=srv.get("user", "root"),
                        port=srv.get("port", 22),
                        key_path=srv.get("key_path", "")
                    ))

                if self.servers:
                    logger.info(f"[MULTI-SERVER] {len(self.servers)} remote server terdaftar.")
        except Exception as e:
            logger.warning(f"[MULTI-SERVER] Error loading config: {e}")

    def federated_block(self, ip: str, reason: str = "Federated Block") -> list:
        """
        Memblokir IP di SEMUA server yang terdaftar.
        Ini membuat satu serangan langsung ditangkis di semua infrastruktur.
        """
        results = []

        for server in self.servers:
            logger.info(f"[MULTI-SERVER] Blocking {ip} on {server.name} ({server.host})...")

            # Block via UFW di remote server
            out, err, code = server.execute(f"sudo ufw insert 1 deny from {ip} to any")

            if code == 0:
                results.append(f"✅ `{server.name}` ({server.host}): IP `{ip}` diblokir")
                logger.info(f"[MULTI-SERVER] ✅ {server.name}: blocked {ip}")
            else:
                results.append(f"❌ `{server.name}` ({server.host}): Gagal — {err[:50]}")
                logger.warning(f"[MULTI-SERVER] ❌ {server.name}: failed to block {ip}: {err}")

        return results

    def federated_unblock(self, ip: str) -> list:
        """Membuka blokir IP di semua server"""
        results = []

        for server in self.servers:
            out, err, code = server.execute(f"sudo ufw delete deny from {ip} to any")

            if code == 0:
                results.append(f"✅ `{server.name}`: IP `{ip}` di-unblock")
            else:
                results.append(f"❌ `{server.name}`: Gagal unblock — {err[:50]}")

        return results

    def health_check_all(self) -> str:
        """Mengecek status semua server"""
        if not self.servers:
            return "🟡 *Multi-Server*: Tidak ada remote server yang dikonfigurasi di `config.yaml`."

        report = ["🌐 *MULTI-SERVER HEALTH CHECK*\n"]

        for server in self.servers:
            reachable = server.is_reachable()
            status = "🟢 Online" if reachable else "🔴 Offline / Unreachable"
            report.append(f"*{server.name}* (`{server.host}:{server.port}`): {status}")

            if reachable:
                # Ambil uptime
                out, _, _ = server.execute("uptime -p")
                if out:
                    report.append(f"  Uptime: {out}")

                # Ambil load avg
                out, _, _ = server.execute("cat /proc/loadavg | awk '{print $1,$2,$3}'")
                if out:
                    report.append(f"  Load: {out}")

        report.append(f"\n🕐 _{time.strftime('%Y-%m-%d %H:%M:%S')}_")
        return "\n".join(report)

    def format_block_report(self, ip: str, reason: str = "") -> str:
        """Format laporan federated block untuk Telegram"""
        if not self.servers:
            return "ℹ️ Multi-Server tidak dikonfigurasi. Block hanya berlaku di server lokal."

        results = self.federated_block(ip, reason)
        report = [f"🌐 *FEDERATED BLOCK: `{ip}`*\n"]
        report.extend(results)
        report.append(f"\n🕐 _{time.strftime('%Y-%m-%d %H:%M:%S')}_")
        return "\n".join(report)


multi_server = MultiServerManager()
