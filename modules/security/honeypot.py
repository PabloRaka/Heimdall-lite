import socket
import time
import logging
import threading
import sqlite3
import random
from pathlib import Path
from modules.core.memory import LTM, DB_PATH
from modules.core.executor import executor
from modules.core.i18n import i18n

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# KONFIGURASI HONEYPOT
# ─────────────────────────────────────────────

# Port honeypot default
FAKE_SSH_PORT = 2222
FAKE_HTTP_PORT = 8888

# Auto-block threshold (berapa kali koneksi sebelum IP diblokir)
AUTO_BLOCK_THRESHOLD = 3

# Tarpit delay — kirim 1 byte setiap N detik
TARPIT_BYTE_DELAY = 2

# Max koneksi per honeypot bersamaan
MAX_CONNECTIONS = 10

# SSH Banner palsu (terlihat seperti server SSH asli)
FAKE_SSH_BANNERS = [
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    "SSH-2.0-OpenSSH_9.3p1 Debian-1\r\n",
    "SSH-2.0-OpenSSH_7.4\r\n",
]

# Fake HTTP admin login page
FAKE_HTTP_RESPONSE = """HTTP/1.1 200 OK\r
Content-Type: text/html\r
Server: nginx/1.24.0\r
\r
<!DOCTYPE html>
<html>
<head><title>Admin Panel - Login</title></head>
<body style="font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;background:#1a1a2e;margin:0">
<div style="background:#16213e;padding:40px;border-radius:12px;color:#fff;width:320px">
<h2 style="text-align:center">🔐 Admin Panel</h2>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Username" style="width:100%;padding:10px;margin:8px 0;border:none;border-radius:6px"><br>
<input type="password" name="password" placeholder="Password" style="width:100%;padding:10px;margin:8px 0;border:none;border-radius:6px"><br>
<button style="width:100%;padding:12px;background:#e94560;border:none;border-radius:6px;color:#fff;cursor:pointer;font-size:16px">Login</button>
</form>
</div>
</body>
</html>"""


class HoneypotServer:
    """Base class untuk honeypot server."""

    def __init__(self, port: int, service_name: str):
        self.port = port
        self.service_name = service_name
        self._running = False
        self._thread = None
        self._connection_count = {}  # ip -> count
        self._lock = threading.Lock()

    def start(self):
        """Start honeypot di background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        logger.info(f"[HONEYPOT] {self.service_name} listening on port {self.port}")

    def stop(self):
        self._running = False

    def _serve(self):
        """TCP server loop."""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.settimeout(2)
            server.bind(("0.0.0.0", self.port))
            server.listen(MAX_CONNECTIONS)

            while self._running:
                try:
                    client, addr = server.accept()
                    # Handle koneksi di thread terpisah agar tarpit tidak memblokir
                    t = threading.Thread(
                        target=self._handle_connection,
                        args=(client, addr),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"[HONEYPOT] {self.service_name} accept error: {e}")

        except OSError as e:
            logger.error(f"[HONEYPOT] Cannot bind port {self.port}: {e}")
        finally:
            try:
                server.close()
            except Exception:
                pass

    def _handle_connection(self, client: socket.socket, addr: tuple):
        """Override di subclass."""
        pass

    def _log_connection(self, ip: str, payload: str = ""):
        """Log koneksi ke database dan cek auto-block threshold."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")

        # Log ke DB
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO honeypot_logs (ip, port, service, payload, timestamp) VALUES (?, ?, ?, ?, ?)",
                (ip, self.port, self.service_name, payload[:500], timestamp),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"[HONEYPOT] DB log error: {e}")

        # Track connection count per IP
        with self._lock:
            self._connection_count[ip] = self._connection_count.get(ip, 0) + 1
            count = self._connection_count[ip]

        logger.warning(
            f"[HONEYPOT] 🍯 {self.service_name}:{self.port} <- {ip} "
            f"(connection #{count})"
        )

        # Auto-block setelah threshold
        if count >= AUTO_BLOCK_THRESHOLD:
            logger.warning(f"[HONEYPOT] 🚫 Auto-blocking {ip} (threshold: {count})")
            try:
                executor.block_ufw(ip)
                executor.block_cloudflare(ip, f"Honeypot trap: {self.service_name}:{self.port}")
                LTM.add_incident(
                    ip,
                    threat_type="HONEYPOT_TRAP",
                    action="BLOCK_CF_UFW",
                    reason=f"Honeypot {self.service_name}:{self.port} — {count} connections",
                    confidence=1.0,
                )
            except Exception as e:
                logger.error(f"[HONEYPOT] Auto-block error: {e}")


class FakeSSHHoneypot(HoneypotServer):
    """
    Fake SSH Server dengan Tarpitting.
    Menerima koneksi, mengirim SSH banner palsu, lalu menerapkan tarpit
    (mengirim data sangat lambat — 1 byte setiap beberapa detik).
    Ini mengunci scanner/bot penyerang selama berjam-jam.
    """

    def __init__(self, port: int = FAKE_SSH_PORT):
        super().__init__(port, "FakeSSH")

    def _handle_connection(self, client: socket.socket, addr: tuple):
        ip = addr[0]
        payload_data = ""

        try:
            client.settimeout(120)

            # Log koneksi masuk
            self._log_connection(ip, "SSH connection attempt")

            # Kirim banner palsu — TAPI dengan tarpit (1 byte per N detik)
            banner = random.choice(FAKE_SSH_BANNERS)
            for byte in banner.encode():
                try:
                    client.send(bytes([byte]))
                    time.sleep(TARPIT_BYTE_DELAY)
                except (BrokenPipeError, ConnectionResetError):
                    break

            # Coba capture apapun yang dikirim penyerang
            try:
                data = client.recv(1024)
                if data:
                    payload_data = data.decode("utf-8", errors="replace")[:200]
                    self._log_connection(ip, f"SSH payload: {payload_data}")
            except socket.timeout:
                pass

            # Setelah menerima data, kirim tarpit data lagi (endless)
            tarpit_msg = "Please wait...\r\n"
            for _ in range(50):
                try:
                    for byte in tarpit_msg.encode():
                        client.send(bytes([byte]))
                        time.sleep(TARPIT_BYTE_DELAY)
                except (BrokenPipeError, ConnectionResetError, socket.timeout):
                    break

        except Exception as e:
            logger.debug(f"[HONEYPOT] FakeSSH handler error: {e}")
        finally:
            try:
                client.close()
            except Exception:
                pass


class FakeHTTPHoneypot(HoneypotServer):
    """
    Fake HTTP Admin Panel.
    Menyajikan halaman login palsu yang menarik. Ketika penyerang
    mengirim kredensial, semua data direkam dan IP diblokir.
    """

    def __init__(self, port: int = FAKE_HTTP_PORT):
        super().__init__(port, "FakeHTTP")

    def _handle_connection(self, client: socket.socket, addr: tuple):
        ip = addr[0]

        try:
            client.settimeout(30)

            # Terima HTTP request dari penyerang
            data = client.recv(4096)
            request = data.decode("utf-8", errors="replace") if data else ""

            if "POST" in request:
                # Penyerang mengirim username/password — capture!
                payload = request.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in request else ""
                self._log_connection(ip, f"POST credentials: {payload[:300]}")

                # Kirim response palsu (berpura-pura login gagal)
                error_response = (
                    "HTTP/1.1 401 Unauthorized\r\n"
                    "Content-Type: text/html\r\n\r\n"
                    "<html><body><h1>Invalid credentials</h1></body></html>"
                )
                # Tarpit response — kirim sangat lambat
                for byte in error_response.encode():
                    try:
                        client.send(bytes([byte]))
                        time.sleep(0.5)
                    except (BrokenPipeError, ConnectionResetError):
                        break
            else:
                # GET request — kirim halaman login palsu
                self._log_connection(ip, f"GET {request[:100]}")

                # Kirim halaman login — juga di-tarpit sedikit
                for byte in FAKE_HTTP_RESPONSE.encode():
                    try:
                        client.send(bytes([byte]))
                        time.sleep(0.05)  # Sedikit lebih cepat agar form ter-render
                    except (BrokenPipeError, ConnectionResetError):
                        break

        except Exception as e:
            logger.debug(f"[HONEYPOT] FakeHTTP handler error: {e}")
        finally:
            try:
                client.close()
            except Exception:
                pass


class HoneypotManager:
    """
    Mengelola semua honeypot instance.
    Menyediakan API untuk mendapatkan statistik dan format report.
    """

    def __init__(self):
        self.honeypots = []

    def start_all(self):
        """Jalankan semua honeypot."""
        ssh_hp = FakeSSHHoneypot(FAKE_SSH_PORT)
        http_hp = FakeHTTPHoneypot(FAKE_HTTP_PORT)

        self.honeypots = [ssh_hp, http_hp]

        for hp in self.honeypots:
            hp.start()

        logger.info(f"[HONEYPOT] Manager started — {len(self.honeypots)} honeypots active")

    def stop_all(self):
        for hp in self.honeypots:
            hp.stop()

    def get_stats(self) -> dict:
        """Ambil statistik dari database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            today = time.strftime("%Y-%m-%d")

            # Total koneksi hari ini
            cursor.execute(
                "SELECT COUNT(*) FROM honeypot_logs WHERE timestamp LIKE ?",
                (f"{today}%",),
            )
            total_today = cursor.fetchone()[0]

            # Total semua
            cursor.execute("SELECT COUNT(*) FROM honeypot_logs")
            total_all = cursor.fetchone()[0]

            # Top 5 IP penyerang
            cursor.execute(
                "SELECT ip, COUNT(*) as cnt FROM honeypot_logs "
                "GROUP BY ip ORDER BY cnt DESC LIMIT 5"
            )
            top_ips = [(row[0], row[1]) for row in cursor.fetchall()]

            # Per-service breakdown
            cursor.execute(
                "SELECT service, COUNT(*) FROM honeypot_logs GROUP BY service"
            )
            per_service = {row[0]: row[1] for row in cursor.fetchall()}

            # 5 koneksi terbaru
            cursor.execute(
                "SELECT ip, port, service, payload, timestamp FROM honeypot_logs "
                "ORDER BY id DESC LIMIT 5"
            )
            recent = [
                {"ip": r[0], "port": r[1], "service": r[2], "payload": r[3], "timestamp": r[4]}
                for r in cursor.fetchall()
            ]

            conn.close()

            return {
                "total_today": total_today,
                "total_all": total_all,
                "top_ips": top_ips,
                "per_service": per_service,
                "recent": recent,
                "active_honeypots": len(self.honeypots),
            }
        except Exception as e:
            logger.error(f"[HONEYPOT] Stats error: {e}")
            return {"total_today": 0, "total_all": 0, "top_ips": [], "per_service": {},
                    "recent": [], "active_honeypots": 0}

    def format_report(self) -> str:
        """Format laporan honeypot untuk Telegram."""
        stats = self.get_stats()

        report = [f"{i18n.t('honeypot_title')}\n"]
        report.append(f"{i18n.t('honeypot_active')}: {stats['active_honeypots']}")
        report.append(f"  • FakeSSH — port {FAKE_SSH_PORT}")
        report.append(f"  • FakeHTTP — port {FAKE_HTTP_PORT}")
        report.append(f"\n{i18n.t('honeypot_connections_today')}: {stats['total_today']}")
        report.append(f"{i18n.t('honeypot_connections_total')}: {stats['total_all']}")

        if stats["top_ips"]:
            report.append(f"\n{i18n.t('honeypot_top_attackers')}")
            for ip, count in stats["top_ips"]:
                report.append(f"  • `{ip}` — {count} connections")

        if stats["recent"]:
            report.append(f"\n{i18n.t('honeypot_recent')}")
            for r in stats["recent"][:3]:
                payload_preview = (r["payload"] or "")[:60]
                report.append(
                    f"  • `{r['ip']}` → {r['service']}:{r['port']}\n"
                    f"    {r['timestamp']} | {payload_preview}"
                )

        if not stats["total_all"]:
            report.append(f"\n{i18n.t('honeypot_no_connections')}")

        return "\n".join(report)


# Singleton Instance
honeypot_manager = HoneypotManager()
