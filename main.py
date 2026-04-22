import os
import time
import yaml
import threading
from pathlib import Path
from dotenv import load_dotenv

# Setup Environment
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

class ConfigManager:
    def __init__(self, config_file):
        self.config = {}
        try:
            if config_file.exists():
                with open(config_file, 'r') as f:
                    self.config = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"[WARN] Error loading config: {e}")

    def get(self, key, default=None):
        keys = key.split('.')
        val = self.config
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val

config = ConfigManager(BASE_DIR / "config.yaml")

# Import Modules
from modules.core.sensor import LogSensor
from modules.core.memory import STM, LTM, GM
from modules.core.brain import brain
from modules.core.executor import executor
from modules.core.reporter import reporter
from modules.security.scanner import scanner
from modules.intel.threat_intel import threat_intel
from modules.infra.dashboard import start_dashboard_in_background
from modules.security.clustering import cluster_detector
from modules.security.canary import canary
from modules.intel.learning import adaptive_learning
from modules.infra.multi_server import multi_server
from modules.security.edr import process_monitor
from modules.security.honeypot import honeypot_manager
from modules.security.selfheal import self_healer
from modules.core.safe_mode import safe_mode

ALERT_DEDUPE_COOLDOWN = int(config.get("pipeline.alert_dedupe_cooldown_seconds", 300))
CANARY_DEDUPE_COOLDOWN = int(config.get("pipeline.canary_alert_dedupe_cooldown_seconds", 300))

def process_pipeline(event: dict):
    """
    Core Event Loop Pipeline.
    Jalur eksekusi: Sensor -> Memory Update -> Brain Analysis -> Executor -> Reporter
    """
    ip = event.get("ip")
    if not ip:
        return

    print(f"\n[PIPELINE] Memproses event dari IP: {ip}")
    
    # ── Fast Path — bypass Brain sepenuhnya ──
    path_val = event.get("path", "")
    if path_val is None:
        path_val = ""
        
    if GM.is_known_bad_ip(ip) or GM.is_blacklisted_path(path_val):
        try:
            executor.block_cloudflare(ip, "GM Fast Path")
        except Exception as e:
            print(f"[PIPELINE] \u274c Executor gagal: {e}")
            reporter.send_message(f"\u274c Executor error untuk {ip}: {e}")
            
        LTM.add_incident(ip, threat_type="THREAT", action="BLOCK_CF", reason="GM Fast Path match", confidence=1.0)
        reporter.send_message(
            f"\u26a1 FAST BLOCK: `{ip}`",
            dedupe_key=f"fast_block:{ip}",
            cooldown=ALERT_DEDUPE_COOLDOWN,
        )
        return
    
    if LTM.is_whitelisted(ip):
        print(f"[PIPELINE] \u2705 {ip} ada di whitelist, diabaikan.")
        return

    # ── Honeypot Trap — jebakan 100% akurat ──
    honeypot_paths = ["/wp-admin", "/wp-login.php", "/phpmyadmin", "/.env", "/.git/config",
                      "/admin/config.php", "/backup.sql", "/db.sql", "/.htpasswd",
                      "/server-status", "/shell.php", "/cmd.php", "/c99.php"]
    if path_val in honeypot_paths:
        print(f"[PIPELINE] \U0001f36f HONEYPOT HIT: {ip} mengakses {path_val}")
        try:
            executor.block_cloudflare(ip, f"Honeypot Trap: {path_val}")
            executor.block_ufw(ip)
        except Exception as e:
            print(f"[PIPELINE] \u274c Executor gagal: {e}")
        LTM.add_incident(ip, threat_type="HONEYPOT", action="BLOCK_CF_UFW", 
                         reason=f"Honeypot trap: accessed {path_val}", confidence=1.0)
        reporter.send_message(
            f"\U0001f36f *HONEYPOT TRAP*\nIP: `{ip}`\nPath: `{path_val}`\n"
            f"Action: Blocked (CF + UFW)\nConfidence: 1.0",
            dedupe_key=f"honeypot:{ip}:{path_val}",
            cooldown=ALERT_DEDUPE_COOLDOWN,
        )
        STM.flush(ip)
        return

    # ── Rate Limit / DDoS Detection ──
    # Catat aktivitas terbaru IP ini ke dalam Short-Term Memory
    STM.increment(ip, failed_attempts=1, path=event.get("path"), service=event.get("service"))
    stm_data = STM.get(ip)
    
    rate_limit = int(config.get("pipeline.rate_limit", 30))
    if stm_data and stm_data.get("failed_attempts", 0) >= rate_limit:
        print(f"[PIPELINE] \U0001f6a8 RATE LIMIT: {ip} mencapai {stm_data['failed_attempts']} attempts!")
        try:
            executor.block_cloudflare(ip, f"Rate limit exceeded: {stm_data['failed_attempts']} attempts")
            executor.block_ufw(ip)
        except Exception as e:
            print(f"[PIPELINE] \u274c Executor gagal: {e}")
        LTM.add_incident(ip, threat_type="DDOS", action="BLOCK_CF_UFW",
                         reason=f"Rate limit: {stm_data['failed_attempts']} attempts in 60min",
                         confidence=0.95)
        reporter.send_message(
            f"\U0001f6a8 *RATE LIMIT / DDoS*\nIP: `{ip}`\n"
            f"Attempts: {stm_data['failed_attempts']} dalam 60 menit\n"
            f"Action: Blocked (CF + UFW)",
            dedupe_key=f"ddos:{ip}",
            cooldown=ALERT_DEDUPE_COOLDOWN,
        )
        STM.flush(ip)
        return

    # ── Threat Intelligence Enrichment ──
    intel_context = ""
    try:
        intel = threat_intel.enrich(ip)
        if intel.get("is_dangerous"):
            intel_context = (f" | AbuseIPDB: {intel['abuse_score']}/100, "
                            f"{intel['total_reports']} reports, {intel['country']}")
            print(f"[PIPELINE] \u26a0\ufe0f Threat Intel: {ip} -> abuse_score={intel['abuse_score']}")
    except Exception as e:
        print(f"[PIPELINE] Threat Intel error: {e}")

    # ── Brain Analysis (Mencakup Sanitizer, Memory Context, LLM, dan Fallback) ──
    decision = brain.analyze(event)
    
    status = decision.get("status", "SAFE")
    action = decision.get("action", "NONE")
    reason = decision.get("reason", "") + intel_context
    confidence = decision.get("confidence", 0.0)
    
    # ── Executor & Reporter ──
    if action in ["BLOCK_CF", "BLOCK_UFW"]:
        print(f"[PIPELINE] \U0001f6d1 Keputusan: BLOKIR {ip} via {action}")
        
        executed = False
        try:
            if action == "BLOCK_CF":
                executed = executor.block_cloudflare(ip, reason)
            elif action == "BLOCK_UFW":
                executed = executor.block_ufw(ip)
        except Exception as e:
            print(f"[PIPELINE] \u274c Executor gagal: {e}")
            reporter.send_message(f"\u274c Executor error untuk {ip}: {e}")
            
        if executed:
            LTM.add_incident(ip, threat_type=status, action=action, reason=reason, confidence=confidence)
            STM.flush(ip)
            
            msg = f"\U0001f6a8 *THREAT BLOCKED*\nTarget: `{ip}`\nAction: `{action}`\nReason: {reason}\nConfidence: {confidence}"
            reporter.send_message(
                msg,
                dedupe_key=f"threat_blocked:{ip}:{status}:{action}",
                cooldown=ALERT_DEDUPE_COOLDOWN,
            )
            
    elif action == "ALERT_ONLY":
        print(f"[PIPELINE] \u26a0\ufe0f Keputusan: ALERT {ip}")
        msg = f"\u26a0\ufe0f *SUSPICIOUS ACTIVITY*\nTarget: `{ip}`\nReason: {reason}\nConfidence: {confidence}"
        reporter.send_message(
            msg,
            dedupe_key=f"alert_only:{ip}:{status}",
            cooldown=ALERT_DEDUPE_COOLDOWN,
        )
        
    else: # SAFE / NONE
        print(f"[PIPELINE] \u2705 Keputusan: SAFE ({ip})")

    # ── Botnet Detection (setiap event, cek clustering) ──
    try:
        botnet = cluster_detector.detect_botnet()
        if botnet["is_botnet"]:
            print(f"[PIPELINE] \U0001f916 BOTNET terdeteksi! {botnet['cluster_size']} IPs")
            for bot_ip in botnet["botnet_ips"]:
                try:
                    executor.block_cloudflare(bot_ip, "Botnet cluster detected")
                    executor.block_ufw(bot_ip)
                    LTM.add_incident(bot_ip, "BOTNET", "BLOCK_CF_UFW",
                                     "Botnet cluster auto-block", 0.9)
                    STM.flush(bot_ip)
                except Exception:
                    pass
            reporter.send_message(cluster_detector.format_report())
            # Federated block jika multi-server aktif
            if multi_server.servers:
                for bot_ip in botnet["botnet_ips"]:
                    multi_server.federated_block(bot_ip, "Botnet")
    except Exception as e:
        print(f"[PIPELINE] Botnet check error: {e}")

def auto_scan_scheduler():
    """
    Background scheduler yang menjalankan silent vulnerability scan.
    Berjalan setiap interval (default: 6 jam).
    Hanya mengirim alert jika ada masalah keamanan terdeteksi.
    """
    interval = int(config.get("scanner.interval_hours", 6)) * 3600
    print(f"[AUTO-SCAN] Scheduler aktif. Interval: {interval // 3600} jam")
    
    # Tunggu 60 detik agar semua modul selesai startup
    time.sleep(60)
    
    while True:
        try:
            print("[AUTO-SCAN] Menjalankan silent scan...")
            result = scanner.scan_silent()
            if result:
                # Ada masalah — kirim ke Telegram
                reporter.send_message(result)
                print("[AUTO-SCAN] ⚠️ Masalah terdeteksi, alert dikirim ke Telegram.")
            else:
                print("[AUTO-SCAN] ✅ Semua aman, tidak ada alert.")

            # Self-Healing check: cek apakah file kritis diubah dan auto-restore
            heal_actions = self_healer.check_and_heal()
            if heal_actions:
                heal_report = self_healer.format_heal_report()
                reporter.send_message(heal_report)
                print(f"[AUTO-SCAN] 🔄 Self-Healing: {len(heal_actions)} tindakan dilakukan.")

        except Exception as e:
            print(f"[AUTO-SCAN] ❌ Error: {e}")
        
        time.sleep(interval)

def canary_alert_handler(filepath, action):
    """Callback saat file canary tersentuh oleh penyusup"""
    msg = (
        f"\U0001f6a8 *CANARY TOKEN TRIGGERED!*\n\n"
        f"File: `{filepath}`\n"
        f"Action: {action}\n"
        f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"\u26a0\ufe0f *Ada penyusup di dalam server!*"
    )
    sent = reporter.send_message(
        msg,
        dedupe_key="canary:intrusion",
        cooldown=CANARY_DEDUPE_COOLDOWN,
    )
    if sent:
        print(f"[CANARY] \U0001f6a8 ALERT SENT: {filepath} -> {action}")
    else:
        print(f"[CANARY] Duplicate alert ditahan: {filepath} -> {action}")

def periodic_learning():
    """
    Background thread yang menjalankan adaptive learning secara berkala.
    Default: setiap 12 jam.
    """
    interval = int(config.get("learning.interval_hours", 12)) * 3600
    print(f"[LEARNING] Scheduler aktif. Interval: {interval // 3600} jam")
    time.sleep(120)  # Tunggu 2 menit setelah startup

    while True:
        try:
            result = adaptive_learning.learn_from_incidents()
            if result["learned_ips"] > 0 or result["learned_paths"] > 0:
                reporter.send_message(adaptive_learning.format_report())
                print(f"[LEARNING] \U0001f9e0 GM diperbarui: +{result['learned_ips']} IP, +{result['learned_paths']} paths")
            else:
                print("[LEARNING] \u2705 Tidak ada pattern baru.")
        except Exception as e:
            print(f"[LEARNING] \u274c Error: {e}")
        time.sleep(interval)

def start_micro_soc():
    """Entry point untuk menjalankan Micro-SOC"""
    print("========================================")
    print("\U0001f6e1\ufe0f  MICRO-SOC AGENT INITIALIZATION...   ")
    print("========================================")
    
    # Safe Mode status
    sm_label = "🟡 ON (alert-only)" if safe_mode.is_enabled else "🟢 OFF (full protection)"
    print(f"[INFO] 🛡️  Safe Mode: {sm_label}")
    print(f"[INFO] Toggle via Telegram: /safemode or .env: SAFE_MODE=true/false")
    
    # 1. Jalankan Telegram Reporter di Background
    reporter.start_in_background()
    
    # 2. Jalankan Dashboard Web di Background
    start_dashboard_in_background()
    
    # 3. Siapkan direktori logs jika belum ada
    LOGS_DIR = BASE_DIR / "logs"
    LOGS_DIR.mkdir(exist_ok=True)
    auth_log = config.get("sensor.auth_log", str(LOGS_DIR / "auth.log"))
    nginx_log = config.get("sensor.nginx_log", str(LOGS_DIR / "access.log"))
    
    # 4. Inisialisasi Sensor dan sambungkan ke Pipeline
    sensor = LogSensor(callback=process_pipeline)
    sensor.watch_file(auth_log, "auth")
    sensor.watch_file(nginx_log, "nginx")
    
    # 5. Jalankan Auto-Scan Scheduler di Background
    scan_thread = threading.Thread(target=auto_scan_scheduler, daemon=True)
    scan_thread.start()
    
    # 6. Jalankan Adaptive Learning Scheduler di Background
    learn_thread = threading.Thread(target=periodic_learning, daemon=True)
    learn_thread.start()
    
    # 7. Mulai Canary Monitoring (jika sudah di-deploy)
    canary.start_monitoring(alert_callback=canary_alert_handler)
    
    # 8. Mulai EDR Process Monitor di Background
    process_monitor.start()
    print("[INFO] 🦠 EDR Process Monitor aktif.")
    
    # 9. Mulai Honeypot Servers di Background
    try:
        honeypot_manager.start_all()
        print("[INFO] 🎭 Honeypot & Tarpitting aktif (port 2222, 8888).")
    except Exception as e:
        print(f"[WARNING] Honeypot gagal dimulai: {e}")
    
    # 10. Buat backup snapshot awal untuk Self-Healing (jika belum ada) 
    try:
        self_healer.create_backup_snapshot()
        print("[INFO] 🔄 Self-Healing backup snapshot siap.")
    except Exception as e:
        print(f"[WARNING] Self-Healing backup gagal: {e}")
    
    print("\n[INFO] Micro-SOC aktif dan siap melindungi server.")
    print("[INFO] Tekan Ctrl+C untuk menghentikan.\n")
    
    # 11. Memulai Monitoring Log (Blocking Loop)
    sensor.start()

if __name__ == "__main__":
    start_micro_soc()
