import os
import time
from pathlib import Path
from dotenv import load_dotenv

# Setup Environment
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# Import Modules
from modules.sensor import LogSensor
from modules.memory import STM, LTM
from modules.brain import brain
from modules.executor import executor
from modules.reporter import reporter

def process_pipeline(event: dict):
    """
    Core Event Loop Pipeline.
    Jalur eksekusi: Sensor -> Memory Update -> Brain Analysis -> Executor -> Reporter
    """
    ip = event.get("ip")
    if not ip:
        return

    print(f"\n[PIPELINE] Memproses event dari IP: {ip}")
    
    # 1. Memory Update (STM)
    # Catat aktivitas terbaru IP ini ke dalam Short-Term Memory
    STM.increment(ip, failed_attempts=1, path=event.get("path"), service=event.get("service"))
    
    # 2. Brain Analysis (Mencakup Sanitizer, Memory Context, LLM, dan Fallback)
    decision = brain.analyze(event)
    
    status = decision.get("status", "SAFE")
    action = decision.get("action", "NONE")
    reason = decision.get("reason", "")
    confidence = decision.get("confidence", 0.0)
    
    # 3. Executor & Reporter
    if action in ["BLOCK_CF", "BLOCK_UFW"]:
        print(f"[PIPELINE] 🛑 Keputusan: BLOKIR {ip} via {action}")
        
        # Eksekusi blokir
        executed = False
        if action == "BLOCK_CF":
            executed = executor.block_cloudflare(ip, reason)
        elif action == "BLOCK_UFW":
            executed = executor.block_ufw(ip)
            
        if executed:
            # Catat insiden ke Long-Term Memory (Database)
            LTM.add_incident(ip, threat_type=status, action=action, reason=reason, confidence=confidence)
            # Bersihkan STM karena IP sudah diblokir
            STM.flush(ip)
            
            # Kirim notifikasi Telegram
            msg = f"🚨 *THREAT BLOCKED*\nTarget: `{ip}`\nAction: `{action}`\nReason: {reason}\nConfidence: {confidence}"
            reporter.send_message(msg)
            
    elif action == "ALERT_ONLY":
        print(f"[PIPELINE] ⚠️ Keputusan: ALERT {ip}")
        msg = f"⚠️ *SUSPICIOUS ACTIVITY*\nTarget: `{ip}`\nReason: {reason}\nConfidence: {confidence}"
        reporter.send_message(msg)
        
    else: # SAFE / NONE
        print(f"[PIPELINE] ✅ Keputusan: SAFE ({ip})")

def start_micro_soc():
    """Entry point untuk menjalankan Micro-SOC"""
    print("========================================")
    print("🛡️  MICRO-SOC AGENT INITIALIZATION...   ")
    print("========================================")
    
    # 1. Jalankan Telegram Reporter di Background
    reporter.start_in_background()
    
    # 2. Siapkan direktori logs jika belum ada
    LOGS_DIR = BASE_DIR / "logs"
    LOGS_DIR.mkdir(exist_ok=True)
    auth_log = str(LOGS_DIR / "auth.log")
    nginx_log = str(LOGS_DIR / "access.log")
    
    # 3. Inisialisasi Sensor dan sambungkan ke Pipeline
    sensor = LogSensor(callback=process_pipeline)
    sensor.watch_file(auth_log, "auth")
    sensor.watch_file(nginx_log, "nginx")
    
    print("\n[INFO] Micro-SOC aktif dan siap melindungi server.")
    print("[INFO] Tekan Ctrl+C untuk menghentikan.\n")
    
    # 4. Memulai Monitoring Log (Blocking Loop)
    sensor.start()

if __name__ == "__main__":
    start_micro_soc()
