import os
import sys
import json
import sqlite3
import requests
from datetime import datetime, timedelta
from pathlib import Path

# Setup paths
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from modules.memory import STM, LTM, DB_PATH
from modules.reporter import reporter

# Ambil env vars dari .env (Sudah di-load oleh modul lain yang di-import)
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "minimax-m1:cloud")
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "")

def get_daily_stats():
    """Mengambil rekapitulasi data ancaman dari LTM dalam 24 jam terakhir"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
    
    cursor.execute("SELECT COUNT(*) as total FROM incidents WHERE timestamp > ?", (yesterday,))
    total_blocks = cursor.fetchone()["total"]
    
    cursor.execute("""
        SELECT ip, COUNT(*) as count 
        FROM incidents 
        WHERE timestamp > ? 
        GROUP BY ip 
        ORDER BY count DESC LIMIT 5
    """, (yesterday,))
    top_ips = [dict(row) for row in cursor.fetchall()]
    
    cursor.execute("""
        SELECT threat_type, COUNT(*) as count 
        FROM incidents 
        WHERE timestamp > ? 
        GROUP BY threat_type 
        ORDER BY count DESC LIMIT 5
    """, (yesterday,))
    top_threats = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return total_blocks, top_ips, top_threats

def generate_summary(total, top_ips, top_threats):
    """Meminta AI untuk menulis ringkasan ancaman (Tanpa format JSON)"""
    if total == 0:
        return "Tidur nyenyak! Tidak ada serangan yang masuk dalam 24 jam terakhir. Sistem sepenuhnya aman. 🌙"
        
    url = f"{OLLAMA_BASE_URL.rstrip('/')}/v1/chat/completions"
    headers = {"Content-Type": "application/json"}
    if OLLAMA_API_KEY:
        headers["Authorization"] = f"Bearer {OLLAMA_API_KEY}"
        
    prompt = f"Total serangan hari ini: {total}. IP penyerang tertinggi: {top_ips}. Kategori ancaman terbanyak: {top_threats}."
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": "Kamu adalah Kepala Security (SOC). Tulis ringkasan eksekutif singkat (maksimal 2 kalimat) dalam bahasa Indonesia mengenai kondisi keamanan server hari ini berdasarkan data. JANGAN tulis dalam format JSON. JANGAN tulis data mentah, jadikan sebuah insight."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.5
    }
    
    try:
        res = requests.post(url, json=payload, headers=headers, timeout=20)
        res.raise_for_status()
        return res.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"Berhasil memblokir {total} serangan hari ini. (Gagal generate AI Summary: {e})"

def cleanup_stm():
    """Menghapus IP yang sudah tidak aktif (stale) > 24 jam dari memori STM"""
    stm_data = STM._read_stm()
    expired_keys = []
    
    now = datetime.now()
    for ip, data in stm_data.items():
        last_seen_str = data.get("last_seen")
        if last_seen_str:
            try:
                last_seen = datetime.strptime(last_seen_str, "%Y-%m-%dT%H:%M:%S")
                # Expire jika lebih dari 24 jam (86400 detik)
                if (now - last_seen).total_seconds() > 86400:
                    expired_keys.append(ip)
            except ValueError:
                pass
                
    for ip in expired_keys:
        del stm_data[ip]
        
    if expired_keys:
        STM._write_stm(stm_data)
        
    return len(expired_keys)

def save_daily_summary(date_str, summary, top_threats_str, total_blocks):
    """Menyimpan ringkasan AI ke tabel daily_summary di LTM"""
    conn = LTM._get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO daily_summary (date, summary, top_threats, total_blocks)
        VALUES (?, ?, ?, ?)
    """, (date_str, summary, top_threats_str, total_blocks))
    conn.commit()
    conn.close()

def run_autodream():
    print("========================================")
    print("💤 MENGAKTIFKAN AUTODREAM PROTOCOL      ")
    print("========================================")
    
    # 1. Housekeeping: Bersihkan STM yang sudah "basi"
    cleaned = cleanup_stm()
    print(f"[AUTODREAM] Membersihkan {cleaned} IP kedaluwarsa dari Short-Term Memory.")
    
    # 2. Analytics: Rekap LTM 24 Jam
    total_blocks, top_ips, top_threats = get_daily_stats()
    print(f"[AUTODREAM] Menganalisis {total_blocks} insiden hari ini...")
    
    # 3. AI Reporting: Generate Executive Summary
    print("[AUTODREAM] Meminta AI menyusun ringkasan ancaman...")
    ai_summary = generate_summary(total_blocks, top_ips, top_threats)
    
    # 4. Storage: Simpan ke tabel LTM
    date_str = datetime.now().strftime("%Y-%m-%d")
    top_threats_str = json.dumps(top_threats)
    save_daily_summary(date_str, ai_summary, top_threats_str, total_blocks)
    
    # 5. Alerting: Broadcast Laporan ke Telegram
    msg = f"🌅 *Micro-SOC Daily Digest*\n\n"
    msg += f"🛡️ *Total Ancaman Diblokir:* {total_blocks}\n"
    msg += f"🤖 *AI Insight:*\n_{ai_summary}_\n\n"
    
    if top_ips:
        msg += "🎯 *Top Attackers (24H):*\n"
        for item in top_ips:
            msg += f"• `{item['ip']}` ({item['count']} insiden)\n"
            
    reporter.send_message(msg)
    print("✅ [AUTODREAM] Siklus selesai. Laporan harian terkirim ke Telegram.")

if __name__ == "__main__":
    run_autodream()
