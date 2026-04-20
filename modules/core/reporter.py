import os
import requests
import asyncio
from threading import Thread
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from pathlib import Path

from modules.core.executor import executor
from modules.core.memory import LTM, GM
from modules.core.memory import DB_PATH
from modules.security.scanner import scanner
from modules.intel.threat_intel import threat_intel
from modules.intel.forensic import forensic
from modules.security.canary import canary
from modules.security.clustering import cluster_detector
from modules.security.remediation import remediation
from modules.intel.learning import adaptive_learning
from modules.infra.multi_server import multi_server
import sqlite3
import time
BASE_DIR = Path(__file__).resolve().parent.parent.parent
env_path = BASE_DIR / ".env"
load_dotenv(env_path)

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

class TelegramReporter:
    """
    Modul untuk melaporkan kejadian ke Admin via Telegram.
    Mendukung pengiriman pesan sinkron (requests) dan penerimaan command async.
    """
    def __init__(self):
        self.app = None
        if TOKEN:
            # Setup bot listener untuk command
            self.app = ApplicationBuilder().token(TOKEN).build()
            self.app.add_handler(CommandHandler("health", self.health_command))
            self.app.add_handler(CommandHandler("block", self.block_command))
            self.app.add_handler(CommandHandler("allow", self.allow_command))
            self.app.add_handler(CommandHandler("check", self.check_command))
            self.app.add_handler(CommandHandler("status", self.status_command))
            self.app.add_handler(CommandHandler("rules", self.rules_command))
            self.app.add_handler(CommandHandler("scan", self.scan_command))
            self.app.add_handler(CommandHandler("intel", self.intel_command))
            self.app.add_handler(CommandHandler("forensic", self.forensic_command))
            self.app.add_handler(CommandHandler("remediate", self.remediate_command))
            self.app.add_handler(CommandHandler("botnet", self.botnet_command))
            self.app.add_handler(CommandHandler("learn", self.learn_command))
            self.app.add_handler(CommandHandler("servers", self.servers_command))
            self.app.add_handler(CommandHandler("fblock", self.fblock_command))
            self.app.add_handler(CommandHandler("deploy_canary", self.deploy_canary_command))
            self.app.add_handler(CommandHandler("help", self.help_command))
        else:
            print("[WARNING] TELEGRAM_BOT_TOKEN tidak ditemukan. Reporter berjalan di mode Simulasi.")

    async def health_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /health. Mengecek apakah sistem hidup."""
        # Validasi keamanan: hanya merespons jika pengirimnya adalah Admin
        if str(update.effective_chat.id) != str(CHAT_ID):
            print(f"[REPORTER] Mengabaikan command dari chat id tidak sah: {update.effective_chat.id}")
            return

        status_msg = (
            "🟢 *Micro-SOC Health Status*\n"
            "Status: ACTIVE\n"
            "Semua sistem inti (Sensor, Memory, Fallback) beroperasi."
        )
        await update.message.reply_text(status_msg, parse_mode="Markdown")
        print("[REPORTER] Command /health berhasil direspons.")

    async def block_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_chat.id) != str(CHAT_ID): return
        if not context.args:
            await update.message.reply_text("Format: `/block <IP>`", parse_mode="Markdown")
            return
        ip = context.args[0]
        executor.block_cloudflare(ip, "Manual Block via Telegram")
        executor.block_ufw(ip)
        LTM.add_incident(ip, "MANUAL", "BLOCK_CF_UFW", "Manual block via Telegram", 1.0)
        await update.message.reply_text(f"✅ IP `{ip}` telah diblokir.", parse_mode="Markdown")

    async def allow_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_chat.id) != str(CHAT_ID): return
        if not context.args:
            await update.message.reply_text("Format: `/allow <IP>`", parse_mode="Markdown")
            return
        ip = context.args[0]
        executor.unblock_cloudflare(ip)
        executor.unblock_ufw(ip)
        LTM.add_whitelist(ip, "Telegram Whitelist", "admin")
        LTM.add_false_positive(ip, "Unblocked via Telegram")
        await update.message.reply_text(f"✅ IP `{ip}` telah dibebaskan dan masuk ke whitelist.", parse_mode="Markdown")

    async def check_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_chat.id) != str(CHAT_ID): return
        if not context.args:
            await update.message.reply_text("Format: `/check <IP>`", parse_mode="Markdown")
            return
        ip = context.args[0]
        history = LTM.get_incident_history(ip)
        is_white = LTM.is_whitelisted(ip)
        msg = f"🔍 *Check IP:* `{ip}`\nWhitelist: {'✅ Ya' if is_white else '❌ Tidak'}\n"
        if not history:
            msg += "Riwayat: Bersih."
        else:
            msg += f"Riwayat ({len(history)} insiden terakhir):\n"
            for h in history:
                msg += f"- {h['timestamp']} | {h['action']} | {h['reason']}\n"
        await update.message.reply_text(msg, parse_mode="Markdown")

    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_chat.id) != str(CHAT_ID): return
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        today = time.strftime("%Y-%m-%d")
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE timestamp LIKE ?", (f"{today}%",))
        result = cursor.fetchone()
        count = result[0] if result else 0
        conn.close()
        msg = f"📊 *Status Hari Ini ({today})*\nTotal Blokir Baru: {count}"
        await update.message.reply_text(msg, parse_mode="Markdown")

    async def scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_chat.id) != str(CHAT_ID): return
        
        # Kirim status loading
        await update.message.reply_text("🔄 *Memulai Eksekusi Vulnerability Scanner...*", parse_mode="Markdown")
        
        # Lakukan pemindaian
        report = scanner.scan_all()
        
        # Kirim laporan hasil
        await update.message.reply_text(report, parse_mode="Markdown")

    async def rules_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_chat.id) != str(CHAT_ID): return
        rules = GM._get_rules()
        paths = ", ".join(rules.get('blacklist_paths', []))[:100] + "..."
        users = ", ".join(rules.get('forbidden_usernames', []))
        msg = f"📋 *Global Rules*\n*Blacklist Paths:* {paths}\n*Forbidden Users:* {users}"
        await update.message.reply_text(msg, parse_mode="Markdown")

    async def intel_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /intel <IP> — Cek reputasi IP via AbuseIPDB + GeoIP"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        if not context.args:
            await update.message.reply_text("Format: `/intel <IP>`", parse_mode="Markdown")
            return
        ip = context.args[0]
        await update.message.reply_text(f"🔍 Mengecek intelijen untuk `{ip}`...", parse_mode="Markdown")
        report = threat_intel.format_intel_report(ip)
        await update.message.reply_text(report, parse_mode="Markdown")

    async def forensic_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /forensic <IP> — Generate forensic timeline untuk IP"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        if not context.args:
            await update.message.reply_text("Format: `/forensic <IP>`", parse_mode="Markdown")
            return
        ip = context.args[0]
        await update.message.reply_text(f"🔎 Generating forensic timeline untuk `{ip}`...", parse_mode="Markdown")
        report = forensic.generate(ip)
        await update.message.reply_text(report, parse_mode="Markdown")

    async def remediate_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /remediate — Auto-fix celah keamanan"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        await update.message.reply_text("🔧 *Menjalankan Auto-Remediation...*", parse_mode="Markdown")
        report = remediation.remediate_all()
        await update.message.reply_text(report, parse_mode="Markdown")

    async def botnet_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /botnet — Deteksi serangan terkoordinasi"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        report = cluster_detector.format_report()
        await update.message.reply_text(report, parse_mode="Markdown")

    async def learn_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /learn — Jalankan adaptive learning dari insiden"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        await update.message.reply_text("🧠 *Menganalisis pattern serangan...*", parse_mode="Markdown")
        report = adaptive_learning.format_report()
        await update.message.reply_text(report, parse_mode="Markdown")

    async def servers_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /servers — Health check semua remote server"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        report = multi_server.health_check_all()
        await update.message.reply_text(report, parse_mode="Markdown")

    async def fblock_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /fblock <IP> — Federated block di semua server"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        if not context.args:
            await update.message.reply_text("Format: `/fblock <IP>`", parse_mode="Markdown")
            return
        ip = context.args[0]
        await update.message.reply_text(f"🌐 *Memblokir `{ip}` di semua server...*", parse_mode="Markdown")
        report = multi_server.format_block_report(ip)
        await update.message.reply_text(report, parse_mode="Markdown")

    async def deploy_canary_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /deploy_canary — Tanam file jebakan di server"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        await update.message.reply_text("🍯 *Menanam file-file canary...*", parse_mode="Markdown")
        deployed = canary.deploy_canaries()
        if deployed:
            files = "\n".join([f"  • `{f}`" for f in deployed])
            msg = f"🍯 *Canary Deployed!*\n{len(deployed)} file ditanam:\n{files}"
        else:
            msg = "⚠️ Tidak ada file canary yang bisa ditanam (direktori tidak ada atau file sudah ada)."
        await update.message.reply_text(msg, parse_mode="Markdown")

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /help — Daftar semua command"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        msg = (
            "🛡️ *Heimdall Micro-SOC Commands*\n\n"
            "📊 *Monitoring*\n"
            "/health — Cek status agen\n"
            "/status — Statistik insiden hari ini\n"
            "/rules — Lihat Global Rules\n\n"
            "🔍 *Investigation*\n"
            "/check <IP> — Riwayat insiden IP\n"
            "/intel <IP> — Threat intelligence IP\n"
            "/forensic <IP> — Forensic timeline IP\n"
            "/botnet — Deteksi serangan botnet\n\n"
            "🛡️ *Defense*\n"
            "/block <IP> — Blokir IP\n"
            "/allow <IP> — Unblock IP\n"
            "/fblock <IP> — Blokir IP di semua server\n"
            "/scan — Vulnerability scan\n"
            "/remediate — Auto-fix celah keamanan\n\n"
            "🧠 *Intelligence*\n"
            "/learn — Adaptive learning dari insiden\n"
            "/deploy\\_canary — Tanam file jebakan\n"
            "/servers — Health check semua server"
        )
        await update.message.reply_text(msg, parse_mode="Markdown")

    def send_message(self, message: str):
        """
        Mengirim pesan ke Telegram secara sinkron.
        Menggunakan requests murni agar tidak bentrok dengan asyncio event loop milik bot.
        Sangat aman dipanggil dari thread mana pun.
        """
        if not TOKEN or not CHAT_ID:
            print(f"\n[REPORTER SIMULATION - No Token]")
            print("-" * 40)
            print(message)
            print("-" * 40)
            return
            
        url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
        payload = {
            "chat_id": CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        try:
            # Gunakan timeout agar tidak memblokir eksekusi utama jika API down
            response = requests.post(url, json=payload, timeout=5)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Gagal mengirim pesan ke Telegram: {e}")

    def start_polling(self):
        """Menjalankan listener command Telegram (blocking)"""
        if self.app:
            print("[REPORTER] Memulai Telegram Bot Command Listener...")
            # Gunakan stop_signals=None agar aman dijalankan di thread
            self.app.run_polling(close_loop=False, stop_signals=None)
            
    def start_in_background(self):
        """Menjalankan listener command Telegram di background thread"""
        if self.app:
            thread = Thread(target=self.start_polling, daemon=True)
            thread.start()

# Singleton Instance
reporter = TelegramReporter()
