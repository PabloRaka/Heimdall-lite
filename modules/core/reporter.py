import os
import requests
import asyncio
from threading import Thread
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, CallbackQueryHandler
from pathlib import Path

from modules.core.executor import executor
from modules.core.memory import LTM, GM
from modules.core.memory import DB_PATH
from modules.core.i18n import i18n, SUPPORTED_LANGUAGES
from modules.security.scanner import scanner
from modules.intel.threat_intel import threat_intel
from modules.intel.forensic import forensic
from modules.security.canary import canary
from modules.security.clustering import cluster_detector
from modules.security.remediation import remediation
from modules.intel.learning import adaptive_learning
from modules.infra.multi_server import multi_server
from modules.security.edr import process_monitor
from modules.security.honeypot import honeypot_manager
from modules.security.selfheal import self_healer
from modules.core.safe_mode import safe_mode
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
            self.app.add_handler(CommandHandler("lang", self.lang_command))
            self.app.add_handler(CommandHandler("edr", self.edr_command))
            self.app.add_handler(CommandHandler("edr_log", self.edr_log_command))
            self.app.add_handler(CommandHandler("honeypot", self.honeypot_command))
            self.app.add_handler(CommandHandler("backup", self.backup_command))
            self.app.add_handler(CommandHandler("heal", self.heal_command))
            self.app.add_handler(CommandHandler("safemode", self.safemode_command))
            self.app.add_handler(CommandHandler("help", self.help_command))
            # Inline keyboard callback untuk pemilihan bahasa
            self.app.add_handler(CallbackQueryHandler(self.lang_callback, pattern="^setlang:"))
        else:
            print("[WARNING] TELEGRAM_BOT_TOKEN tidak ditemukan. Reporter berjalan di mode Simulasi.")

    async def health_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /health. Mengecek apakah sistem hidup."""
        # Validasi keamanan: hanya merespons jika pengirimnya adalah Admin
        if str(update.effective_chat.id) != str(CHAT_ID):
            print(f"[REPORTER] Mengabaikan command dari chat id tidak sah: {update.effective_chat.id}")
            return

        status_msg = (
            f"{i18n.t('health_title')}\n"
            f"{i18n.t('health_status')}\n"
            f"{i18n.t('health_body')}"
        )
        await update.message.reply_text(status_msg, parse_mode="Markdown")
        print("[REPORTER] Command /health berhasil direspons.")

    async def block_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_chat.id) != str(CHAT_ID): return
        if not context.args:
            await update.message.reply_text(i18n.t("block_format"), parse_mode="Markdown")
            return
        ip = context.args[0]
        executor.block_cloudflare(ip, "Manual Block via Telegram")
        executor.block_ufw(ip)
        LTM.add_incident(ip, "MANUAL", "BLOCK_CF_UFW", "Manual block via Telegram", 1.0)
        await update.message.reply_text(i18n.t("block_success", ip=ip), parse_mode="Markdown")

    async def allow_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_chat.id) != str(CHAT_ID): return
        if not context.args:
            await update.message.reply_text(i18n.t("allow_format"), parse_mode="Markdown")
            return
        ip = context.args[0]
        executor.unblock_cloudflare(ip)
        executor.unblock_ufw(ip)
        LTM.add_whitelist(ip, "Telegram Whitelist", "admin")
        LTM.add_false_positive(ip, "Unblocked via Telegram")
        await update.message.reply_text(i18n.t("allow_success", ip=ip), parse_mode="Markdown")

    async def check_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_chat.id) != str(CHAT_ID): return
        if not context.args:
            await update.message.reply_text("Format: `/check <IP>`", parse_mode="Markdown")
            return
        ip = context.args[0]
        history = LTM.get_incident_history(ip)
        is_white = LTM.is_whitelisted(ip)
        wl_val = i18n.t("check_whitelist_yes") if is_white else i18n.t("check_whitelist_no")
        msg = f"{i18n.t('check_title', ip=ip)}\n{i18n.t('check_whitelist')}: {wl_val}\n"
        if not history:
            msg += i18n.t("check_history_clean")
        else:
            msg += f"{i18n.t('check_history_label', count=len(history))}\n"
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
        msg = (
            f"{i18n.t('status_title', date=today)}\n"
            f"{i18n.t('status_blocks', count=count)}"
        )
        await update.message.reply_text(msg, parse_mode="Markdown")

    async def scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_chat.id) != str(CHAT_ID): return
        
        # Kirim status loading
        await update.message.reply_text(i18n.t("scan_starting"), parse_mode="Markdown")
        
        # Lakukan pemindaian
        report = scanner.scan_all()
        
        # Kirim laporan hasil
        await update.message.reply_text(report, parse_mode="Markdown")

    async def rules_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_chat.id) != str(CHAT_ID): return
        rules = GM._get_rules()
        paths = ", ".join(rules.get('blacklist_paths', []))[:100] + "..."
        users = ", ".join(rules.get('forbidden_usernames', []))
        msg = (
            f"{i18n.t('rules_title')}\n"
            f"{i18n.t('rules_blacklist_paths', paths=paths)}\n"
            f"{i18n.t('rules_forbidden_users', users=users)}"
        )
        await update.message.reply_text(msg, parse_mode="Markdown")

    async def intel_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /intel <IP> — Cek reputasi IP via AbuseIPDB + GeoIP"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        if not context.args:
            await update.message.reply_text(i18n.t("intel_format"), parse_mode="Markdown")
            return
        ip = context.args[0]
        await update.message.reply_text(i18n.t("intel_checking", ip=ip), parse_mode="Markdown")
        report = threat_intel.format_intel_report(ip)
        await update.message.reply_text(report, parse_mode="Markdown")

    async def forensic_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /forensic <IP> — Generate forensic timeline untuk IP"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        if not context.args:
            await update.message.reply_text(i18n.t("forensic_format"), parse_mode="Markdown")
            return
        ip = context.args[0]
        await update.message.reply_text(i18n.t("forensic_checking", ip=ip), parse_mode="Markdown")
        report = forensic.generate(ip)
        await update.message.reply_text(report, parse_mode="Markdown")

    async def remediate_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /remediate — Auto-fix celah keamanan"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        await update.message.reply_text(i18n.t("remediate_starting"), parse_mode="Markdown")
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
        await update.message.reply_text(i18n.t("learn_analyzing"), parse_mode="Markdown")
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
            await update.message.reply_text(i18n.t("fblock_format"), parse_mode="Markdown")
            return
        ip = context.args[0]
        await update.message.reply_text(i18n.t("fblock_starting", ip=ip), parse_mode="Markdown")
        report = multi_server.format_block_report(ip)
        await update.message.reply_text(report, parse_mode="Markdown")

    async def deploy_canary_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /deploy_canary — Tanam file jebakan di server"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        await update.message.reply_text(i18n.t("canary_deploying"), parse_mode="Markdown")
        deployed = canary.deploy_canaries()
        if deployed:
            files = "\n".join([f"  • `{f}`" for f in deployed])
            msg = i18n.t("canary_deployed", count=len(deployed), files=files)
        else:
            msg = i18n.t("canary_none")
        await update.message.reply_text(msg, parse_mode="Markdown")

    async def lang_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /lang — Tampilkan pilihan bahasa dengan inline keyboard"""
        if str(update.effective_chat.id) != str(CHAT_ID): return

        # Buat inline keyboard dengan satu baris per bahasa
        keyboard = [
            [
                InlineKeyboardButton(
                    f"{meta['label']} {'✓' if i18n.is_current(code) else ''}".strip(),
                    callback_data=f"setlang:{code}"
                )
            ]
            for code, meta in SUPPORTED_LANGUAGES.items()
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(
            i18n.t("lang_select_prompt"),
            reply_markup=reply_markup,
            parse_mode="Markdown"
        )

    async def lang_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Callback handler saat user mengklik tombol pilihan bahasa"""
        query = update.callback_query
        await query.answer()  # Hapus loading state di Telegram

        if str(query.message.chat.id) != str(CHAT_ID):
            return

        # Ekstrak kode bahasa dari callback data (format: "setlang:xx")
        lang_code = query.data.split(":", 1)[-1]

        if i18n.is_current(lang_code):
            # Bahasa sudah aktif
            msg = i18n.t("lang_already_set")
        else:
            success = i18n.set_language(lang_code)
            if success:
                msg = i18n.t("lang_changed")
            else:
                msg = "❌ Language not supported."

        # Update pesan asli dengan tombol yang sudah di-refresh (tanda centang berpindah)
        keyboard = [
            [
                InlineKeyboardButton(
                    f"{meta['label']} {'✓' if i18n.is_current(code) else ''}".strip(),
                    callback_data=f"setlang:{code}"
                )
            ]
            for code, meta in SUPPORTED_LANGUAGES.items()
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            text=f"{i18n.t('lang_select_prompt')}\n\n{msg}",
            reply_markup=reply_markup,
            parse_mode="Markdown"
        )

    async def edr_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /edr — Status EDR Process Monitor"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        report = process_monitor.format_status_report()
        await update.message.reply_text(report, parse_mode="Markdown")

    async def edr_log_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /edr_log — Log proses yang dihentikan"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        report = process_monitor.format_log_report()
        await update.message.reply_text(report, parse_mode="Markdown")

    async def honeypot_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /honeypot — Statistik honeypot"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        report = honeypot_manager.format_report()
        await update.message.reply_text(report, parse_mode="Markdown")

    async def backup_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /backup — Buat backup snapshot file kritis"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        await update.message.reply_text(i18n.t("heal_backup_title"), parse_mode="Markdown")
        report = self_healer.format_backup_report()
        await update.message.reply_text(report, parse_mode="Markdown")

    async def heal_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /heal — Jalankan self-healing check"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        report = self_healer.format_heal_report()
        await update.message.reply_text(report, parse_mode="Markdown")

    async def safemode_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /safemode — Toggle Safe Mode on/off"""
        if str(update.effective_chat.id) != str(CHAT_ID): return
        new_state = safe_mode.toggle()
        if new_state:
            msg = i18n.t("safemode_enabled")
        else:
            msg = i18n.t("safemode_disabled")
        await update.message.reply_text(msg, parse_mode="Markdown")

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler /help — Daftar semua command"""
        if str(update.effective_chat.id) != str(CHAT_ID): return

        # Safe mode indicator
        sm_status = "🟡 ON" if safe_mode.is_enabled else "🟢 OFF"

        msg = (
            f"{i18n.t('help_title')}\n"
            f"{i18n.t('safemode_status', status=sm_status)}\n\n"
            f"{i18n.t('help_monitoring')}\n"
            f"{i18n.t('help_health')}\n"
            f"{i18n.t('help_status')}\n"
            f"{i18n.t('help_rules')}\n"
            f"{i18n.t('help_lang')}\n"
            f"{i18n.t('help_safemode')}\n\n"
            f"{i18n.t('help_investigation')}\n"
            f"{i18n.t('help_check')}\n"
            f"{i18n.t('help_intel')}\n"
            f"{i18n.t('help_forensic')}\n"
            f"{i18n.t('help_botnet')}\n\n"
            f"{i18n.t('help_defense')}\n"
            f"{i18n.t('help_block')}\n"
            f"{i18n.t('help_allow')}\n"
            f"{i18n.t('help_fblock')}\n"
            f"{i18n.t('help_scan')}\n"
            f"{i18n.t('help_remediate')}\n\n"
            f"{i18n.t('help_intelligence')}\n"
            f"{i18n.t('help_learn')}\n"
            f"{i18n.t('help_canary')}\n"
            f"{i18n.t('help_servers')}\n\n"
            f"{i18n.t('help_advanced')}\n"
            f"{i18n.t('help_edr')}\n"
            f"{i18n.t('help_edr_log')}\n"
            f"{i18n.t('help_honeypot')}\n"
            f"{i18n.t('help_backup')}\n"
            f"{i18n.t('help_heal')}"
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
