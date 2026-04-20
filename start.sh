#!/usr/bin/env bash
# ============================================
# Heimdall-Lite — Startup Launcher
# ============================================
# Script ini memastikan Heimdall berjalan dengan hak akses root
# sehingga scanner, executor, dan remediation tidak pernah
# meminta password di tengah operasi.
# ============================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python3"
SYSTEM_PYTHON="$(command -v python3)"

# Pilih Python interpreter
if [ -f "$VENV_PYTHON" ]; then
    PYTHON="$VENV_PYTHON"
else
    PYTHON="$SYSTEM_PYTHON"
fi

# Banner
echo ""
echo "  ╔═══════════════════════════════════════╗"
echo "  ║  🛡️  Heimdall-Lite Micro-SOC Agent    ║"
echo "  ╚═══════════════════════════════════════╝"
echo ""

# Cek apakah sudah root
if [ "$(id -u)" -eq 0 ]; then
    echo "[✅] Berjalan sebagai root."
    exec "$PYTHON" "$SCRIPT_DIR/main.py" "$@"
else
    echo "[🔐] Heimdall membutuhkan akses root untuk:"
    echo "     • Membaca /var/log/auth.log"
    echo "     • Menjalankan UFW firewall"
    echo "     • Scanning konfigurasi SSH"
    echo "     • File Integrity Monitoring"
    echo ""
    echo "[🔑] Masukkan password sudo Anda (hanya sekali):"
    echo ""
    
    # Minta password sekali, lalu jalankan sebagai root
    exec sudo -E "$PYTHON" "$SCRIPT_DIR/main.py" "$@"
fi
