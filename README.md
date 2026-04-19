<p align="center">
  <img src="assets/heimdall_lite_banner.png" alt="Heimdall-Lite Banner" width="100%">
</p>

# Heimdall-Lite: Micro-SOC AI Security Agent 🛡️

**Advanced Cybersecurity AI Agent** dirancang khusus untuk perlindungan proaktif dengan sumber daya minimalis. 

Heimdall-Lite adalah **Pertahanan Lapis Kedua (Layer-2 Defense)** cerdas yang berjalan efisien bahkan di atas mesin berspesifikasi sangat rendah (seperti AMD A4, 4GB RAM) yang beroperasi di belakang Cloudflare Tunnel. Heimdall-Lite tidak sekadar mencatat log, tetapi mendeteksi, menganalisis dengan AI, dan merespons ancaman secara otomatis (*Sense → Think → Act*).

---

## 🔥 Keunggulan Utama (Why Heimdall-Lite?)

- **Zero Local Compute AI:** Menggunakan infrastruktur **Ollama Cloud** (seperti *minimax-m1:cloud*, *gemma3:cloud*) untuk inferensi AI kompleks. Beban CPU lokal hampir 0%, memastikan server sekecil apapun tetap bisa memiliki *Security Operations Center* canggih.
- **Fail-Secure & Rule-Based Fallback:** Sistem tidak akan *freeze* atau pasif saat API down. Jika analisis LLM mengalami timeout atau mengembalikan JSON error, Heimdall-Lite langsung mengaktifkan jalur **Rule-Based Fallback** deterministik tanpa latensi.
- **Arsitektur Memori 3 Lapis:** 
  - **Short-Term Memory (STM):** Melacak aktivitas agresif dalam 30-60 menit terakhir.
  - **Long-Term Memory (LTM):** SQLite database otomatis merekam jejak riwayat insiden, *false positives*, dan *whitelist*.
  - **Global Memory (GM):** Aturan mutlak mutlak (seperti *blacklist paths* atau username terlarang) yang mempercepat waktu respons ancaman di bawah 1 detik tanpa melibatkan proses LLM.
- **Auto-Dream & Self-Learning:** Setiap malam, Heimdall-Lite merangkum pola serangan harian dari LTM dan melaporkan ke admin, membangun "ingatan" musuh jangka panjang agar semakin pintar setiap harinya.
- **Anti-Prompt Injection:** Filter sanitasi input ketat mencegah serangan langsung. Setiap *log entry* disterilkan sebelum ke prompt LLM untuk memastikan tidak ada payload JSON tersembunyi yang "membajak" perintah AI.

## 🛡️ Tipe Serangan yang Dideteksi

Heimdall-Lite dirancang untuk memitigasi vektor serangan berikut secara *real-time*:
1. **Brute Force & Credential Stuffing:** Mendeteksi percobaan login berulang yang gagal pada SSH atau Web, serta penggunaan *username* terlarang.
2. **Directory Traversal / LFI:** Memblokir seketika akses ke path sensitif (contoh: `/.env`, `/.git`, `/etc/passwd`, atau direktori *config* tersembunyi).
3. **Vulnerability Scanning (HTTP Scanning):** Mengenali bot yang mencari celah keamanan dengan melakukan *scan* membabi buta (ditandai dengan lonjakan *error* 404 beruntun).
4. **Lateral Movement:** Mendeteksi aktivitas atau percobaan akses aneh yang bersumber dari dalam jaringan lokal sendiri.
5. **Log-Based Prompt Injection:** Kebal terhadap *hacker* yang mencoba menyuntikkan instruksi *bypass* LLM ke dalam entri log (misal lewat URL/User-Agent).

## 🏗️ Arsitektur Tiga Pilar

Heimdall-Lite memisahkan fungsionalitasnya menjadi 3 pilar utama:
1. **🔍 SENSOR (Log Watcher):** Eksekusi *event-driven* (bukan polling) yang memantau `/var/log/auth.log` dan `/var/log/nginx/access.log`. Mengekstrak entitas kritis secara efisien (IP, timestamp, path, method) setiap kali baris terdeteksi.
2. **🧠 BRAIN (AI Communicator):** Merakit prompt dengan cerdas dari gabungan log tersanitasi + memori STM/LTM, kemudian mengirimnya ke AI. Mampu mengambil keputusan (BLOCK, ALERT, NONE) berbasis output JSON yang divalidasi ketat.
3. **💪 MUSCLE (Executor & Reporter):** Melakukan eksekusi aman via API pinggiran (Cloudflare) atau *subprocess* terlindungi (UFW). Perintah sangat selektif dan di-*whitelist* guna mencegah *shell injection*. Admin selalu mendapat notifikasi Telegram secara *real-time*.

## 🚀 Panduan Setup & Deployment

### Persyaratan
- Linux (Debian/Ubuntu Server Headless direkomendasikan)
- Python 3.10+
- Kredensial: Akun Telegram (untuk bot) & API Key Cloudflare
- Endpoint Ollama lokal untuk menjembatani LLM cloud (misal: `minimax-m1:cloud`)

### Setup Cepat

1. **Clone & Environment Setup**
   ```bash
   git clone <repo>
   cd heimdall-lite
   cp .env.example .env
   # Edit file .env dengan token Cloudflare, Telegram, dan Endpoint Ollama
   chmod 600 .env # Wajib, keamanan secret!
   ```

2. **Install Dependensi & Inisiasi Database**
   ```bash
   pip install -r requirements.txt
   python3 scripts/init_db.py
   ```

3. **Jalankan Agent (Mode Test/Console)**
   ```bash
   sudo -u agent-user python3 main.py
   ```
   *(Untuk operasional jangka panjang, buatkan systemd service agar berjalan di background).*

## 📱 Interaksi Admin via Telegram

Pusat kendali berada tepat di saku Anda. Gunakan command ini pada Bot Telegram:
- `/status` — Ringkasan ancaman 24 jam terakhir.
- `/block <IP>` — Eksekusi paksa blokir IP secara manual.
- `/allow <IP>` — *Whitelist* IP / bebaskan blokir.
- `/check <IP>` — Lihat riwayat insiden IP yang tersimpan dalam LTM.
- `/health` — Diagnosa status keaktifan Sensor, AI Brain, dan Executor.

---
*Heimdall-Lite didesain dengan filosofi **Zero-Trust** dan **Defense in Depth**. Tidak ada satu pun ancaman yang dibiarkan lewat tanpa analisa.*
