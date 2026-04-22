# Heimdall-Lite Workflow

Dokumen ini menjelaskan alur kerja Heimdall-Lite saat runtime, dari proses startup sampai mitigasi, pelaporan, dan pembelajaran adaptif.

## 1. Gambaran Besar

Heimdall-Lite bekerja sebagai agent host-defense yang menjalankan beberapa loop paralel:

- loop utama pemantauan log
- loop background untuk dashboard dan Telegram bot
- loop scanning dan self-healing berkala
- loop adaptive learning
- loop EDR process monitoring
- loop honeypot dan canary monitoring

Secara sederhana, alurnya:

```text
Startup
  -> Load config + env
  -> Start Telegram reporter
  -> Start dashboard
  -> Attach log sensors
  -> Start schedulers/modules background
  -> Process incoming events
  -> Analyze + decide
  -> Execute mitigation
  -> Store evidence/history
  -> Notify admin
  -> Learn from incidents
```

## 2. Startup Flow

Entry point utama ada di `main.py` melalui `start_micro_soc()`.

Saat proses dimulai, Heimdall-Lite melakukan urutan berikut:

1. Load `.env` dan `config.yaml`.
2. Inisialisasi status `Safe Mode`.
3. Menjalankan Telegram reporter di background.
4. Menjalankan dashboard web di background.
5. Menyiapkan file log yang akan diawasi.
6. Menghubungkan `LogSensor` ke pipeline utama.
7. Menjalankan scheduler auto-scan di background.
8. Menjalankan scheduler adaptive learning di background.
9. Mengaktifkan monitoring canary file.
10. Mengaktifkan EDR process monitor.
11. Menyalakan honeypot SSH dan HTTP.
12. Membuat snapshot backup awal untuk self-healing.
13. Memulai monitoring log sebagai loop blocking utama.

## 3. Sumber Event

Heimdall-Lite menerima event dari beberapa sumber:

- `auth.log`
  Untuk mendeteksi percobaan login SSH gagal atau user invalid.
- `access.log` web server
  Untuk mendeteksi probing path sensitif seperti `/.env`, `/wp-login.php`, dan sejenisnya.
- honeypot TCP
  Untuk mendeteksi koneksi langsung ke port jebakan.
- canary files
  Untuk mendeteksi akses ke file umpan.
- process monitor `/proc`
  Untuk mendeteksi proses mencurigakan di host.
- scheduler scan
  Untuk mendeteksi kelemahan konfigurasi host.

## 4. Log Processing Flow

Alur utama event dari log berjalan seperti ini:

```text
Log file changed
  -> LogSensor reads new lines
  -> Parser converts line into normalized event
  -> process_pipeline(event)
  -> Fast checks
  -> STM/LTM/Threat Intel/Brain
  -> Decision
  -> Executor
  -> LTM update + alert
```

### 4.1 Parsing

`modules/core/sensor.py` melakukan parsing:

- log SSH gagal menjadi event dengan `service=ssh`, `ip`, `username`
- log akses web menjadi event dengan `service=nginx`, `ip`, `path`, `status_code`

Setelah itu event dikirim ke `process_pipeline(event)`.

### 4.2 Fast Path

Sebelum memanggil AI, pipeline melakukan keputusan cepat:

- jika IP ada di `Global Memory`, langsung blokir
- jika path ada di blacklist `Global Memory`, langsung blokir
- jika IP ada di whitelist `Long-Term Memory`, event diabaikan
- jika path cocok dengan daftar honeypot path statis, langsung blokir

Tujuan tahap ini adalah memberi jalur mitigasi berlatensi rendah tanpa bergantung pada LLM.

### 4.3 Short-Term Memory

Jika event tidak terkena fast path, pipeline memperbarui `STM`:

- menambah `failed_attempts`
- memperbarui `last_seen`
- mencatat path yang diakses
- menyimpan service asal

STM dipakai untuk mendeteksi lonjakan aktivitas dan rate-limit berbasis jangka pendek.

### 4.4 Rate Limit / DDoS Check

Setelah STM diupdate, pipeline membandingkan jumlah percobaan dengan threshold `pipeline.rate_limit`.

Jika melebihi threshold:

- IP diblokir
- incident dicatat ke `LTM`
- admin diberi notifikasi
- konteks STM IP tersebut dihapus

### 4.5 Threat Intelligence Enrichment

Sebelum analisis AI, Heimdall-Lite dapat memperkaya context IP dengan threat intel, seperti:

- skor AbuseIPDB
- jumlah report
- negara asal IP

Informasi ini menambah konteks untuk reason dan pelaporan.

### 4.6 Brain Analysis

Jika event masih perlu dianalisis, `Brain.analyze()` melakukan:

1. ambil context STM untuk IP terkait
2. ambil histori insiden IP dari LTM
3. cek apakah IP pernah ditandai false positive
4. sanitasi input log
5. bangun prompt untuk model LLM
6. kirim prompt ke endpoint Ollama/OpenAI-compatible
7. parse JSON hasil keputusan

Output keputusan minimal berisi:

- `status`
- `confidence`
- `action`
- `target`
- `reason`

### 4.7 Fallback Logic

Jika LLM gagal karena timeout, respons invalid, atau format JSON rusak:

- pipeline jatuh ke rule-based fallback engine
- sistem tetap membuat keputusan tanpa menghentikan alur utama

Ini menjaga sifat fail-secure.

### 4.8 Decision and Mitigation

Jika hasil analisis memutuskan aksi:

- `BLOCK_CF`
  IP diblokir di Cloudflare
- `BLOCK_UFW`
  IP diblokir di firewall lokal/host
- `ALERT_ONLY`
  tidak ada blokir, hanya kirim alert
- `NONE`
  event dianggap aman

Saat aksi sukses:

- insiden disimpan ke `LTM`
- STM untuk IP terkait di-flush
- admin menerima notifikasi Telegram

### 4.9 Botnet / Cluster Detection

Di akhir pipeline, Heimdall-Lite mengecek pola serangan terkoordinasi:

- beberapa IP menyerang path atau service serupa
- jika memenuhi kriteria cluster, semua IP dalam cluster bisa diblokir
- jika multi-server aktif, block dapat difederasikan ke server lain

## 5. Memory Architecture

Heimdall-Lite memakai tiga lapisan memori:

### 5.1 STM

`Short-Term Memory` disimpan di file JSON.

Fungsinya:

- menyimpan konteks runtime 30-60 menit
- menghitung attempt jangka pendek
- melacak path yang sedang diakses IP tertentu

### 5.2 LTM

`Long-Term Memory` disimpan di SQLite.

Fungsinya:

- menyimpan histori insiden
- menyimpan whitelist
- menyimpan false positive
- menjadi sumber forensic dan adaptive learning

### 5.3 GM

`Global Memory` disimpan di file JSON static rules.

Fungsinya:

- blacklist path
- known malicious IPs
- forbidden usernames

GM dipakai untuk fast path tanpa perlu analisis AI.

## 6. Background Modules

Selain pipeline utama, beberapa modul terus berjalan di background.

### 6.1 Telegram Reporter

Reporter memiliki dua fungsi:

- mengirim alert saat insiden terjadi
- menerima command admin seperti `/scan`, `/remediate`, `/block`, `/allow`, `/forensic`, `/edr`, `/honeypot`, `/backup`, `/heal`, dan `/safemode`

Dengan ini, admin bisa mengontrol agent tanpa login ke host.

### 6.2 Dashboard

Dashboard menampilkan status SOC secara real time, termasuk aktivitas dan statistik insiden.

### 6.3 Auto-Scan Scheduler

Scheduler ini berjalan periodik berdasarkan `scanner.interval_hours`.

Tugasnya:

- menjalankan host vulnerability scan
- mengecek firewall
- audit SSH
- melihat service yang gagal
- memantau integritas file
- audit authorized keys
- mengirim alert hanya jika ada temuan

### 6.4 Self-Healing

Self-healing bekerja dalam dua tahap:

1. membuat baseline backup file penting
2. membandingkan hash file host saat ini dengan baseline

Jika file berubah:

- simpan evidensi perubahan
- jika file aman untuk auto-restore, file dipulihkan
- service terkait direstart jika perlu
- semua tindakan dicatat dan dilaporkan

Untuk file sangat sensitif seperti `/etc/passwd` dan `/etc/shadow`, mode default adalah alert-only.

### 6.5 EDR Process Monitor

EDR memindai proses host secara periodik.

Yang dicari:

- shell dijalankan oleh restricted users seperti `www-data`
- binary berbahaya seperti `bash`, `nc`, `python`, `curl`
- executable dari direktori staging seperti `/tmp` atau `/dev/shm`
- command line pattern reverse shell atau download-and-execute

Jika `Safe Mode` nonaktif, proses mencurigakan bisa di-`SIGKILL`.

### 6.6 Honeypot

Ada dua honeypot:

- fake SSH di port `2222`
- fake HTTP admin panel di port `8888`

Fungsinya:

- menarik attacker ke service jebakan
- mencatat payload dan credential attempt
- menahan attacker dengan teknik tarpit
- auto-block IP setelah ambang koneksi tertentu

### 6.7 Canary

Canary module men-deploy file jebakan seperti backup atau env file.

Jika file disentuh:

- trigger alert
- dicatat sebagai indikator intrusi

### 6.8 Adaptive Learning

Scheduler learning membaca histori insiden yang sudah tersimpan, lalu mencari pola berulang.

Contohnya:

- IP yang sering diblokir
- path yang sering muncul pada incident reason

Jika melewati threshold:

- IP ditambahkan ke `known_malicious_ips`
- path ditambahkan ke `blacklist_paths`

Hasilnya, serangan serupa berikutnya bisa diblokir via fast path tanpa perlu analisis ulang.

## 7. Safe Mode

`Safe Mode` adalah sakelar global untuk aksi destruktif.

Jika `Safe Mode` aktif:

- block firewall tidak dijalankan
- kill process tidak dijalankan
- remediation tidak diterapkan
- self-heal restore tidak dijalankan
- sistem hanya alert

Jika `Safe Mode` nonaktif:

- mitigasi berjalan penuh

Statusnya dapat berasal dari:

- database
- `.env`
- command Telegram `/safemode`

## 8. Docker Compose Host-Defense Flow

Jika Heimdall-Lite dijalankan dengan `docker compose` bawaan repo ini:

- container berjalan sebagai profile host-defense penuh
- host root dimount ke `/host`
- container join host PID namespace dan network namespace
- command host dijalankan via `nsenter -t 1`

Artinya modul berikut bekerja terhadap host asli:

- firewall/UFW
- `systemctl`
- pembacaan `/proc`
- FIM dan self-healing file `/etc/*`
- honeypot pada port host

Secara praktik, ini membuat container bertindak seperti agent keamanan host, bukan aplikasi container biasa.

## 9. Incident Lifecycle

Satu insiden tipikal berjalan seperti ini:

```text
Attacker probes /.env
  -> Nginx log updated
  -> Sensor parses event
  -> Pipeline sees honeypot/static sensitive path
  -> IP blocked via Cloudflare/UFW
  -> Incident saved to SQLite
  -> Telegram alert sent
  -> Future repeated behavior may be learned into GM
```

Contoh lain:

```text
Compromised web process launches reverse shell
  -> EDR scans /proc
  -> Threat pattern matches
  -> Process killed
  -> Incident stored
  -> Admin notified
```

## 10. Ringkasan Alur End-to-End

```text
Startup
  -> Initialize modules
  -> Start monitors and services

Incoming signal
  -> Log / honeypot / canary / process / scheduler

Normalization
  -> Event parsed into internal format

Decision
  -> GM fast path
  -> whitelist check
  -> STM update
  -> rate limit check
  -> threat intel enrichment
  -> LLM or fallback analysis

Action
  -> block / alert / kill / restore / restart / federated block

Persistence
  -> save incident, evidence, snapshots, learning data

Notification
  -> Telegram + dashboard

Improvement loop
  -> adaptive learning updates static rules
```

## 11. File Map

Beberapa file utama yang membentuk workflow ini:

- `main.py`
  Orkestrator startup dan pipeline utama.
- `modules/core/sensor.py`
  Monitoring log dan parsing event.
- `modules/core/brain.py`
  Analisis AI dan fallback.
- `modules/core/memory.py`
  STM, LTM, dan GM.
- `modules/core/executor.py`
  Eksekusi blokir Cloudflare dan UFW.
- `modules/core/reporter.py`
  Telegram command center.
- `modules/security/scanner.py`
  Host vulnerability scanner.
- `modules/security/remediation.py`
  Auto-remediation.
- `modules/security/edr.py`
  Process monitoring dan kill.
- `modules/security/honeypot.py`
  Honeypot SSH/HTTP dan tarpit.
- `modules/security/selfheal.py`
  Backup, FIM, dan auto-restore.
- `modules/intel/learning.py`
  Adaptive learning ke Global Memory.

