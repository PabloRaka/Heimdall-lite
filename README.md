<p align="center">
  <img src="assets/heimdall_lite_banner.png" alt="Heimdall-Lite Banner" width="50%">
</p>

# Heimdall-Lite: Enterprise-Grade Micro-SOC AI Security Agent 🛡️

**Advanced Cybersecurity AI Agent** designed specifically for proactive protection with minimalist resource requirements.

Heimdall-Lite is an intelligent **Layer-2 Defense** that runs efficiently even on extremely low-spec machines operating behind a Cloudflare Tunnel. Heimdall-Lite doesn't just log events; it detects, analyzes with AI, and responds to threats automatically (*Sense → Think → Act*). It has recently been upgraded to include Enterprise-grade SOC features like IP Clustering, Auto-Remediation, Adaptive Learning, and Canary Tokens.

---

## 🔥 Key Features (Why Heimdall-Lite?)

- **Zero Local Compute AI:** Utilizes **Ollama Cloud** infrastructure for complex AI inference. Local CPU load is near 0%.
- **Fail-Secure & Rule-Based Fallback:** Immediate zero-latency deterministic **Rule-Based Fallback** if the LLM analysis times out or fails.
- **3-Layer Memory Architecture:**
  - **Short-Term Memory (STM):** Tracks aggressive activities over the last 30-60 minutes.
  - **Long-Term Memory (LTM):** SQLite database recording incident history, false positives, and whitelists.
  - **Global Memory (GM):** Absolute static rules for zero-latency mitigation.
- **Adaptive Learning 🧠:** Analyzes LTM automatically to learn new attack patterns and add them to GM, getting smarter over time.
- **Auto-Remediation 🔧:** Automatically fixes security misconfigurations (e.g., enabling UFW, fixing weak SSH configs, restarting failed services).
- **IP Clustering / Botnet Detection 🤖:** Detects coordinated attacks from multiple IPs targeting the same paths/services and federates the block.
- **Canary Tokens 🍯:** Deploys bait files (e.g., `backup.sql`, `.env`) and instantly alerts and blocks intruders who attempt to access them.
- **Threat Intelligence 🌍:** Integrates **AbuseIPDB** and **GeoIP** for real-time IP reputation and geographic context.
- **Rate Limiting & DDoS Detection 🔁:** Automatically tracks and blocks IPs exceeding configurable attempt thresholds.
- **Real-time Web Dashboard 📈:** Embedded, dependency-free live web dashboard (accessible via port `8443`) for monitoring SOC activities.
- **Forensic Timelines 🕵️:** Assembles full attack chronologies using STM, LTM, and Threat Intel.
- **Multi-Server Federated Blocking 🌐:** One agent can manage blocklists across multiple remote servers via SSH, ensuring that an attack on one server is instantly mitigated across the infrastructure.
- **Layer-7 Vulnerability Scanner:** Built-in automated scanner covering FIM (File Integrity Monitoring), Firewall status, SSH audit, outdated packages, and failed services.

## 🏗️ Folder Structure & Modular Architecture

Heimdall-Lite's capabilities are grouped logically into a clean modular structure:

```
modules/
├── core/                    # 🧠 Core Pipeline & Execution
│   ├── sensor.py            # Log monitoring (auth, nginx)
│   ├── brain.py             # LLM Analysis + Sanitization
│   ├── memory.py            # Storage (STM, LTM, GM)
│   ├── executor.py          # Action Execution (Cloudflare, UFW)
│   ├── reporter.py          # Telegram Notifier & Command Handler
│   ├── sanitizer.py         # Anti-Prompt Injection filters
│   └── fallback.py          # Deterministic Rule Engine
│
├── security/                # 🛡️ Scanning & Defense Mechanisms
│   ├── scanner.py           # 7-Layer Host Vulnerability Scanner
│   ├── canary.py            # Intrusion Detection via Bait Files
│   ├── clustering.py        # Coordinated Botnet Detection
│   └── remediation.py       # Auto-Fix security misconfigurations
│
├── intel/                   # 🔍 Intelligence & Analysis
│   ├── threat_intel.py      # Reputational & GeoIP logic
│   ├── forensic.py          # Automated Timeline generation
│   └── learning.py          # Adaptive Rules extraction
│
└── infra/                   # 📊 Infrastructure Ecosystem
    ├── dashboard.py         # Standalone HTTP Live Dashboard
    └── multi_server.py      # Remote Server SSH Federation
```

## 🚀 Setup & Deployment Guide

### Requirements
- Linux (Debian/Ubuntu Server Headless recommended)
- Python 3.10+
- Telegram Account & Cloudflare API Key
- Local Ollama endpoint

### Initial Setup

1. **Clone & Environment Setup**
   ```bash
   git clone https://github.com/Pabloraka/Heimdall-lite.git
   cd Heimdall-lite
   cp .env.example .env
   # Edit .env with your Cloudflare, Telegram API, AbuseIPDB, and Ollama tokens.
   chmod 600 .env
   ```

2. **Configuration**
   Customize `config.yaml` to define rate limits, auto-scan intervals, and federated remote servers.

3. **Install Dependencies & Initialize Components**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Agent**
   ```bash
   python3 main.py
   ```
   *(For production use, set it up as a systemd service).*

## 📱 Admin Interaction via Telegram

You have a complete SOC command center in your Telegram Bot. Send `/help` to see all commands:

**📊 Monitoring**
- `/health` — Agent and infrastructure status.
- `/status` — Incident statistics for today.
- `/rules` — View Global Rules and blocklists.

**🔍 Investigation**
- `/check <IP>` — Complete incident history of an IP.
- `/intel <IP>` — Threat intelligence and reputation (GeoIP + AbuseIPDB).
- `/forensic <IP>` — Forensic timeline assembly.
- `/botnet` — Analyze STM for coordinated Botnet patterns.

**🛡️ Defense**
- `/block <IP>` — Force block an IP manually.
- `/allow <IP>` — Whitelist/Unblock an IP.
- `/fblock <IP>` — Federated Block (block on all remote servers).
- `/scan` — Run a 7-layer Host Vulnerability Scan.
- `/remediate` — Run Auto-Remediation to fix active vulnerabilities.

**🧠 Intelligence**
- `/learn` — Trigger Adaptive Learning manually to extract new GM rules.
- `/deploy_canary` — Plant bait files to trap intruders.
- `/servers` — Perform a health check on all federated servers.

---
*Heimdall-Lite is designed with a **Zero-Trust** and **Defense in Depth** philosophy. Not a single threat is allowed to pass without analysis.*

## 📄 License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for the full text.

Copyright © 2026 **Pabloraka**.
