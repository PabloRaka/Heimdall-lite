<p align="center">
  <img src="assets/heimdall_lite_banner.png" alt="Heimdall-Lite Banner" width="50%">
</p>

# Heimdall-Lite: Lightweight Micro-SOC Security Daemon 🛡️

A low-footprint security daemon designed for proactive threat mitigation with minimal compute overhead.

Heimdall-Lite functions as a Layer-2 defense system optimized for low-spec environments operating behind a Cloudflare Tunnel. Instead of passive logging, it actively parses web and auth logs, utilizes remote LLM endpoints for behavioral analysis, and triggers automated firewall/routing responses. Core capabilities include IP clustering for decentralized attacks, automated configuration patching, dynamic malicious signature generation, and decoy (canary) file monitoring.

---

## 🎯 Target Audience

Heimdall-Lite is purpose-built for users who need autonomous security without the overhead of complex enterprise stacks (like Splunk or Elastic):
- **Indie Hackers & Solo Founders:** Running 1-5 VPS instances and needing an automated "security guard" that handles mitigation and alerts via Telegram, rather than requiring daily manual log parsing.
- **Small Infra Teams / Sysadmins:** Managing lean infrastructure that requires a robust, easy-to-deploy automated defense layer capable of auto-remediating basic misconfigurations.
- **Self-Hosters & Homelab Enthusiasts:** Seeking an advanced, AI-driven protective daemon that can run smoothly on a low-spec machine (like a Raspberry Pi or single vCPU VPS) behind Cloudflare.

## 🔥 Key Features (Why Heimdall-Lite?)

- **Offloaded LLM Inference:** Sends complex log analysis payloads to a remote **Ollama** API endpoint, keeping the local server CPU footprint near 0%.
- **Deterministic Fallback:** Automatically switches to a strict, regex-based heuristic engine if the LLM endpoint times out or returns malformed data.
- **3-Layer Memory Architecture:**
  - **Short-Term Memory (STM):** Tracks aggressive activities over the last 30-60 minutes.
  - **Long-Term Memory (LTM):** SQLite database recording incident history, false positives, and whitelists.
  - **Global Memory (GM):** Absolute static rules for zero-latency mitigation.
- **Dynamic Rule Generation 🧠:** Periodically queries the SQLite Long-Term Memory (LTM) to identify recurring malicious patterns and compiles them into static Global Memory (GM) rules.
- **Automated Hardening 🔧:** Executes localized scripts to patch misconfigurations dynamically (e.g., enforcing UFW state, restricting SSH parameters, resetting crashed services).
- **IP Clustering / Botnet Detection 🤖:** Detects coordinated attacks from multiple IPs targeting the same paths/services and federates the block.
- **Canary Tokens 🍯:** Deploys bait files (e.g., `backup.sql`, `.env`) and instantly alerts and blocks intruders who attempt to access them.
- **Threat Intelligence 🌍:** Integrates **AbuseIPDB** and **GeoIP** for real-time IP reputation and geographic context.
- **Rate Limiting & DDoS Detection 🔁:** Automatically tracks and blocks IPs exceeding configurable attempt thresholds.
- **Real-time Web Dashboard 📈:** Embedded, dependency-free live web dashboard (accessible via port `8443`) for monitoring SOC activities.
- **Forensic Timelines 🕵️:** Assembles full attack chronologies using STM, LTM, and Threat Intel.
- **Multi-Server Federated Blocking 🌐:** One agent can manage blocklists across multiple remote servers via SSH, ensuring that an attack on one server is instantly mitigated across the infrastructure.
- **Layer-7 Vulnerability Scanner:** Built-in automated scanner covering FIM (File Integrity Monitoring), Firewall status, SSH audit, outdated packages, and failed services.

## 👁️ Heimdall-Lite in Action

### 1. The Log → Response Pipeline (Console)
```text
[1] Raw Log Detected (Sensor):
192.168.1.55 - - [21/Apr/2026:01:40:12 +0700] "GET /.env HTTP/1.1" 404 153 "-" "Mozilla/5.0"

[2] LLM Heuristic Analysis (Brain):
{
  "threat_level": "CRITICAL",
  "confidence": 0.98,
  "attack_type": "Information Disclosure / Env File Probing",
  "reasoning": "Attempt to access environment variables usually containing credentials.",
  "recommended_action": "BLOCK_IP"
}

[3] Automated Mitigation (Executor):
[INFO] IP 192.168.1.55 blocked via UFW (Rule added).
[INFO] Cloudflare API invoked. IP 192.168.1.55 added to WAF Deny list.
```

### 2. Telegram Alert Example
```text
🚨 HEIMDALL-LITE INTERVENTION 🚨

⚠️ Threat Level: CRITICAL
🎯 Target: /.env
🛡️ Action: BLOCKED (UFW & Cloudflare)

IP Address: 192.168.1.55
GeoIP: Moscow, Russia 🇷🇺
AbuseIPDB Score: 85% (Malicious)

Brain Analysis: 
"Attempting to access environment configuration. High likelihood of reconnaissance."

[ 🔍 Investigate IP ]   [ 🔓 Unblock ]
```

### 3. Real-Time Web Dashboard
![Heimdall-Lite Dashboard](assets/dashboard_preview.png)
*(Heimdall-Lite's real-time terminal dashboard accessible via port 8443)*

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
│   ├── learning.py          # Dynamic Rule generation
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

3. **Install Dependencies & Initialize Database**
   ```bash
   pip install -r requirements.txt
   python3 scripts/init_db.py
   ```

4. **Run the Agent**
   Use the smart launcher script. It automatically routes to the correct virtual environment and prompts for `sudo` (required for UFW rules and system log access):
   ```bash
   chmod +x start.sh
   ./start.sh
   ```
   *(For production deployment, it is recommended to set this launcher as a `systemd` service).*

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
- `/learn` — Trigger the rule generation pipeline manually to compile new GM blocks.
- `/deploy_canary` — Plant bait files to trap intruders.
- `/servers` — Perform a health check on all federated servers.

---
*Heimdall-Lite provides automated, multi-layered security validation to ensure traffic anomalies are verified and mitigated before reaching critical services.*

## 📄 License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for the full text.

Copyright © 2026 **Pabloraka**.
