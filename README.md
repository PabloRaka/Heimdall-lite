<p align="center">
  <img src="assets/heimdall_lite_banner.png" alt="Heimdall-Lite Banner" width="50%">
</p>

# Heimdall-Lite: Micro-SOC AI Security Agent 🛡️

**Advanced Cybersecurity AI Agent** designed specifically for proactive protection with minimalist resource requirements.

Heimdall-Lite is an intelligent **Layer-2 Defense** that runs efficiently even on extremely low-spec machines (such as AMD A4, 4GB RAM) operating behind a Cloudflare Tunnel. Heimdall-Lite doesn't just log events; it detects, analyzes with AI, and responds to threats automatically (*Sense → Think → Act*).

---

## 🔥 Key Features (Why Heimdall-Lite?)

- **Zero Local Compute AI:** Utilizes **Ollama Cloud** infrastructure (like *minimax-m1:cloud*, *gemma3:cloud*) for complex AI inference. Local CPU load is near 0%, ensuring even the smallest servers can have a sophisticated Security Operations Center.
- **Fail-Secure & Rule-Based Fallback:** The system won't freeze or remain passive during API downtimes. If the LLM analysis times out or returns a JSON error, Heimdall-Lite immediately activates a zero-latency deterministic **Rule-Based Fallback** path.
- **3-Layer Memory Architecture:**
  - **Short-Term Memory (STM):** Tracks aggressive activities over the last 30-60 minutes.
  - **Long-Term Memory (LTM):** An automated SQLite database that records incident history, false positives, and whitelists.
  - **Global Memory (GM):** Absolute static rules (like blacklist paths or forbidden usernames) that accelerate threat response time to under 1 second without involving the LLM process.
- **Auto-Dream & Self-Learning:** Every midnight, Heimdall-Lite summarizes daily attack patterns from the LTM and reports to the admin, building a long-term "memory" of adversaries to get smarter every day.
- **Anti-Prompt Injection:** Strict input sanitization filters prevent direct attacks. Every log entry is sterilized before being passed to the LLM prompt to ensure no hidden JSON payloads can "hijack" AI commands.

## 🛡️ Detected Attack Types

Heimdall-Lite is designed to mitigate the following attack vectors in *real-time*:
1. **Brute Force & Credential Stuffing:** Detects repeated failed login attempts on SSH or Web interfaces, as well as the use of forbidden usernames.
2. **Directory Traversal / LFI:** Instantly blocks access to sensitive paths (e.g., `/.env`, `/.git`, `/etc/passwd`, or hidden config directories).
3. **Vulnerability Scanning (HTTP Scanning):** Recognizes bots looking for security loopholes through blind scanning (indicated by consecutive 404 error spikes).
4. **Lateral Movement:** Detects anomalous activities or access attempts originating from within the local network itself.
5. **Log-Based Prompt Injection:** Immune to hackers attempting to inject LLM bypass instructions into log entries (e.g., via URL or User-Agent).

## 🏗️ Three-Pillar Architecture

Heimdall-Lite separates its functionality into 3 main pillars:
1. **🔍 SENSOR (Log Watcher):** Event-driven execution (not polling) that monitors `/var/log/auth.log` and `/var/log/nginx/access.log`. Efficiently extracts critical entities (IP, timestamp, path, method) whenever a line is detected.
2. **🧠 BRAIN (AI Communicator):** Intelligently assembles prompts from sanitized logs combined with STM/LTM memory, then sends them to the AI. Makes decisions (BLOCK, ALERT, NONE) based on strictly validated JSON outputs.
3. **💪 MUSCLE (Executor & Reporter):** Performs secure execution via edge APIs (Cloudflare) or protected subprocesses (UFW). Commands are highly selective and whitelisted to prevent shell injection. Admins always receive real-time Telegram notifications.

## 🚀 Setup & Deployment Guide

### Requirements
- Linux (Debian/Ubuntu Server Headless recommended)
- Python 3.10+
- Credentials: Telegram Account (for bot) & Cloudflare API Key
- Local Ollama endpoint to bridge cloud LLMs (e.g., `minimax-m1:cloud`)

### Quick Setup

1. **Clone & Environment Setup**
   ```bash
   git clone <repo>
   cd heimdall-lite
   cp .env.example .env
   # Edit the .env file with your Cloudflare, Telegram, and Ollama Endpoint tokens
   chmod 600 .env # Mandatory, secret security!
   ```

2. **Install Dependencies & Initialize Database**
   ```bash
   pip install -r requirements.txt
   python3 scripts/init_db.py
   ```

3. **Run the Agent (Test/Console Mode)**
   ```bash
   sudo -u agent-user python3 main.py
   ```
   *(For long-term operation, create a systemd service to run it in the background).*

## 📱 Admin Interaction via Telegram

The command center is right in your pocket. Use these commands on your Telegram Bot:
- `/status` — Summary of threats in the last 24 hours.
- `/block <IP>` — Force manual IP block execution.
- `/allow <IP>` — Whitelist an IP / unblock it.
- `/check <IP>` — View the incident history of an IP stored in the LTM.
- `/rules` — View the active Global Rules.
- `/health` — Diagnose the operational status of the Sensor, AI Brain, and Executor.

---
*Heimdall-Lite is designed with a **Zero-Trust** and **Defense in Depth** philosophy. Not a single threat is allowed to pass without analysis.*
