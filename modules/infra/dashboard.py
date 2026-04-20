import os
import time
import json
import sqlite3
import threading
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

DB_PATH = BASE_DIR / "data" / "security_archive.db"
STM_PATH = BASE_DIR / "data" / "stm_context.json"
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8443"))

logger = logging.getLogger(__name__)

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Heimdall — Micro-SOC Dashboard</title>
<meta name="description" content="Real-time security monitoring dashboard for Heimdall Micro-SOC Agent">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0e17;
    --surface: #111827;
    --surface2: #1f2937;
    --border: #374151;
    --text: #e5e7eb;
    --text-dim: #9ca3af;
    --accent: #3b82f6;
    --accent-glow: rgba(59,130,246,0.15);
    --danger: #ef4444;
    --danger-glow: rgba(239,68,68,0.15);
    --warn: #f59e0b;
    --safe: #22c55e;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family:'Inter', sans-serif;
    background:var(--bg);
    color:var(--text);
    min-height:100vh;
  }
  .topbar {
    background:linear-gradient(135deg, var(--surface) 0%, #0f172a 100%);
    border-bottom:1px solid var(--border);
    padding:16px 32px;
    display:flex; justify-content:space-between; align-items:center;
  }
  .topbar h1 { font-size:20px; font-weight:700; }
  .topbar h1 span { color:var(--accent); }
  .topbar .live { display:flex; align-items:center; gap:8px; font-size:13px; color:var(--safe); }
  .topbar .live .dot {
    width:8px; height:8px; background:var(--safe); border-radius:50%;
    animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

  .grid {
    display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
    gap:20px; padding:24px 32px;
  }
  .card {
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:12px;
    padding:20px 24px;
    transition: transform 0.2s, box-shadow 0.2s;
  }
  .card:hover { transform:translateY(-2px); box-shadow:0 8px 24px rgba(0,0,0,0.3); }
  .card .label { font-size:12px; text-transform:uppercase; color:var(--text-dim); letter-spacing:1px; margin-bottom:8px; }
  .card .value { font-size:32px; font-weight:700; }
  .card .value.danger { color:var(--danger); }
  .card .value.warn { color:var(--warn); }
  .card .value.safe { color:var(--safe); }
  .card .value.accent { color:var(--accent); }

  .section { padding:0 32px 24px; }
  .section h2 { font-size:16px; font-weight:600; margin-bottom:12px; color:var(--text-dim); }

  table {
    width:100%; border-collapse:collapse;
    background:var(--surface); border-radius:12px; overflow:hidden;
    border:1px solid var(--border);
  }
  thead { background:var(--surface2); }
  th { padding:12px 16px; text-align:left; font-size:12px; text-transform:uppercase; color:var(--text-dim); letter-spacing:0.5px; }
  td { padding:12px 16px; font-size:13px; border-top:1px solid var(--border); }
  tr:hover td { background:var(--accent-glow); }
  .badge {
    display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600;
  }
  .badge.block { background:var(--danger-glow); color:var(--danger); }
  .badge.alert { background:rgba(245,158,11,0.15); color:var(--warn); }
  .badge.safe { background:rgba(34,197,94,0.15); color:var(--safe); }

  .stm-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr)); gap:12px; }
  .stm-card {
    background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:14px 18px;
  }
  .stm-card .ip { font-weight:600; color:var(--accent); margin-bottom:4px; }
  .stm-card .meta { font-size:12px; color:var(--text-dim); }

  .footer { text-align:center; padding:24px; color:var(--text-dim); font-size:12px; }

  @media(max-width:768px) {
    .grid { padding:16px; gap:12px; }
    .section { padding:0 16px 16px; }
    .topbar { padding:12px 16px; }
  }
</style>
</head>
<body>
<div class="topbar">
  <h1>🛡️ <span>Heimdall</span> Micro-SOC</h1>
  <div class="live"><div class="dot"></div> Live Monitoring</div>
</div>

<div class="grid" id="stats">
  <div class="card"><div class="label">Total Incidents Today</div><div class="value accent" id="s-today">-</div></div>
  <div class="card"><div class="label">Total Blocks (All Time)</div><div class="value danger" id="s-total">-</div></div>
  <div class="card"><div class="label">Active IPs (STM)</div><div class="value warn" id="s-active">-</div></div>
  <div class="card"><div class="label">Whitelisted IPs</div><div class="value safe" id="s-white">-</div></div>
</div>

<div class="section">
  <h2>Recent Incidents</h2>
  <table>
    <thead><tr><th>Time</th><th>IP</th><th>Threat</th><th>Action</th><th>Reason</th><th>Confidence</th></tr></thead>
    <tbody id="incidents-body"><tr><td colspan="6" style="text-align:center;color:var(--text-dim)">Loading...</td></tr></tbody>
  </table>
</div>

<div class="section">
  <h2>Active Monitoring (STM)</h2>
  <div class="stm-grid" id="stm-grid">
    <div class="stm-card"><div class="meta">Loading...</div></div>
  </div>
</div>

<div class="footer">Heimdall Lite Micro-SOC &copy; 2026 — Auto-refresh setiap 10 detik</div>

<script>
async function fetchData() {
  try {
    const res = await fetch('/api/dashboard');
    const data = await res.json();

    document.getElementById('s-today').textContent = data.today_incidents;
    document.getElementById('s-total').textContent = data.total_blocks;
    document.getElementById('s-active').textContent = data.active_ips;
    document.getElementById('s-white').textContent = data.whitelisted;

    // Incidents table
    const tbody = document.getElementById('incidents-body');
    if (data.recent_incidents.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-dim)">Belum ada insiden hari ini</td></tr>';
    } else {
      tbody.innerHTML = data.recent_incidents.map(i => {
        let badge = 'safe';
        if (i.action.includes('BLOCK')) badge = 'block';
        else if (i.action === 'ALERT_ONLY') badge = 'alert';
        return `<tr>
          <td>${i.timestamp}</td>
          <td><strong>${i.ip}</strong></td>
          <td>${i.threat_type}</td>
          <td><span class="badge ${badge}">${i.action}</span></td>
          <td>${i.reason}</td>
          <td>${i.confidence}</td>
        </tr>`;
      }).join('');
    }

    // STM cards
    const stmGrid = document.getElementById('stm-grid');
    const stmEntries = Object.entries(data.stm_data);
    if (stmEntries.length === 0) {
      stmGrid.innerHTML = '<div class="stm-card"><div class="meta">Tidak ada IP aktif saat ini</div></div>';
    } else {
      stmGrid.innerHTML = stmEntries.map(([ip, d]) => `
        <div class="stm-card">
          <div class="ip">${ip}</div>
          <div class="meta">
            Attempts: ${d.failed_attempts} | Last: ${d.last_seen} | Service: ${d.service || '-'}
            ${d.paths_accessed && d.paths_accessed.length ? '<br>Paths: ' + d.paths_accessed.slice(0,5).join(', ') : ''}
          </div>
        </div>
      `).join('');
    }
  } catch (e) {
    console.error('Dashboard fetch error:', e);
  }
}

fetchData();
setInterval(fetchData, 10000);
</script>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler untuk Dashboard"""

    def log_message(self, format, *args):
        # Suppress default HTTP request logging
        pass

    def do_GET(self):
        if self.path == "/" or self.path == "/dashboard":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode("utf-8"))

        elif self.path == "/api/dashboard":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            data = self._get_dashboard_data()
            self.wfile.write(json.dumps(data).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def _get_dashboard_data(self) -> dict:
        """Mengambil semua data yang dibutuhkan dashboard"""
        data = {
            "today_incidents": 0,
            "total_blocks": 0,
            "active_ips": 0,
            "whitelisted": 0,
            "recent_incidents": [],
            "stm_data": {}
        }

        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            today = time.strftime("%Y-%m-%d")

            # Today's incidents
            cursor.execute("SELECT COUNT(*) as c FROM incidents WHERE timestamp LIKE ?", (f"{today}%",))
            row = cursor.fetchone()
            data["today_incidents"] = row["c"] if row else 0

            # Total blocks
            cursor.execute("SELECT COUNT(*) as c FROM incidents WHERE action LIKE '%BLOCK%'")
            row = cursor.fetchone()
            data["total_blocks"] = row["c"] if row else 0

            # Whitelisted
            cursor.execute("SELECT COUNT(*) as c FROM trusted_devices")
            row = cursor.fetchone()
            data["whitelisted"] = row["c"] if row else 0

            # Recent incidents (last 50)
            cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 50")
            rows = cursor.fetchall()
            data["recent_incidents"] = [dict(r) for r in rows]

            conn.close()
        except Exception as e:
            logger.warning(f"[DASHBOARD] DB error: {e}")

        # STM data
        try:
            if STM_PATH.exists():
                with open(STM_PATH, 'r') as f:
                    stm = json.load(f)
                data["stm_data"] = stm
                data["active_ips"] = len(stm)
        except Exception:
            pass

        return data


def start_dashboard():
    """Menjalankan dashboard HTTP server di background thread"""
    try:
        server = HTTPServer(("0.0.0.0", DASHBOARD_PORT), DashboardHandler)
        logger.info(f"[DASHBOARD] Running on http://0.0.0.0:{DASHBOARD_PORT}")
        print(f"[DASHBOARD] 📊 Dashboard aktif di port {DASHBOARD_PORT}")
        server.serve_forever()
    except Exception as e:
        logger.warning(f"[DASHBOARD] Failed to start: {e}")
        print(f"[DASHBOARD] ❌ Gagal start: {e}")


def start_dashboard_in_background():
    """Menjalankan dashboard di daemon thread"""
    t = threading.Thread(target=start_dashboard, daemon=True)
    t.start()
