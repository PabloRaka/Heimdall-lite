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
<title>HEIMDALL TERMINAL</title>
<style>
  :root {
    --bg: #000000;
    --text: #ffb000; /* Amber phosphor */
    --dim: #a87200;
    --border: #332200;
    --danger: #ff0033;
    --warn: #ffff00;
    --safe: #00ff00;
    --accent: #00ffff;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family: 'Courier New', Courier, monospace;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    font-size: 14px;
    padding: 15px;
  }
  /* Soft CRT effect */
  body::after {
    content: " ";
    display: block;
    position: fixed;
    top: 0; left: 0; bottom: 0; right: 0;
    background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
    z-index: 2; background-size: 100% 2px, 3px 100%; pointer-events: none;
  }
  .header {
    display: flex; justify-content: space-between;
    border-bottom: 2px solid var(--text);
    padding-bottom: 8px; margin-bottom: 20px;
    text-transform: uppercase;
  }
  .header h1 { font-size: 20px; font-weight: bold; letter-spacing: 2px;}
  .header .blink { animation: blinker 1s linear infinite; }
  @keyframes blinker { 50% { opacity: 0; } }

  .grid {
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 15px; margin-bottom: 30px;
  }
  .card {
    border: 1px solid var(--text);
    padding: 15px;
    background: rgba(255, 176, 0, 0.03);
  }
  .card .label { font-size: 12px; text-transform: uppercase; margin-bottom: 8px; color: var(--dim); }
  .card .value { font-size: 28px; font-weight: bold; }
  .card .value.danger { color: var(--danger); text-shadow: 0 0 5px rgba(255,0,51,0.5); }
  .card .value.warn { color: var(--warn); text-shadow: 0 0 5px rgba(255,255,0,0.5); }
  .card .value.safe { color: var(--safe); text-shadow: 0 0 5px rgba(0,255,0,0.5); }
  .card .value.accent { color: var(--accent); text-shadow: 0 0 5px rgba(0,255,255,0.5); }

  .section { margin-bottom: 30px; }
  .section-title {
    background: var(--text); color: var(--bg);
    padding: 4px 12px; display: inline-block; font-weight: bold;
    text-transform: uppercase; margin-bottom: 12px; letter-spacing: 1px;
  }

  table {
    width: 100%; border-collapse: collapse; font-size: 13px;
    border: 1px solid var(--border);
  }
  th { text-align: left; padding: 8px; border-bottom: 1px solid var(--text); color: var(--dim); text-transform: uppercase; }
  td { padding: 8px; border-bottom: 1px dashed var(--border); word-break: break-all; }
  tr:hover td { background: rgba(255,176,0,0.1); }
  
  .badge { padding: 2px 6px; font-weight: bold; text-transform: uppercase; }
  .badge.block { background: var(--bg); color: var(--danger); outline: 1px solid var(--danger); }
  .badge.alert { background: var(--bg); color: var(--warn); outline: 1px solid var(--warn); }
  .badge.safe { background: var(--bg); color: var(--safe); outline: 1px solid var(--safe); }

  /* Log Archive controls */
  .log-controls {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 12px; flex-wrap: wrap; gap: 10px;
  }
  .log-controls-left { display: flex; align-items: center; gap: 12px; }
  .per-page-label { font-size: 12px; color: var(--dim); text-transform: uppercase; }
  .per-page-select {
    background: var(--bg); color: var(--text);
    border: 1px solid var(--text); padding: 4px 8px;
    font-family: 'Courier New', Courier, monospace; font-size: 13px;
    cursor: pointer; outline: none;
  }
  .per-page-select:hover { border-color: var(--accent); color: var(--accent); }
  .per-page-select option { background: #111; }

  /* Pagination */
  .pagination {
    display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
  }
  .page-btn {
    background: var(--bg); color: var(--text);
    border: 1px solid var(--border); padding: 4px 10px;
    font-family: 'Courier New', Courier, monospace; font-size: 12px;
    cursor: pointer; transition: all 0.15s;
    text-transform: uppercase; min-width: 32px; text-align: center;
  }
  .page-btn:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
  .page-btn.active { background: var(--text); color: var(--bg); border-color: var(--text); font-weight: bold; }
  .page-btn:disabled { opacity: 0.3; cursor: not-allowed; }
  .page-info { font-size: 12px; color: var(--dim); white-space: nowrap; }

  .stm-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 15px; }
  .stm-card { border: 1px solid var(--text); padding: 12px; font-size: 12px; background: rgba(255, 176, 0, 0.03); line-height: 1.5; }
  .stm-card .ip { color: var(--accent); font-weight: bold; font-size: 14px; margin-bottom: 6px; border-bottom: 1px dashed var(--border); padding-bottom: 4px; }

  .footer { text-align: right; font-size: 11px; color: var(--dim); margin-top: 30px; border-top: 1px solid var(--border); padding-top: 10px; }

  @media(max-width:768px) {
    .grid { grid-template-columns: 1fr 1fr; }
    .log-controls { flex-direction: column; align-items: flex-start; }
  }
</style>
</head>
<body>
<div class="header">
  <h1>HEIMDALL-LITE :: SYS_MONITOR</h1>
  <div><span class="blink">█</span> SYS_ONLINE : PRT_8443</div>
</div>

<div class="grid" id="stats">
  <div class="card"><div class="label">INCIDENTS_TDY</div><div class="value accent" id="s-today">...</div></div>
  <div class="card"><div class="label">TOTAL_BLOCKED</div><div class="value danger" id="s-total">...</div></div>
  <div class="card"><div class="label">ACTIVE_TARGETS</div><div class="value warn" id="s-active">...</div></div>
  <div class="card"><div class="label">WHITELISTED</div><div class="value safe" id="s-white">...</div></div>
</div>

<div class="section">
  <div class="log-controls">
    <div class="log-controls-left">
      <div class="section-title" id="log-archive-title">LOG_ARCHIVE</div>
      <span class="per-page-label">ROWS/PAGE:</span>
      <select class="per-page-select" id="per-page-select">
        <option value="15">15</option>
        <option value="20">20</option>
        <option value="25" selected>25</option>
        <option value="50">50</option>
      </select>
    </div>
    <div class="pagination" id="pagination-top"></div>
  </div>
  <table>
    <thead><tr><th>TIMESTAMP</th><th>SRC_IP</th><th>REGION</th><th>THREAT_SIG</th><th>ACTION</th><th>HEURISTIC_REASON</th><th>CONFIRM_SCORE</th></tr></thead>
    <tbody id="incidents-body"><tr><td colspan="7" style="text-align:center;">AWAITING_DATA...</td></tr></tbody>
  </table>
  <div style="display:flex; justify-content:flex-end; margin-top:10px;">
    <div class="pagination" id="pagination-bottom"></div>
  </div>
</div>

<div class="section">
  <div class="section-title">ACTIVE_MONITOR (STM_CACHE)</div>
  <div class="stm-grid" id="stm-grid">
    <div class="stm-card">AWAITING_DATA...</div>
  </div>
</div>

<div class="footer">
  TERMINAL_REFRESH_RATE: 10S | HEIMDALL_LITE_V1.0
</div>

<script>
// --- Pagination State ---
let currentPage = 1;
let currentPerPage = 25;
let totalPages = 1;
let totalRows = 0;
let autoRefreshTimer = null;

// --- Fetch Stats & STM (dashboard summary) ---
async function fetchSummary() {
  try {
    const res = await fetch('/api/dashboard');
    const data = await res.json();
    document.getElementById('s-today').textContent = data.today_incidents;
    document.getElementById('s-total').textContent = data.total_blocks;
    document.getElementById('s-active').textContent = data.active_ips;
    document.getElementById('s-white').textContent = data.whitelisted;

    const stmGrid = document.getElementById('stm-grid');
    const stmEntries = Object.entries(data.stm_data);
    if (stmEntries.length === 0) {
      stmGrid.innerHTML = '<div class="stm-card">NO_ACTIVE_TARGETS</div>';
    } else {
      stmGrid.innerHTML = stmEntries.map(([ip, d]) => `
        <div class="stm-card">
          <div class="ip">${ip}</div>
          <div>ATTEMPTS : ${d.failed_attempts}</div>
          <div>LAST_SEEN: ${d.last_seen}</div>
          <div>SERVICE  : ${d.service || 'UNKNOWN'}</div>
          ${d.paths_accessed && d.paths_accessed.length ? '<div>PATHS    : ' + d.paths_accessed.slice(0,5).join(', ') + '</div>' : ''}
        </div>
      `).join('');
    }
  } catch (e) {
    console.error('TRML_ERR (summary):', e);
  }
}

// --- Fetch Log Archive with Pagination ---
async function fetchLogs(page, perPage) {
  try {
    const res = await fetch(`/api/logs?page=${page}&per_page=${perPage}`);
    const data = await res.json();

    totalPages = data.total_pages;
    totalRows  = data.total;
    currentPage = data.page;

    // Update section title
    const start = (currentPage - 1) * perPage + 1;
    const end   = Math.min(currentPage * perPage, totalRows);
    document.getElementById('log-archive-title').textContent =
      `LOG_ARCHIVE : ${totalRows > 0 ? start + '-' + end : 0} / ${totalRows}`;

    // Render table rows
    const tbody = document.getElementById('incidents-body');
    if (!data.incidents || data.incidents.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;">NO_DATA_FOUND</td></tr>';
    } else {
      tbody.innerHTML = data.incidents.map(i => {
        let badge = 'safe';
        if (i.action && i.action.includes('BLOCK')) badge = 'block';
        else if (i.action === 'ALERT_ONLY') badge = 'alert';
        const geoParts = [
          i.city,
          i.region,
          i.country && i.country !== 'Unknown' ? i.country : ''
        ].filter(Boolean);
        const geoLabel = geoParts.length ? geoParts.join(', ') : '-';
        return `<tr>
          <td>${i.timestamp || '-'}</td>
          <td style="color:var(--accent); font-weight:bold;">${i.ip || '-'}</td>
          <td>${geoLabel}</td>
          <td>${i.threat_type || '-'}</td>
          <td><span class="badge ${badge}">${i.action || '-'}</span></td>
          <td>${i.reason || '-'}</td>
          <td>${i.confidence !== undefined ? i.confidence : '-'}</td>
        </tr>`;
      }).join('');
    }

    renderPagination();
  } catch (e) {
    console.error('TRML_ERR (logs):', e);
  }
}

// --- Render Pagination Controls ---
function renderPagination() {
  const ids = ['pagination-top', 'pagination-bottom'];
  ids.forEach(id => {
    const container = document.getElementById(id);
    if (!container) return;

    if (totalPages <= 1) { container.innerHTML = ''; return; }

    let html = '';
    // Prev button
    html += `<button class="page-btn" onclick="goToPage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>◄ PREV</button>`;

    // Page number buttons (smart windowing)
    const window = 2;
    let start = Math.max(1, currentPage - window);
    let end   = Math.min(totalPages, currentPage + window);

    if (start > 1) {
      html += `<button class="page-btn" onclick="goToPage(1)">1</button>`;
      if (start > 2) html += `<span class="page-info">…</span>`;
    }
    for (let p = start; p <= end; p++) {
      html += `<button class="page-btn ${p === currentPage ? 'active' : ''}" onclick="goToPage(${p})">${p}</button>`;
    }
    if (end < totalPages) {
      if (end < totalPages - 1) html += `<span class="page-info">…</span>`;
      html += `<button class="page-btn" onclick="goToPage(${totalPages})">${totalPages}</button>`;
    }

    // Next button
    html += `<button class="page-btn" onclick="goToPage(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>NEXT ►</button>`;

    // Page info
    html += `<span class="page-info">PG ${currentPage}/${totalPages}</span>`;

    container.innerHTML = html;
  });
}

function goToPage(page) {
  if (page < 1 || page > totalPages) return;
  currentPage = page;
  fetchLogs(currentPage, currentPerPage);
}

// --- Per-Page Selector ---
document.getElementById('per-page-select').addEventListener('change', function() {
  currentPerPage = parseInt(this.value);
  currentPage = 1; // reset to first page
  fetchLogs(currentPage, currentPerPage);
});

// --- Initial Load & Auto-Refresh ---
function fetchAll() {
  fetchSummary();
  fetchLogs(currentPage, currentPerPage);
}

fetchAll();
autoRefreshTimer = setInterval(function() {
  fetchSummary();
  // Only auto-refresh logs if user is on page 1 to avoid disrupting navigation
  if (currentPage === 1) fetchLogs(1, currentPerPage);
}, 10000);
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

        elif self.path.startswith("/api/logs"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            data = self._get_logs_paginated(self.path)
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

    def _get_logs_paginated(self, path: str) -> dict:
        """Mengambil log archive dengan pagination"""
        # Parse query params
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(path)
        params = parse_qs(parsed.query)

        ALLOWED_PER_PAGE = {15, 20, 25, 50}
        try:
            per_page = int(params.get("per_page", ["25"])[0])
            if per_page not in ALLOWED_PER_PAGE:
                per_page = 25
        except (ValueError, IndexError):
            per_page = 25

        try:
            page = max(1, int(params.get("page", ["1"])[0]))
        except (ValueError, IndexError):
            page = 1

        result = {
            "page": page,
            "per_page": per_page,
            "total": 0,
            "total_pages": 1,
            "incidents": []
        }

        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Count total rows
            cursor.execute("SELECT COUNT(*) as c FROM incidents")
            row = cursor.fetchone()
            total = row["c"] if row else 0
            result["total"] = total
            result["total_pages"] = max(1, (total + per_page - 1) // per_page)

            # Clamp page
            page = min(page, result["total_pages"])
            result["page"] = page
            offset = (page - 1) * per_page

            cursor.execute(
                "SELECT * FROM incidents ORDER BY id DESC LIMIT ? OFFSET ?",
                (per_page, offset)
            )
            rows = cursor.fetchall()
            result["incidents"] = [dict(r) for r in rows]
            conn.close()
        except Exception as e:
            logger.warning(f"[DASHBOARD] Logs pagination error: {e}")

        return result


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
