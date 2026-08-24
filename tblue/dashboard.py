"""
Tblue Live Dashboard — streams scan results to a browser via SSE.

No external dependencies; uses Python's built-in http.server + threading.
"""

import json
import queue
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List

# ── HTML page (embedded) ───────────────────────────────────────────────────────

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Tblue — Live Scan</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root {
    --bg:      #0a0e1a;
    --panel:   #0f1424;
    --border:  #1e2d47;
    --cyan:    #00d4ff;
    --green:   #3ddc84;
    --yellow:  #ffd166;
    --red:     #ef4565;
    --orange:  #ff9f1c;
    --dim:     #4a5568;
    --text:    #c9d1d9;
    --white:   #f0f6ff;
    --radius:  10px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace, monospace;
    font-size: 13px;
    line-height: 1.6;
    display: flex;
    flex-direction: column;
    min-height: 100vh;
  }

  /* ── Header ────────────────────────────────────────────── */
  header {
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    padding: 18px 28px;
    display: flex;
    align-items: center;
    gap: 24px;
    flex-shrink: 0;
  }
  .logo {
    font-size: 22px;
    font-weight: 700;
    color: var(--cyan);
    letter-spacing: -0.5px;
    white-space: nowrap;
  }
  .logo span { color: var(--white); }
  .target-pill {
    background: #111827;
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 4px 14px;
    color: var(--cyan);
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 420px;
  }
  .pulse-dot {
    width: 10px; height: 10px;
    border-radius: 50%;
    background: var(--cyan);
    box-shadow: 0 0 0 0 rgba(0,212,255,0.6);
    animation: pulse 1.4s infinite;
    flex-shrink: 0;
  }
  .pulse-dot.done { background: var(--green); box-shadow: none; animation: none; }
  @keyframes pulse {
    0%   { box-shadow: 0 0 0 0 rgba(0,212,255,0.6); }
    70%  { box-shadow: 0 0 0 10px rgba(0,212,255,0); }
    100% { box-shadow: 0 0 0 0 rgba(0,212,255,0); }
  }
  .status-text {
    color: var(--dim);
    font-size: 12px;
    white-space: nowrap;
  }
  .header-right { margin-left: auto; display: flex; align-items: center; gap: 16px; }

  /* ── Progress bar ──────────────────────────────────────── */
  .progress-wrap {
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    padding: 10px 28px;
    display: flex;
    align-items: center;
    gap: 14px;
    flex-shrink: 0;
  }
  .progress-bar-outer {
    flex: 1;
    height: 6px;
    background: var(--border);
    border-radius: 3px;
    overflow: hidden;
  }
  .progress-bar-inner {
    height: 100%;
    width: 0%;
    background: linear-gradient(90deg, var(--cyan), var(--green));
    border-radius: 3px;
    transition: width 0.4s ease;
  }
  .progress-label { color: var(--dim); font-size: 11px; white-space: nowrap; min-width: 90px; text-align: right; }

  /* ── Main layout ───────────────────────────────────────── */
  main {
    flex: 1;
    display: grid;
    grid-template-columns: 340px 1fr;
    gap: 0;
    overflow: hidden;
    min-height: 0;
  }

  /* ── Left panel — scanner list ─────────────────────────── */
  .panel-scanners {
    border-right: 1px solid var(--border);
    background: var(--panel);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .panel-title {
    padding: 12px 16px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--dim);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .scanner-list {
    overflow-y: auto;
    flex: 1;
    padding: 6px 0;
  }
  .scanner-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 5px 16px;
    opacity: 0;
    transform: translateX(-8px);
    animation: slide-in 0.25s ease forwards;
    font-size: 12px;
  }
  @keyframes slide-in {
    to { opacity: 1; transform: translateX(0); }
  }
  .scanner-icon { font-size: 10px; flex-shrink: 0; }
  .scanner-icon.ok   { color: var(--green); }
  .scanner-icon.warn { color: var(--yellow); }
  .scanner-icon.fail { color: var(--red); }
  .scanner-icon.clean { color: var(--dim); }
  .scanner-name { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .scanner-badge {
    margin-left: auto;
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 10px;
    flex-shrink: 0;
  }
  .badge-fail  { background: rgba(239,69,101,0.15); color: var(--red); }
  .badge-warn  { background: rgba(255,209,102,0.15); color: var(--yellow); }
  .badge-pass  { background: rgba(61,220,132,0.1);  color: var(--dim); }

  /* ── Right panel — findings ────────────────────────────── */
  .panel-findings {
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .findings-list {
    overflow-y: auto;
    flex: 1;
    padding: 8px 0;
  }
  .finding-item {
    display: grid;
    grid-template-columns: 52px 1fr;
    gap: 0;
    border-bottom: 1px solid rgba(30,45,71,0.4);
    padding: 7px 20px;
    opacity: 0;
    animation: fade-in 0.3s ease forwards;
  }
  @keyframes fade-in { to { opacity: 1; } }
  .finding-sev {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.04em;
    padding-top: 1px;
  }
  .sev-FAIL     { color: var(--red); }
  .sev-WARN     { color: var(--yellow); }
  .sev-critical { color: var(--red); }
  .sev-high     { color: var(--orange); }
  .sev-medium   { color: var(--yellow); }
  .sev-low      { color: var(--cyan); }
  .finding-body {}
  .finding-type { color: var(--white); font-size: 12px; }
  .finding-url  { color: var(--dim);  font-size: 11px; margin-top: 1px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  /* ── Score card (hidden until complete) ────────────────── */
  .score-card {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(10,14,26,0.88);
    backdrop-filter: blur(4px);
    align-items: center;
    justify-content: center;
    z-index: 100;
    animation: fade-in 0.4s ease;
  }
  .score-card.show { display: flex; }
  .score-box {
    background: var(--panel);
    border: 1px solid var(--cyan);
    border-radius: var(--radius);
    padding: 36px 48px;
    text-align: center;
    min-width: 380px;
    max-width: 500px;
    box-shadow: 0 0 60px rgba(0,212,255,0.12);
  }
  .score-box .og-logo {
    font-size: 15px;
    color: var(--cyan);
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 24px;
    opacity: 0.7;
  }
  .score-num {
    font-size: 72px;
    font-weight: 800;
    line-height: 1;
    margin-bottom: 4px;
  }
  .score-label { color: var(--dim); font-size: 12px; margin-bottom: 20px; }
  .grade-badge {
    display: inline-block;
    width: 56px; height: 56px;
    line-height: 56px;
    border-radius: 50%;
    font-size: 24px;
    font-weight: 800;
    margin-bottom: 24px;
  }
  .grade-A  { background: rgba(61,220,132,0.15); color: var(--green); border: 2px solid var(--green); }
  .grade-B  { background: rgba(0,212,255,0.12);  color: var(--cyan);  border: 2px solid var(--cyan); }
  .grade-C  { background: rgba(255,209,102,0.12); color: var(--yellow); border: 2px solid var(--yellow); }
  .grade-D  { background: rgba(255,159,28,0.12); color: var(--orange); border: 2px solid var(--orange); }
  .grade-F  { background: rgba(239,69,101,0.12); color: var(--red);   border: 2px solid var(--red); }
  .stat-row {
    display: flex;
    justify-content: space-around;
    margin: 20px 0;
    padding: 16px 0;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }
  .stat { text-align: center; }
  .stat-n { font-size: 24px; font-weight: 700; }
  .stat-l { font-size: 11px; color: var(--dim); margin-top: 2px; }
  .close-btn {
    margin-top: 20px;
    background: none;
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--dim);
    font-family: inherit;
    font-size: 12px;
    padding: 8px 20px;
    cursor: pointer;
    transition: border-color 0.2s, color 0.2s;
  }
  .close-btn:hover { border-color: var(--cyan); color: var(--cyan); }

  /* Severity mini-bar inside score card */
  .sev-bars { margin: 16px 0; text-align: left; }
  .sev-row  { display: flex; align-items: center; gap: 10px; margin: 5px 0; font-size: 11px; }
  .sev-row-label { width: 60px; color: var(--dim); }
  .sev-row-bar-outer { flex: 1; height: 4px; background: var(--border); border-radius: 2px; }
  .sev-row-bar-inner { height: 100%; border-radius: 2px; }
  .sev-row-count { width: 28px; text-align: right; color: var(--text); }

  /* scrollbar */
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  /* mini score counter top-right */
  .mini-score {
    font-size: 20px;
    font-weight: 800;
    color: var(--cyan);
    min-width: 56px;
    text-align: right;
    transition: color 0.5s;
  }
</style>
</head>
<body>

<header>
  <div class="logo">Open<span>Guard</span></div>
  <div class="target-pill" id="targetPill">{{TARGET}}</div>
  <div class="pulse-dot" id="pulseDot"></div>
  <div class="status-text" id="statusText">Initialising…</div>
  <div class="header-right">
    <div class="mini-score" id="miniScore">—</div>
  </div>
</header>

<div class="progress-wrap">
  <div class="progress-bar-outer">
    <div class="progress-bar-inner" id="progressBar"></div>
  </div>
  <div class="progress-label" id="progressLabel">0 / {{TOTAL}}</div>
</div>

<main>
  <div class="panel-scanners">
    <div class="panel-title">Scanners</div>
    <div class="scanner-list" id="scannerList"></div>
  </div>
  <div class="panel-findings">
    <div class="panel-title" id="findingsTitle">Findings</div>
    <div class="findings-list" id="findingsList"></div>
  </div>
</main>

<!-- Score card overlay -->
<div class="score-card" id="scoreCard">
  <div class="score-box">
    <div class="og-logo">Tblue</div>
    <div class="grade-badge" id="gradeBadge">?</div>
    <div class="score-num" id="scoreNum">—</div>
    <div class="score-label">/ 100 security score</div>
    <div class="stat-row">
      <div class="stat"><div class="stat-n" id="statPass" style="color:var(--green)">0</div><div class="stat-l">Passed</div></div>
      <div class="stat"><div class="stat-n" id="statWarn" style="color:var(--yellow)">0</div><div class="stat-l">Warned</div></div>
      <div class="stat"><div class="stat-n" id="statFail" style="color:var(--red)">0</div><div class="stat-l">Failed</div></div>
    </div>
    <div class="sev-bars" id="sevBars"></div>
    <button class="close-btn" onclick="document.getElementById('scoreCard').classList.remove('show')">
      Dismiss  ·  Results saved to disk
    </button>
  </div>
</div>

<script>
  const TOTAL = parseInt("{{TOTAL}}", 10) || 1;
  let done = 0, fails = 0, warns = 0, passes = 0;
  let findCount = 0;

  const progressBar  = document.getElementById("progressBar");
  const progressLbl  = document.getElementById("progressLabel");
  const scannerList  = document.getElementById("scannerList");
  const findingsList = document.getElementById("findingsList");
  const findingsTitle= document.getElementById("findingsTitle");
  const statusText   = document.getElementById("statusText");
  const pulseDot     = document.getElementById("pulseDot");
  const miniScore    = document.getElementById("miniScore");

  function severityColor(s) {
    if (!s) return "var(--dim)";
    s = s.toLowerCase();
    if (s === "critical") return "var(--red)";
    if (s === "high")     return "var(--orange)";
    if (s === "medium")   return "var(--yellow)";
    if (s === "low")      return "var(--cyan)";
    return "var(--dim)";
  }

  function gradeClass(g) {
    if (!g) return "grade-F";
    const c = g[0].toUpperCase();
    return "grade-" + (["A","B","C","D","F"].includes(c) ? c : "F");
  }

  const es = new EventSource("/events");

  es.onmessage = function(e) {
    let data;
    try { data = JSON.parse(e.data); } catch { return; }

    switch (data.type) {

      case "scanner_done": {
        done++;
        const pct = Math.min(100, Math.round(done / TOTAL * 100));
        progressBar.style.width = pct + "%";
        progressLbl.textContent = done + " / " + TOTAL;
        statusText.textContent  = "Scanning… " + pct + "%";

        const failures = (data.fails || 0);
        const warnings = (data.warns || 0);

        const item = document.createElement("div");
        item.className = "scanner-item";

        let iconClass = "clean", iconChar = "✓", badgeHtml = "";
        if (failures > 0) {
          iconClass = "fail"; iconChar = "✖";
          badgeHtml = `<span class="scanner-badge badge-fail">${failures} FAIL</span>`;
        } else if (warnings > 0) {
          iconClass = "warn"; iconChar = "⚑";
          badgeHtml = `<span class="scanner-badge badge-warn">${warnings} WARN</span>`;
        } else {
          badgeHtml = `<span class="scanner-badge badge-pass">ok</span>`;
        }

        item.innerHTML = `
          <span class="scanner-icon ${iconClass}">${iconChar}</span>
          <span class="scanner-name">${data.module || ""}</span>
          ${badgeHtml}
        `;
        scannerList.appendChild(item);
        scannerList.scrollTop = scannerList.scrollHeight;
        break;
      }

      case "finding": {
        findCount++;
        findingsTitle.textContent = "Findings (" + findCount + ")";

        const sev    = (data.severity || "").toUpperCase();
        const status = (data.status   || "").toUpperCase();
        const display = status || sev;
        const color  = status === "FAIL" ? "var(--red)" : (status === "WARN" ? "var(--yellow)" : severityColor(data.severity));

        const item = document.createElement("div");
        item.className = "finding-item";
        const shortUrl = (data.url || "").replace(/^https?:[/][/]/, "").slice(0, 70);
        item.innerHTML = `
          <div class="finding-sev" style="color:${color}">${display}</div>
          <div class="finding-body">
            <div class="finding-type">${data.finding_type || ""}</div>
            <div class="finding-url">${shortUrl}</div>
          </div>
        `;
        findingsList.appendChild(item);
        findingsList.scrollTop = findingsList.scrollHeight;
        break;
      }

      case "score": {
        const s = data.score || 0;
        miniScore.textContent = s;
        if      (s >= 80) miniScore.style.color = "var(--green)";
        else if (s >= 60) miniScore.style.color = "var(--yellow)";
        else              miniScore.style.color  = "var(--red)";
        break;
      }

      case "complete": {
        statusText.textContent = "Scan complete";
        pulseDot.className     = "pulse-dot done";
        progressBar.style.width = "100%";
        progressLbl.textContent = TOTAL + " / " + TOTAL;

        // Fill score card
        const score = data.score || 0;
        const grade = data.grade || "?";
        document.getElementById("scoreNum").textContent  = score;
        document.getElementById("gradeBadge").textContent = grade;
        document.getElementById("gradeBadge").className   = "grade-badge " + gradeClass(grade);
        document.getElementById("statPass").textContent  = data.passed  || 0;
        document.getElementById("statWarn").textContent  = data.warned  || 0;
        document.getElementById("statFail").textContent  = data.failed  || 0;

        // Severity bars
        const breakdown = data.breakdown || {};
        const total_sev = Object.values(breakdown).reduce((a,b)=>a+b,0) || 1;
        const sevDefs = [
          ["critical","var(--red)",    "Critical"],
          ["high",    "var(--orange)", "High"],
          ["medium",  "var(--yellow)", "Medium"],
          ["low",     "var(--cyan)",   "Low"],
          ["info",    "var(--dim)",    "Info"],
        ];
        const sevBars = document.getElementById("sevBars");
        sevDefs.forEach(([key, color, label]) => {
          const n   = breakdown[key] || 0;
          const pct = Math.round(n / total_sev * 100);
          const row = document.createElement("div");
          row.className = "sev-row";
          row.innerHTML = `
            <div class="sev-row-label">${label}</div>
            <div class="sev-row-bar-outer">
              <div class="sev-row-bar-inner" style="width:${pct}%;background:${color}"></div>
            </div>
            <div class="sev-row-count">${n}</div>
          `;
          sevBars.appendChild(row);
        });

        // Show overlay after a short delay
        setTimeout(() => {
          document.getElementById("scoreCard").classList.add("show");
        }, 800);

        es.close();
        break;
      }
    }
  };

  es.onerror = function() {
    statusText.textContent = "Connection lost";
  };
</script>
</body>
</html>
"""

# ── Event bus ─────────────────────────────────────────────────────────────────

class _EventBus:
    def __init__(self) -> None:
        self._queues: list = []
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue()
        with self._lock:
            self._queues.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            try:
                self._queues.remove(q)
            except ValueError:
                pass

    def push(self, event_type: str, data: Dict[str, Any]) -> None:
        payload = json.dumps({"type": event_type, **data})
        with self._lock:
            for q in list(self._queues):
                q.put(payload)


# ── HTTP handler ──────────────────────────────────────────────────────────────

def _make_handler(bus: _EventBus, html: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args) -> None:
            pass  # suppress access log

        def do_GET(self) -> None:
            if self.path in ("/", "/index.html"):
                body = html.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            elif self.path == "/events":
                self.send_response(200)
                self.send_header("Content-Type",  "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection",    "keep-alive")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                q = bus.subscribe()
                try:
                    while True:
                        try:
                            payload = q.get(timeout=15)
                            self.wfile.write(f"data: {payload}\n\n".encode())
                            self.wfile.flush()
                            if json.loads(payload).get("type") == "complete":
                                break
                        except queue.Empty:
                            self.wfile.write(b": ping\n\n")
                            self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    bus.unsubscribe(q)
            else:
                self.send_error(404)

    return Handler


# ── Public API ────────────────────────────────────────────────────────────────

class DashboardServer:
    """
    Starts a local HTTP server that streams scan events to a browser via SSE.

    Usage in cli.py:
        dash = DashboardServer(target, total_scanners=len(_active_tasks))
        port = dash.start()
        # ... run scanners, call dash.push_scanner_done(...) etc. ...
        dash.push_complete(score, grade, passed, warned, failed, breakdown)
    """

    def __init__(self, target: str, total_scanners: int) -> None:
        self.target          = target
        self.total_scanners  = total_scanners
        self._bus            = _EventBus()
        self._server: HTTPServer | None = None
        self._port: int | None = None

    def start(self, open_browser: bool = True) -> int:
        html    = _HTML.replace("{{TARGET}}", self.target).replace("{{TOTAL}}", str(self.total_scanners))
        handler = _make_handler(self._bus, html)
        server  = HTTPServer(("127.0.0.1", 0), handler)
        self._server = server
        self._port   = server.server_address[1]

        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        url = f"http://127.0.0.1:{self._port}"
        print(f"\n  \033[96m◆\033[0m  Dashboard → \033[1m{url}\033[0m\n")

        if open_browser:
            threading.Timer(0.4, lambda: webbrowser.open(url)).start()

        return self._port

    def push_scanner_done(self, module: str, results: List[Dict]) -> None:
        fails = sum(1 for r in results if r.get("status") == "FAIL")
        warns = sum(1 for r in results if r.get("status") == "WARN")
        self._bus.push("scanner_done", {"module": module, "fails": fails, "warns": warns})

        for r in results:
            if r.get("status") in ("FAIL", "WARN"):
                self._bus.push("finding", {
                    "finding_type": r.get("type", ""),
                    "status":       r.get("status", ""),
                    "severity":     r.get("severity", ""),
                    "url":          r.get("url", ""),
                })

    def push_score(self, score: int) -> None:
        self._bus.push("score", {"score": score})

    def push_complete(
        self,
        score: int,
        grade: str,
        passed: int,
        warned: int,
        failed: int,
        breakdown: Dict[str, int],
    ) -> None:
        self._bus.push("complete", {
            "score": score, "grade": grade,
            "passed": passed, "warned": warned, "failed": failed,
            "breakdown": breakdown,
        })

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
