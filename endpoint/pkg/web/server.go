package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"
)

// ScanStatus represents current scan status
type ScanStatus struct {
	Phase      string    `json:"phase"`
	Progress   int       `json:"progress"`
	Total      int       `json:"total"`
	Found      int       `json:"found"`
	StartTime  time.Time `json:"start_time"`
	IsRunning  bool      `json:"is_running"`
	IsComplete bool      `json:"is_complete"`
}

// LiveFinding represents a finding for live updates
type LiveFinding struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Risk      string    `json:"risk"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail"`
	Service   string    `json:"service,omitempty"`
}

// WebServer handles the web UI
type WebServer struct {
	Port     int
	Status   ScanStatus
	Findings []LiveFinding
	mu       sync.RWMutex
	clients  map[chan LiveFinding]bool
}

// NewWebServer creates a new web server
func NewWebServer(port int) *WebServer {
	return &WebServer{
		Port:     port,
		Findings: make([]LiveFinding, 0),
		clients:  make(map[chan LiveFinding]bool),
	}
}

// Start starts the web server
func (ws *WebServer) Start() error {
	http.HandleFunc("/", ws.handleIndex)
	http.HandleFunc("/api/status", ws.handleStatus)
	http.HandleFunc("/api/findings", ws.handleFindings)
	http.HandleFunc("/api/events", ws.handleSSE)

	fmt.Printf("\n[*] Web UI available at http://localhost:%d\n", ws.Port)
	return http.ListenAndServe(fmt.Sprintf(":%d", ws.Port), nil)
}

// UpdateStatus updates the scan status
func (ws *WebServer) UpdateStatus(phase string, progress, total, found int, running, complete bool) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	ws.Status = ScanStatus{
		Phase:      phase,
		Progress:   progress,
		Total:      total,
		Found:      found,
		IsRunning:  running,
		IsComplete: complete,
	}
}

// AddFinding adds a new finding and broadcasts to clients
func (ws *WebServer) AddFinding(f LiveFinding) {
	ws.mu.Lock()
	f.Timestamp = time.Now()
	ws.Findings = append(ws.Findings, f)
	ws.mu.Unlock()

	// Broadcast to SSE clients
	ws.mu.RLock()
	for client := range ws.clients {
		select {
		case client <- f:
		default:
		}
	}
	ws.mu.RUnlock()
}

// handleIndex serves the main page
func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("index").Parse(indexHTML))
	tmpl.Execute(w, nil)
}

// handleStatus returns current status as JSON
func (ws *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ws.Status)
}

// handleFindings returns all findings as JSON
func (ws *WebServer) handleFindings(w http.ResponseWriter, r *http.Request) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ws.Findings)
}

// handleSSE handles Server-Sent Events for live updates
func (ws *WebServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	client := make(chan LiveFinding, 100)
	ws.mu.Lock()
	ws.clients[client] = true
	ws.mu.Unlock()

	defer func() {
		ws.mu.Lock()
		delete(ws.clients, client)
		close(client)
		ws.mu.Unlock()
	}()

	for {
		select {
		case finding := <-client:
			data, _ := json.Marshal(finding)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Endpoint Scanner - Live</title>
    <style>
        :root {
            --bg: #0d1117;
            --card: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --muted: #8b949e;
            --critical: #f85149;
            --high: #f0883e;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
            --accent: #238636;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        header {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        header h1 { color: var(--accent); display: flex; align-items: center; gap: 0.5rem; }
        .status-badge {
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: bold;
        }
        .status-running { background: var(--accent); animation: pulse 2s infinite; }
        .status-complete { background: var(--info); }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
        .progress-section {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        .progress-bar {
            height: 8px;
            background: var(--border);
            border-radius: 4px;
            overflow: hidden;
            margin: 1rem 0;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--accent), var(--info));
            transition: width 0.3s;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }
        .stat-card.critical { border-top: 3px solid var(--critical); }
        .stat-card.high { border-top: 3px solid var(--high); }
        .stat-card.medium { border-top: 3px solid var(--medium); }
        .stat-card.low { border-top: 3px solid var(--low); }
        .stat-card.info { border-top: 3px solid var(--info); }
        .stat-count { font-size: 2rem; font-weight: bold; }
        .stat-card.critical .stat-count { color: var(--critical); }
        .stat-card.high .stat-count { color: var(--high); }
        .stat-card.medium .stat-count { color: var(--medium); }
        .stat-card.low .stat-count { color: var(--low); }
        .stat-card.info .stat-count { color: var(--info); }
        .findings {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            max-height: 600px;
            overflow-y: auto;
        }
        .findings-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
            font-weight: bold;
            position: sticky;
            top: 0;
            background: var(--card);
        }
        .finding {
            padding: 0.75rem 1.5rem;
            border-bottom: 1px solid var(--border);
            display: grid;
            grid-template-columns: 100px 1fr auto;
            gap: 1rem;
            align-items: center;
            animation: slideIn 0.3s;
        }
        @keyframes slideIn { from { opacity: 0; transform: translateX(-10px); } }
        .finding:hover { background: rgba(255,255,255,0.02); }
        .risk-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            text-align: center;
        }
        .risk-critical { background: var(--critical); }
        .risk-high { background: var(--high); }
        .risk-medium { background: var(--medium); color: #000; }
        .risk-low { background: var(--low); }
        .risk-info { background: var(--info); }
        .finding-target { font-family: monospace; word-break: break-all; }
        .finding-time { color: var(--muted); font-size: 0.875rem; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Endpoint Scanner</h1>
            <span id="status" class="status-badge status-running">Scanning...</span>
        </header>

        <div class="progress-section">
            <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                <span id="phase">Initializing...</span>
                <span id="progress-text">0%</span>
            </div>
            <div class="progress-bar">
                <div id="progress-fill" class="progress-fill" style="width: 0%"></div>
            </div>
            <div style="display: flex; justify-content: space-between; color: var(--muted); font-size: 0.875rem;">
                <span id="found">Found: 0</span>
                <span id="elapsed">Elapsed: 0s</span>
            </div>
        </div>

        <div class="stats">
            <div class="stat-card critical">
                <div id="critical-count" class="stat-count">0</div>
                <div>Critical</div>
            </div>
            <div class="stat-card high">
                <div id="high-count" class="stat-count">0</div>
                <div>High</div>
            </div>
            <div class="stat-card medium">
                <div id="medium-count" class="stat-count">0</div>
                <div>Medium</div>
            </div>
            <div class="stat-card low">
                <div id="low-count" class="stat-count">0</div>
                <div>Low</div>
            </div>
            <div class="stat-card info">
                <div id="info-count" class="stat-count">0</div>
                <div>Info</div>
            </div>
        </div>

        <div class="findings">
            <div class="findings-header">Live Findings</div>
            <div id="findings-list"></div>
        </div>
    </div>

    <script>
        const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        let startTime = Date.now();

        // SSE for live updates
        const evtSource = new EventSource('/api/events');
        evtSource.onmessage = (e) => {
            const finding = JSON.parse(e.data);
            addFinding(finding);
        };

        // Poll status
        setInterval(async () => {
            const res = await fetch('/api/status');
            const status = await res.json();
            updateStatus(status);
        }, 1000);

        function addFinding(f) {
            const list = document.getElementById('findings-list');
            const div = document.createElement('div');
            div.className = 'finding';
            div.innerHTML = ` +
	"`" + `
                <span class="risk-badge risk-${f.risk.toLowerCase()}">${f.risk}</span>
                <span class="finding-target">${f.target} - ${f.detail}</span>
                <span class="finding-time">${new Date(f.timestamp).toLocaleTimeString()}</span>
            ` + "`" + `;
            list.insertBefore(div, list.firstChild);

            // Update counts
            counts[f.risk.toLowerCase()]++;
            document.getElementById(f.risk.toLowerCase() + '-count').textContent = counts[f.risk.toLowerCase()];
        }

        function updateStatus(s) {
            document.getElementById('phase').textContent = s.phase;
            const pct = s.total > 0 ? Math.round((s.progress / s.total) * 100) : 0;
            document.getElementById('progress-text').textContent = pct + '%';
            document.getElementById('progress-fill').style.width = pct + '%';
            document.getElementById('found').textContent = 'Found: ' + s.found;

            const elapsed = Math.round((Date.now() - startTime) / 1000);
            document.getElementById('elapsed').textContent = 'Elapsed: ' + elapsed + 's';

            const statusEl = document.getElementById('status');
            if (s.is_complete) {
                statusEl.textContent = 'Complete';
                statusEl.className = 'status-badge status-complete';
            }
        }
    </script>
</body>
</html>`
