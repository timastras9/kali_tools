package report

import (
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ScanReport holds all scan results
type ScanReport struct {
	Target          string
	Mode            string
	StartTime       time.Time
	EndTime         time.Time
	Duration        time.Duration
	Subdomains      []SubdomainEntry
	Paths           []PathEntry
	Ports           []PortEntry
	AuthResults     []AuthEntry
	DNSRecords      DNSInfo
	GeoLocations    []GeoInfo
	Summary         ReportSummary
	CloudflareHosts string // Comma-separated list of hosts behind Cloudflare
}

// DNSInfo holds DNS record information
type DNSInfo struct {
	MXRecords  []string
	NSRecords  []string
	TXTRecords []string
	ARecords   []string
}

// GeoInfo holds IP geolocation data for the report
type GeoInfo struct {
	IP      string
	Country string
	City    string
	ISP     string
	Org     string
}

type SubdomainEntry struct {
	Subdomain  string
	IP         string
	StatusCode int
	Scheme     string
}

type PathEntry struct {
	URL        string
	Path       string
	StatusCode int
	Size       int64
	Risk       string
	Category   string
	OWASP      string // OWASP Top 10 mapping
	CWE        string // CWE ID
	NIST       string // NIST 800-53 control
}

type PortEntry struct {
	Host        string
	Port        int
	Service     string
	Banner      string
	Risk        string
	OWASP       string // OWASP Top 10 mapping
	CWE         string // CWE ID
	NIST        string // NIST 800-53 control
	IsCloudflare bool  // True if this is a Cloudflare-proxied port
}

type AuthEntry struct {
	Host       string
	Port       int
	Service    string
	AuthNeeded bool
	Username   string
	Password   string
	Risk       string
	Message    string
	OWASP      string // OWASP Top 10 mapping
	CWE        string // CWE ID
	NIST       string // NIST 800-53 control
}

type ReportSummary struct {
	TotalSubdomains int
	TotalPaths      int
	TotalPorts      int
	TotalAuthTests  int
	CriticalCount   int
	HighCount       int
	MediumCount     int
	LowCount        int
	InfoCount       int
}

// Templates are embedded directly in the code for simplicity

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Endpoint Scan Report - {{.Target}}</title>
    <meta name="description" content="Security scan report following OWASP Top 10 and NIST 800-53 standards">
    <style>
        :root {
            --bg-dark: #0d1117;
            --bg-card: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
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
            background: var(--bg-dark);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        .header h1 {
            color: var(--accent);
            font-size: 2rem;
            margin-bottom: 1rem;
        }
        .header-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .header-info div { color: var(--text-muted); }
        .header-info strong { color: var(--text); }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .summary-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }
        .summary-card.critical { border-left: 4px solid var(--critical); }
        .summary-card.high { border-left: 4px solid var(--high); }
        .summary-card.medium { border-left: 4px solid var(--medium); }
        .summary-card.low { border-left: 4px solid var(--low); }
        .summary-card.info { border-left: 4px solid var(--info); }
        .summary-card .count {
            font-size: 2.5rem;
            font-weight: bold;
        }
        .summary-card.critical .count { color: var(--critical); }
        .summary-card.high .count { color: var(--high); }
        .summary-card.medium .count { color: var(--medium); }
        .summary-card.low .count { color: var(--low); }
        .summary-card.info .count { color: var(--info); }
        .summary-card .label { color: var(--text-muted); font-size: 0.875rem; }
        .section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 2rem;
            overflow: hidden;
        }
        .section-header {
            background: rgba(0,0,0,0.2);
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .section-header h2 { font-size: 1.25rem; }
        .section-header .count {
            background: var(--border);
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.875rem;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th {
            background: rgba(0,0,0,0.2);
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 0.75rem;
        }
        tr:hover { background: rgba(255,255,255,0.02); }
        .risk-badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
        }
        .risk-critical { background: var(--critical); color: white; }
        .risk-high { background: var(--high); color: white; }
        .risk-medium { background: var(--medium); color: black; }
        .risk-low { background: var(--low); color: white; }
        .risk-info { background: var(--info); color: white; }
        .status-200 { color: var(--low); }
        .status-301, .status-302 { color: var(--info); }
        .status-401, .status-403 { color: var(--medium); }
        .status-500 { color: var(--critical); }
        code {
            background: rgba(0,0,0,0.3);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.875rem;
        }
        .footer {
            text-align: center;
            color: var(--text-muted);
            padding: 2rem;
            font-size: 0.875rem;
        }
        @media print {
            body { background: white; color: black; }
            .section, .header, .summary-card { border-color: #ddd; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Endpoint Scan Report</h1>
            <div class="header-info">
                <div><strong>Target:</strong> {{.Target}}</div>
                <div><strong>Mode:</strong> {{.Mode}}</div>
                <div><strong>Started:</strong> {{.StartTime.Format "2006-01-02 15:04:05"}}</div>
                <div><strong>Duration:</strong> {{.Duration.Round 1000000000}}</div>
            </div>
        </div>

        <div class="summary">
            <div class="summary-card critical">
                <div class="count">{{.Summary.CriticalCount}}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{{.Summary.HighCount}}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{{.Summary.MediumCount}}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{{.Summary.LowCount}}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="count">{{.Summary.InfoCount}}</div>
                <div class="label">Info</div>
            </div>
        </div>

        {{if or .DNSRecords.MXRecords .DNSRecords.NSRecords .DNSRecords.TXTRecords .DNSRecords.ARecords}}
        <div class="section">
            <div class="section-header">
                <h2>📋 DNS Records</h2>
            </div>
            <div style="padding: 1rem;">
                {{if .DNSRecords.ARecords}}
                <div style="margin-bottom: 1rem;">
                    <strong style="color: var(--info);">🔢 A/AAAA Records:</strong>
                    <ul style="margin-top: 0.5rem; padding-left: 2rem;">
                        {{range .DNSRecords.ARecords}}<li><code>{{.}}</code></li>{{end}}
                    </ul>
                </div>
                {{end}}
                {{if .DNSRecords.MXRecords}}
                <div style="margin-bottom: 1rem;">
                    <strong style="color: var(--info);">📧 MX Records (Mail Servers):</strong>
                    <ul style="margin-top: 0.5rem; padding-left: 2rem;">
                        {{range .DNSRecords.MXRecords}}<li><code>{{.}}</code></li>{{end}}
                    </ul>
                </div>
                {{end}}
                {{if .DNSRecords.NSRecords}}
                <div style="margin-bottom: 1rem;">
                    <strong style="color: var(--info);">🌐 NS Records (Nameservers):</strong>
                    <ul style="margin-top: 0.5rem; padding-left: 2rem;">
                        {{range .DNSRecords.NSRecords}}<li><code>{{.}}</code></li>{{end}}
                    </ul>
                </div>
                {{end}}
                {{if .DNSRecords.TXTRecords}}
                <div style="margin-bottom: 1rem;">
                    <strong style="color: var(--info);">📝 TXT Records:</strong>
                    <ul style="margin-top: 0.5rem; padding-left: 2rem;">
                        {{range .DNSRecords.TXTRecords}}<li><code style="word-break: break-all;">{{.}}</code></li>{{end}}
                    </ul>
                </div>
                {{end}}
            </div>
        </div>
        {{end}}

        {{if .GeoLocations}}
        <div class="section">
            <div class="section-header">
                <h2>📍 IP Geolocation</h2>
                <span class="count">{{len .GeoLocations}} IPs</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Location</th>
                        <th>ISP / Organization</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .GeoLocations}}
                    <tr>
                        <td><code>{{.IP}}</code></td>
                        <td>{{.City}}, {{.Country}}</td>
                        <td>{{.ISP}}{{if .Org}} ({{.Org}}){{end}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}

        {{if .Subdomains}}
        <div class="section">
            <div class="section-header">
                <h2>🌐 Subdomains</h2>
                <span class="count">{{len .Subdomains}} found</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>IP Address</th>
                        <th>Scheme</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Subdomains}}
                    <tr>
                        <td><code>{{.Subdomain}}</code></td>
                        <td>{{.IP}}</td>
                        <td>{{.Scheme}}</td>
                        <td class="status-{{.StatusCode}}">{{.StatusCode}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}

        {{if .Paths}}
        <div class="section">
            <div class="section-header">
                <h2>📁 Discovered Paths</h2>
                <span class="count">{{len .Paths}} found</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Risk</th>
                        <th>Path</th>
                        <th>URL</th>
                        <th>Status</th>
                        <th>Size</th>
                        <th>Category</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Paths}}
                    <tr>
                        <td><span class="risk-badge risk-{{lower .Risk}}">{{.Risk}}</span></td>
                        <td><code>{{.Path}}</code></td>
                        <td><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
                        <td class="status-{{.StatusCode}}">{{.StatusCode}}</td>
                        <td>{{.Size}} bytes</td>
                        <td>{{.Category}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}

        {{if .Ports}}
        <div class="section">
            <div class="section-header">
                <h2>🔌 Open Ports</h2>
                <span class="count">{{len .Ports}} found</span>
            </div>
            {{if .CloudflareHosts}}
            <div style="padding: 1rem; border-bottom: 1px solid var(--border);">
                <strong style="color: var(--info);">☁️ Hosts behind Cloudflare:</strong>
                <code style="margin-left: 0.5rem;">{{.CloudflareHosts}}</code>
            </div>
            {{end}}
            <table>
                <thead>
                    <tr>
                        <th>Risk</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Ports}}
                    <tr>
                        <td><span class="risk-badge risk-{{lower .Risk}}">{{.Risk}}</span></td>
                        <td>{{.Port}}</td>
                        <td>{{.Service}}</td>
                        <td>{{if .IsCloudflare}}<span style="color: var(--info);">☁️ Cloudflare Proxy</span>{{else}}{{.Banner}}{{end}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}

        {{if .AuthResults}}
        <div class="section">
            <div class="section-header">
                <h2>🔐 Authentication Findings</h2>
                <span class="count">{{len .AuthResults}} tested</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Risk</th>
                        <th>Host</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Auth Required</th>
                        <th>Credentials</th>
                        <th>Notes</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .AuthResults}}
                    <tr>
                        <td><span class="risk-badge risk-{{lower .Risk}}">{{.Risk}}</span></td>
                        <td>{{.Host}}</td>
                        <td>{{.Port}}</td>
                        <td>{{.Service}}</td>
                        <td>{{if .AuthNeeded}}Yes{{else}}No{{end}}</td>
                        <td>{{if .Username}}<code>{{.Username}}:{{.Password}}</code>{{else}}-{{end}}</td>
                        <td>{{.Message}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}

        <div class="footer">
            <p>Generated by Endpoint Scanner v2.0</p>
            <p>{{.EndTime.Format "2006-01-02 15:04:05 MST"}}</p>
        </div>
    </div>
</body>
</html>`

// riskPriority returns a numeric priority for sorting (lower = more critical)
func riskPriority(risk string) int {
	switch risk {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	default:
		return 4 // INFO
	}
}

// sortReportBySeverity sorts all findings by severity (Critical first)
func sortReportBySeverity(report *ScanReport) {
	// Sort paths by risk
	sort.Slice(report.Paths, func(i, j int) bool {
		return riskPriority(report.Paths[i].Risk) < riskPriority(report.Paths[j].Risk)
	})

	// Sort ports by risk
	sort.Slice(report.Ports, func(i, j int) bool {
		return riskPriority(report.Ports[i].Risk) < riskPriority(report.Ports[j].Risk)
	})

	// Sort auth results by risk
	sort.Slice(report.AuthResults, func(i, j int) bool {
		return riskPriority(report.AuthResults[i].Risk) < riskPriority(report.AuthResults[j].Risk)
	})
}

// GenerateHTMLReport creates an HTML report
func GenerateHTMLReport(report *ScanReport, outputPath string) error {
	funcMap := template.FuncMap{
		"lower": func(s string) string {
			if len(s) == 0 {
				return s
			}
			return string([]byte{s[0] + 32}) + s[1:]
		},
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	report.EndTime = time.Now()
	report.Duration = report.EndTime.Sub(report.StartTime)

	// Sort all findings by severity (Critical first)
	sortReportBySeverity(report)

	// Calculate summary
	report.Summary.TotalSubdomains = len(report.Subdomains)
	report.Summary.TotalPaths = len(report.Paths)
	report.Summary.TotalPorts = len(report.Ports)
	report.Summary.TotalAuthTests = len(report.AuthResults)

	// Count by risk
	for _, p := range report.Paths {
		switch p.Risk {
		case "CRITICAL":
			report.Summary.CriticalCount++
		case "HIGH":
			report.Summary.HighCount++
		case "MEDIUM":
			report.Summary.MediumCount++
		case "LOW":
			report.Summary.LowCount++
		default:
			report.Summary.InfoCount++
		}
	}

	for _, p := range report.Ports {
		switch p.Risk {
		case "CRITICAL":
			report.Summary.CriticalCount++
		case "HIGH":
			report.Summary.HighCount++
		case "MEDIUM":
			report.Summary.MediumCount++
		case "LOW":
			report.Summary.LowCount++
		default:
			report.Summary.InfoCount++
		}
	}

	for _, a := range report.AuthResults {
		switch a.Risk {
		case "CRITICAL":
			report.Summary.CriticalCount++
		case "HIGH":
			report.Summary.HighCount++
		case "MEDIUM":
			report.Summary.MediumCount++
		case "LOW":
			report.Summary.LowCount++
		default:
			report.Summary.InfoCount++
		}
	}

	return tmpl.Execute(file, report)
}

// OpenInBrowser opens the report in the default browser
func OpenInBrowser(path string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", path)
	default:
		return fmt.Errorf("unsupported platform")
	}

	return cmd.Start()
}

// GenerateHTMLReportString generates an HTML report as a string (for API responses)
func GenerateHTMLReportString(report *ScanReport) (string, error) {
	funcMap := template.FuncMap{
		"lower": func(s string) string {
			if len(s) == 0 {
				return s
			}
			return string([]byte{s[0] + 32}) + s[1:]
		},
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	report.EndTime = time.Now()
	report.Duration = report.EndTime.Sub(report.StartTime)

	// Sort all findings by severity (Critical first)
	sortReportBySeverity(report)

	// Calculate summary
	report.Summary.TotalSubdomains = len(report.Subdomains)
	report.Summary.TotalPaths = len(report.Paths)
	report.Summary.TotalPorts = len(report.Ports)
	report.Summary.TotalAuthTests = len(report.AuthResults)

	// Count by risk
	for _, p := range report.Paths {
		switch p.Risk {
		case "CRITICAL":
			report.Summary.CriticalCount++
		case "HIGH":
			report.Summary.HighCount++
		case "MEDIUM":
			report.Summary.MediumCount++
		case "LOW":
			report.Summary.LowCount++
		default:
			report.Summary.InfoCount++
		}
	}

	for _, p := range report.Ports {
		switch p.Risk {
		case "CRITICAL":
			report.Summary.CriticalCount++
		case "HIGH":
			report.Summary.HighCount++
		case "MEDIUM":
			report.Summary.MediumCount++
		case "LOW":
			report.Summary.LowCount++
		default:
			report.Summary.InfoCount++
		}
	}

	for _, a := range report.AuthResults {
		switch a.Risk {
		case "CRITICAL":
			report.Summary.CriticalCount++
		case "HIGH":
			report.Summary.HighCount++
		case "MEDIUM":
			report.Summary.MediumCount++
		case "LOW":
			report.Summary.LowCount++
		default:
			report.Summary.InfoCount++
		}
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, report); err != nil {
		return "", err
	}
	return buf.String(), nil
}
