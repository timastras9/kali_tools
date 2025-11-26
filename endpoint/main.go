package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/timastras9/kali_tools/endpoint/pkg/auth"
	"github.com/timastras9/kali_tools/endpoint/pkg/report"
	"github.com/timastras9/kali_tools/endpoint/pkg/scanner"
	"github.com/timastras9/kali_tools/endpoint/pkg/web"
)

const version = "2.0.0"

func main() {
	// Parse flags BEFORE positional args
	top50 := flag.Bool("top50", false, "Quick scan: 50 high-risk endpoints + top 50 ports")
	_ = flag.Bool("top100", false, "Standard scan: 100 endpoints + top 100 ports (default)")
	all := flag.Bool("all", false, "Full scan: extended wordlists + all ports")
	workers := flag.Int("w", 100, "Number of concurrent workers")
	timeout := flag.Int("timeout", 5, "Connection timeout in seconds")
	output := flag.String("o", "", "Output HTML report file")
	serve := flag.Bool("serve", false, "Start web UI server")
	port := flag.Int("port", 8080, "Web UI port")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	domain := args[0]
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")

	// Determine scan mode
	mode := "Standard (-top100)"
	var subdomains, paths []string
	var ports []int

	switch {
	case *top50:
		mode = "Quick (-top50)"
		subdomains = scanner.Top50Subdomains
		paths = scanner.Top50Paths
		ports = scanner.Top50Ports
	case *all:
		mode = "Full (-all)"
		subdomains = scanner.ExtendedSubdomains
		paths = scanner.ExtendedPaths
		ports = scanner.Top100Ports
	default: // top100 or default
		subdomains = scanner.DefaultSubdomains
		paths = scanner.Top100Paths
		ports = scanner.Top100Ports
	}

	// Initialize report
	scanReport := &report.ScanReport{
		Target:    domain,
		Mode:      mode,
		StartTime: time.Now(),
	}

	// Print header
	printHeader(domain, mode, *workers)

	// Start web server if requested
	var webServer *web.WebServer
	if *serve {
		webServer = web.NewWebServer(*port)
		go webServer.Start()
	}

	timeoutDuration := time.Duration(*timeout) * time.Second

	// ==========================================
	// PHASE 1: Subdomain Discovery
	// ==========================================
	report.PrintPhaseStart("Subdomain Discovery", len(subdomains))
	phaseStart := time.Now()

	subScanner := scanner.NewSubdomainScanner(*workers, timeoutDuration)
	subScanner.OnResult = func(r scanner.SubdomainResult) {
		report.PrintFindingInstant("INFO", r.Subdomain, fmt.Sprintf("%s [%d]", r.Scheme, r.StatusCode))
		if webServer != nil {
			webServer.AddFinding(web.LiveFinding{
				Type:   "subdomain",
				Risk:   "INFO",
				Target: r.Subdomain,
				Detail: fmt.Sprintf("%s [%d]", r.Scheme, r.StatusCode),
			})
		}
	}

	subResults := subScanner.Scan(domain, subdomains)
	report.PrintPhaseComplete("Subdomain Discovery", len(subResults), time.Since(phaseStart))

	// Convert to report format
	for _, r := range subResults {
		scanReport.Subdomains = append(scanReport.Subdomains, report.SubdomainEntry{
			Subdomain:  r.Subdomain,
			IP:         r.IP,
			StatusCode: r.StatusCode,
			Scheme:     r.Scheme,
		})
	}

	// Collect all hosts to scan
	hosts := []string{domain}
	for _, r := range subResults {
		hosts = append(hosts, r.Subdomain)
	}

	// ==========================================
	// PHASE 2: Path Discovery
	// ==========================================
	report.PrintPhaseStart("Path Discovery", len(paths)*len(hosts))
	phaseStart = time.Now()

	pathScanner := scanner.NewPathScanner(*workers, timeoutDuration)
	pathScanner.OnResult = func(r scanner.PathResult) {
		// Determine if vulnerable
		vulnType := report.ClassifyPathVulnerability(r.Path)
		owasp, cwe, nist := report.GetCompliance(string(vulnType))

		risk := r.Risk
		if r.StatusCode == 200 && (r.Risk == "CRITICAL" || r.Risk == "HIGH") {
			report.PrintFindingInstant(risk, r.URL, fmt.Sprintf("VULNERABLE - %s", owasp))
		} else {
			report.PrintFindingInstant(risk, r.URL, fmt.Sprintf("[%d]", r.StatusCode))
		}

		if webServer != nil {
			webServer.AddFinding(web.LiveFinding{
				Type:   "path",
				Risk:   risk,
				Target: r.URL,
				Detail: fmt.Sprintf("[%d] %s", r.StatusCode, r.Category),
			})
		}

		scanReport.Paths = append(scanReport.Paths, report.PathEntry{
			URL:        r.URL,
			Path:       r.Path,
			StatusCode: r.StatusCode,
			Size:       r.Size,
			Risk:       r.Risk,
			Category:   r.Category,
			OWASP:      owasp,
			CWE:        cwe,
			NIST:       nist,
		})
	}

	for _, host := range hosts {
		baseURL := fmt.Sprintf("https://%s", host)
		pathScanner.Scan(baseURL, paths)
	}
	report.PrintPhaseComplete("Path Discovery", len(pathScanner.Results), time.Since(phaseStart))

	// ==========================================
	// PHASE 3: Port Scanning
	// ==========================================
	report.PrintPhaseStart("Port Scanning", len(ports)*len(hosts))
	phaseStart = time.Now()

	portScanner := scanner.NewPortScanner(*workers, timeoutDuration)
	portScanner.OnResult = func(r scanner.PortResult) {
		vulnType := report.ClassifyServiceVulnerability(r.Service, false)
		owasp, cwe, nist := report.GetCompliance(string(vulnType))

		if r.Risk == "CRITICAL" || r.Risk == "HIGH" {
			report.PrintFindingInstant(r.Risk, fmt.Sprintf("%s:%d", r.Host, r.Port),
				fmt.Sprintf("VULNERABLE - %s (%s)", r.Service, owasp))
		} else {
			report.PrintFindingInstant(r.Risk, fmt.Sprintf("%s:%d", r.Host, r.Port), r.Service)
		}

		if webServer != nil {
			webServer.AddFinding(web.LiveFinding{
				Type:    "port",
				Risk:    r.Risk,
				Target:  fmt.Sprintf("%s:%d", r.Host, r.Port),
				Detail:  r.Service,
				Service: r.Service,
			})
		}

		scanReport.Ports = append(scanReport.Ports, report.PortEntry{
			Host:    r.Host,
			Port:    r.Port,
			Service: r.Service,
			Banner:  r.Banner,
			Risk:    r.Risk,
			OWASP:   owasp,
			CWE:     cwe,
			NIST:    nist,
		})
	}

	portScanner.ScanMultipleHosts(hosts, ports)
	report.PrintPhaseComplete("Port Scanning", len(portScanner.Results), time.Since(phaseStart))

	// ==========================================
	// PHASE 4: Service Detection (from port results)
	// ==========================================
	report.PrintPhaseStart("Service Detection", len(portScanner.Results))
	phaseStart = time.Now()
	// Service detection already done during port scanning
	report.PrintPhaseComplete("Service Detection", len(portScanner.Results), time.Since(phaseStart))

	// ==========================================
	// PHASE 5: Auth Testing
	// ==========================================
	// Get unique services to test
	servicesToTest := make(map[string]struct {
		host    string
		port    int
		service string
	})

	for _, p := range portScanner.Results {
		if p.Service != "" && p.Service != "Unknown" {
			key := fmt.Sprintf("%s:%d", p.Host, p.Port)
			servicesToTest[key] = struct {
				host    string
				port    int
				service string
			}{p.Host, p.Port, p.Service}
		}
	}

	report.PrintPhaseStart("Auth Testing", len(servicesToTest))
	phaseStart = time.Now()

	authTester := auth.NewAuthTester(timeoutDuration, *workers)
	authTester.OnResult = func(r auth.AuthResult) {
		vulnType := report.ClassifyServiceVulnerability(r.Service, r.AuthNeeded)
		owasp, cwe, nist := report.GetCompliance(string(vulnType))

		if r.Credential != nil {
			report.PrintFindingInstant("CRITICAL",
				fmt.Sprintf("%s:%d", r.Host, r.Port),
				fmt.Sprintf("VULNERABLE - Default creds: %s:%s (%s)", r.Credential.Username, r.Credential.Password, owasp))
		} else if !r.AuthNeeded {
			report.PrintFindingInstant("HIGH",
				fmt.Sprintf("%s:%d", r.Host, r.Port),
				fmt.Sprintf("VULNERABLE - No auth required (%s)", owasp))
		}

		if webServer != nil {
			webServer.AddFinding(web.LiveFinding{
				Type:    "auth",
				Risk:    r.Risk,
				Target:  fmt.Sprintf("%s:%d", r.Host, r.Port),
				Detail:  r.Message,
				Service: r.Service,
			})
		}

		username := ""
		password := ""
		if r.Credential != nil {
			username = r.Credential.Username
			password = r.Credential.Password
		}

		scanReport.AuthResults = append(scanReport.AuthResults, report.AuthEntry{
			Host:       r.Host,
			Port:       r.Port,
			Service:    r.Service,
			AuthNeeded: r.AuthNeeded,
			Username:   username,
			Password:   password,
			Risk:       r.Risk,
			Message:    r.Message,
			OWASP:      owasp,
			CWE:        cwe,
			NIST:       nist,
		})
	}

	for _, s := range servicesToTest {
		authTester.TestService(s.host, s.port, s.service)
	}
	report.PrintPhaseComplete("Auth Testing", len(authTester.Results), time.Since(phaseStart))

	// ==========================================
	// Generate Report
	// ==========================================
	fmt.Println()

	// Print summary
	totalFindings := len(scanReport.Subdomains) + len(scanReport.Paths) + len(scanReport.Ports) + len(scanReport.AuthResults)
	duration := time.Since(scanReport.StartTime)

	fmt.Printf("\n✅ Scan Complete!\n")
	fmt.Printf("   Duration: %s\n", duration.Round(time.Second))
	fmt.Printf("   Total Findings: %d\n", totalFindings)
	fmt.Printf("   Subdomains: %d\n", len(scanReport.Subdomains))
	fmt.Printf("   Paths: %d\n", len(scanReport.Paths))
	fmt.Printf("   Open Ports: %d\n", len(scanReport.Ports))
	fmt.Printf("   Auth Tests: %d\n", len(scanReport.AuthResults))

	// Generate HTML report
	outputFile := *output
	if outputFile == "" {
		outputFile = fmt.Sprintf("report_%s_%s.html", domain, time.Now().Format("20060102_150405"))
	}

	err := report.GenerateHTMLReport(scanReport, outputFile)
	if err != nil {
		fmt.Printf("\n❌ Failed to generate report: %v\n", err)
	} else {
		fmt.Printf("\n📄 Report saved to: %s\n", outputFile)

		// Open in browser
		if err := report.OpenInBrowser(outputFile); err == nil {
			fmt.Println("🌐 Opening report in browser...")
		}
	}

	// Keep web server running if started
	if *serve {
		fmt.Printf("\n🌐 Web UI running at http://localhost:%d\n", *port)
		fmt.Println("Press Ctrl+C to stop...")
		select {}
	}
}

func printUsage() {
	fmt.Printf(`
Endpoint Scanner v%s - Security Reconnaissance Tool

Usage:
  go run . <domain> [options]

Examples:
  go run . example.com                    # Standard scan (top100)
  go run . example.com -top50             # Quick scan
  go run . example.com -all               # Full comprehensive scan
  go run . example.com -all -o report.html
  go run . example.com -serve             # Start web UI

Options:
`, version)
	flag.PrintDefaults()
	fmt.Println(`
Scan Modes:
  -top50    Quick scan: 50 high-risk paths + 50 critical ports
  -top100   Standard scan (default): 100 paths + 100 ports
  -all      Full scan: Extended wordlists, all common ports

Compliance:
  Reports include OWASP Top 10, CWE, and NIST 800-53 mappings

Output:
  HTML report auto-generated and opened in browser
  Use -serve for live web UI at localhost:8080
`)
}

func printHeader(domain, mode string, workers int) {
	fmt.Printf(`
╭─────────────────────────────────────────────────────────╮
│  ENDPOINT SCANNER v%s                                │
│  Target: %-45s │
│  Mode: %-47s │
│  Workers: %-44d │
╰─────────────────────────────────────────────────────────╯
`, version, domain, mode, workers)
}
