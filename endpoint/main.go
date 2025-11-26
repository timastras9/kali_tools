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

const version = "3.0.0"

func main() {
	// Parse flags
	workers := flag.Int("w", 50, "Number of concurrent workers")
	timeout := flag.Int("timeout", 10, "Connection timeout in seconds")
	output := flag.String("o", "", "Output HTML report file")
	serve := flag.Bool("serve", false, "Start web UI server")
	port := flag.Int("port", 8080, "Web UI port")
	stealth := flag.Bool("stealth", false, "Stealth mode: slower scan, random delays (bypass WAF/Cloudflare)")
	delay := flag.Int("delay", 0, "Delay between requests in ms (0 = no delay)")
	depth := flag.Int("depth", 3, "Crawl depth for endpoint discovery")
	flag.Parse()

	// Stealth mode overrides
	if *stealth {
		if *workers > 10 {
			*workers = 10
		}
		if *delay == 0 {
			*delay = 500
		}
	}

	args := flag.Args()
	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	domain := args[0]
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")

	// Initialize report
	scanReport := &report.ScanReport{
		Target:    domain,
		Mode:      "Dynamic Discovery",
		StartTime: time.Now(),
	}

	// Print header
	printHeader(domain, *workers, *depth)

	// Start web server if requested
	var webServer *web.WebServer
	if *serve {
		webServer = web.NewWebServer(*port)
		go webServer.Start()
	}

	timeoutDuration := time.Duration(*timeout) * time.Second

	// ==========================================
	// PHASE 1: Subdomain Discovery (CT Logs + DNS Records)
	// ==========================================
	fmt.Println("\n🔍 Phase 1: Subdomain Discovery")
	fmt.Println("   Searching CT logs, DNS records (MX, NS, TXT, CNAME)...")
	phaseStart := time.Now()

	discoveredSubdomains := make(map[string]bool)

	// 1a: Certificate Transparency logs
	ctLookup := scanner.NewCTLookup(timeoutDuration)
	ctSubs, err := ctLookup.FindSubdomains(domain)
	if err == nil && len(ctSubs) > 0 {
		fmt.Printf("   ✅ CT Logs: Found %d subdomains\n", len(ctSubs))
		for _, sub := range ctSubs {
			discoveredSubdomains[sub] = true
		}
	}

	// 1b: DNS Records enumeration
	dnsEnum := scanner.NewDNSEnumerator(timeoutDuration)
	dnsSubs := dnsEnum.FindSubdomainsViaDNS(domain)
	if len(dnsSubs) > 0 {
		fmt.Printf("   ✅ DNS Records: Found %d subdomains\n", len(dnsSubs))
		for _, sub := range dnsSubs {
			discoveredSubdomains[sub] = true
		}
	}

	// Always add the base domain
	discoveredSubdomains[domain] = true
	discoveredSubdomains["www."+domain] = true

	// Verify which subdomains are live
	fmt.Printf("   Verifying %d potential subdomains...\n", len(discoveredSubdomains))
	subScanner := scanner.NewSubdomainScanner(*workers, timeoutDuration)

	// Convert to slice for scanning
	subsToCheck := make([]string, 0)
	for sub := range discoveredSubdomains {
		// Extract just subdomain part if it's a full domain
		if strings.HasSuffix(sub, "."+domain) {
			sub = strings.TrimSuffix(sub, "."+domain)
		}
		if sub != domain && sub != "" {
			subsToCheck = append(subsToCheck, sub)
		}
	}

	subResults := subScanner.Scan(domain, subsToCheck)

	// Add main domain to results
	mainDomainResult := subScanner.CheckSubdomain(domain)
	if mainDomainResult.Live {
		subResults = append(subResults, mainDomainResult)
	}

	liveHosts := []string{}
	for _, r := range subResults {
		if r.Live {
			liveHosts = append(liveHosts, r.Subdomain)
			fmt.Printf("   ✅ LIVE: %s (%s)\n", r.Subdomain, r.IP)

			// Check CNAME
			if cname, hasCNAME := dnsEnum.CheckCNAME(r.Subdomain); hasCNAME {
				fmt.Printf("      └─ CNAME: %s\n", cname)
			}

			scanReport.Subdomains = append(scanReport.Subdomains, report.SubdomainEntry{
				Subdomain:  r.Subdomain,
				IP:         r.IP,
				StatusCode: r.StatusCode,
				Scheme:     r.Scheme,
			})

			if webServer != nil {
				webServer.AddFinding(web.LiveFinding{
					Type:   "subdomain",
					Risk:   "INFO",
					Target: r.Subdomain,
					Detail: fmt.Sprintf("%s [%d]", r.Scheme, r.StatusCode),
				})
			}
		}
	}

	fmt.Printf("   Found %d live subdomains (%.1fs)\n", len(liveHosts), time.Since(phaseStart).Seconds())

	// ==========================================
	// PHASE 2: Dynamic Endpoint Discovery (Crawling)
	// ==========================================
	fmt.Println("\n🕷️  Phase 2: Endpoint Discovery (Crawling)")
	fmt.Println("   Crawling sites, parsing HTML/JS, checking robots.txt & sitemap.xml...")
	phaseStart = time.Now()

	crawler := scanner.NewCrawler(*workers, timeoutDuration)
	crawler.MaxDepth = *depth
	crawler.RateLimit = time.Duration(*delay) * time.Millisecond
	crawler.OnResult = func(r scanner.CrawlResult) {
		if r.StatusCode == 200 {
			fmt.Printf("   ✅ [%s] %s\n", r.Type, r.URL)

			if webServer != nil {
				webServer.AddFinding(web.LiveFinding{
					Type:   "endpoint",
					Risk:   "INFO",
					Target: r.URL,
					Detail: fmt.Sprintf("[%d] %s (from %s)", r.StatusCode, r.Type, r.Source),
				})
			}
		}
	}

	allEndpoints := make(map[string]scanner.CrawlResult)
	for _, host := range liveHosts {
		baseURL := fmt.Sprintf("https://%s", host)
		results := crawler.Crawl(baseURL)
		for _, r := range results {
			if r.StatusCode == 200 {
				allEndpoints[r.URL] = r
			}
		}

		// Also try HTTP if HTTPS failed
		baseURL = fmt.Sprintf("http://%s", host)
		results = crawler.Crawl(baseURL)
		for _, r := range results {
			if r.StatusCode == 200 {
				allEndpoints[r.URL] = r
			}
		}
	}

	// Convert to report format
	for _, r := range allEndpoints {
		scanReport.Paths = append(scanReport.Paths, report.PathEntry{
			URL:        r.URL,
			Path:       r.URL,
			StatusCode: r.StatusCode,
			Risk:       "INFO",
			Category:   r.Type,
		})
	}

	fmt.Printf("   Found %d unique endpoints (%.1fs)\n", len(allEndpoints), time.Since(phaseStart).Seconds())

	// ==========================================
	// PHASE 3: Port Scanning
	// ==========================================
	ports := scanner.Top100Ports
	fmt.Printf("\n🔌 Phase 3: Port Scanning (%d ports per host)\n", len(ports))
	phaseStart = time.Now()

	portScanner := scanner.NewPortScanner(*workers, timeoutDuration)
	portScanner.OnResult = func(r scanner.PortResult) {
		fmt.Printf("   ✅ %s:%d - %s\n", r.Host, r.Port, r.Service)

		vulnType := report.ClassifyServiceVulnerability(r.Service, false)
		owasp, cwe, nist := report.GetCompliance(string(vulnType))

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

		if webServer != nil {
			webServer.AddFinding(web.LiveFinding{
				Type:    "port",
				Risk:    r.Risk,
				Target:  fmt.Sprintf("%s:%d", r.Host, r.Port),
				Detail:  r.Service,
				Service: r.Service,
			})
		}
	}

	portScanner.ScanMultipleHosts(liveHosts, ports)
	fmt.Printf("   Found %d open ports (%.1fs)\n", len(portScanner.Results), time.Since(phaseStart).Seconds())

	// ==========================================
	// PHASE 4: Auth Testing
	// ==========================================
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

	if len(servicesToTest) > 0 {
		fmt.Printf("\n🔐 Phase 4: Auth Testing (%d services)\n", len(servicesToTest))
		phaseStart = time.Now()

		authTester := auth.NewAuthTester(timeoutDuration, *workers)
		authTester.OnResult = func(r auth.AuthResult) {
			if r.Credential != nil {
				fmt.Printf("   🚨 CRITICAL: %s:%d (%s) - Default creds: %s:%s\n",
					r.Host, r.Port, r.Service, r.Credential.Username, r.Credential.Password)
			} else if !r.AuthNeeded {
				fmt.Printf("   ⚠️  HIGH: %s:%d (%s) - No auth required\n",
					r.Host, r.Port, r.Service)
			}

			vulnType := report.ClassifyServiceVulnerability(r.Service, r.AuthNeeded)
			owasp, cwe, nist := report.GetCompliance(string(vulnType))

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

			if webServer != nil {
				webServer.AddFinding(web.LiveFinding{
					Type:    "auth",
					Risk:    r.Risk,
					Target:  fmt.Sprintf("%s:%d", r.Host, r.Port),
					Detail:  r.Message,
					Service: r.Service,
				})
			}
		}

		for _, s := range servicesToTest {
			authTester.TestService(s.host, s.port, s.service)
		}
		fmt.Printf("   Tested %d services (%.1fs)\n", len(authTester.Results), time.Since(phaseStart).Seconds())
	}

	// ==========================================
	// Generate Report
	// ==========================================
	totalFindings := len(scanReport.Subdomains) + len(scanReport.Paths) + len(scanReport.Ports) + len(scanReport.AuthResults)
	duration := time.Since(scanReport.StartTime)

	fmt.Printf("\n✅ Scan Complete!\n")
	fmt.Printf("   Duration: %s\n", duration.Round(time.Second))
	fmt.Printf("   Total Findings: %d\n", totalFindings)
	fmt.Printf("   Live Subdomains: %d\n", len(scanReport.Subdomains))
	fmt.Printf("   Endpoints: %d\n", len(scanReport.Paths))
	fmt.Printf("   Open Ports: %d\n", len(scanReport.Ports))
	fmt.Printf("   Auth Tests: %d\n", len(scanReport.AuthResults))

	// Generate HTML report
	outputFile := *output
	if outputFile == "" {
		outputFile = fmt.Sprintf("report_%s_%s.html", domain, time.Now().Format("20060102_150405"))
	}

	reportErr := report.GenerateHTMLReport(scanReport, outputFile)
	if reportErr != nil {
		fmt.Printf("\n❌ Failed to generate report: %v\n", reportErr)
	} else {
		fmt.Printf("\n📄 Report saved to: %s\n", outputFile)

		if openErr := report.OpenInBrowser(outputFile); openErr == nil {
			fmt.Println("🌐 Opening report in browser...")
		}
	}

	if *serve {
		fmt.Printf("\n🌐 Web UI running at http://localhost:%d\n", *port)
		fmt.Println("Press Ctrl+C to stop...")
		select {}
	}
}

func printUsage() {
	fmt.Printf(`
Endpoint Scanner v%s - Dynamic Security Reconnaissance

Usage:
  endpoint <domain> [options]

Examples:
  endpoint example.com                    # Full dynamic scan
  endpoint example.com -stealth           # Stealth mode (slower, evades WAF)
  endpoint example.com -depth 5           # Deeper crawl
  endpoint example.com -o report.html     # Custom report name
  endpoint example.com -serve             # Start web UI

Options:
`, version)
	flag.PrintDefaults()
	fmt.Println(`
Discovery Methods:
  - Certificate Transparency logs (crt.sh)
  - DNS Records (MX, NS, TXT, CNAME)
  - Web crawling (HTML links, JavaScript API endpoints)
  - robots.txt and sitemap.xml parsing

Compliance:
  Reports include OWASP Top 10, CWE, and NIST 800-53 mappings
`)
}

func printHeader(domain string, workers, depth int) {
	fmt.Printf(`
╭─────────────────────────────────────────────────────────╮
│  ENDPOINT SCANNER v%s                                │
│  Target: %-45s │
│  Mode: Dynamic Discovery                                │
│  Workers: %-44d │
│  Crawl Depth: %-40d │
╰─────────────────────────────────────────────────────────╯
`, version, domain, workers, depth)
}
