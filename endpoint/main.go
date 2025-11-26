package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/timastras9/kali_tools/endpoint/pkg/auth"
	"github.com/timastras9/kali_tools/endpoint/pkg/report"
	"github.com/timastras9/kali_tools/endpoint/pkg/scanner"
	"github.com/timastras9/kali_tools/endpoint/pkg/web"
)

const version = "3.3.0"

// Top 25 most common subdomains for brute forcing
var Top25Subdomains = []string{
	"www", "mail", "api", "admin", "dev",
	"staging", "test", "app", "portal", "secure",
	"vpn", "remote", "login", "dashboard", "cdn",
	"static", "assets", "blog", "shop", "support",
	"docs", "help", "status", "auth", "token",
}

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
	brute := flag.Bool("brute", false, "Enable DNS brute forcing with top 25 common subdomains")
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

	// Show MX records (mail servers)
	mxRecords := dnsEnum.GetMXRecords(domain)
	if len(mxRecords) > 0 {
		fmt.Println("   📧 MX Records (mail servers):")
		for _, mx := range mxRecords {
			fmt.Printf("      %s (priority %d)\n", mx.Host, mx.Pref)
		}
	}

	// Show NS records (nameservers)
	nsRecords := dnsEnum.GetNSRecords(domain)
	if len(nsRecords) > 0 {
		fmt.Println("   🌐 NS Records (nameservers):")
		for _, ns := range nsRecords {
			fmt.Printf("      %s\n", ns)
		}
	}

	// Show TXT records (SPF, DKIM, etc.)
	txtRecords := dnsEnum.GetTXTRecords(domain)
	if len(txtRecords) > 0 {
		fmt.Println("   📝 TXT Records:")
		for _, txt := range txtRecords {
			if len(txt) > 60 {
				fmt.Printf("      %s...\n", txt[:60])
			} else {
				fmt.Printf("      %s\n", txt)
			}
		}
	}

	// Show A/AAAA records
	aRecords := dnsEnum.GetARecords(domain)
	if len(aRecords) > 0 {
		fmt.Println("   🔢 A/AAAA Records:")
		for _, ip := range aRecords {
			fmt.Printf("      %s\n", ip)
		}
	}

	// Always add the base domain
	discoveredSubdomains[domain] = true
	discoveredSubdomains["www."+domain] = true

	// 1c: DNS brute forcing (optional)
	if *brute {
		fmt.Printf("   🔨 Brute forcing top 25 subdomains...\n")
		for _, prefix := range Top25Subdomains {
			discoveredSubdomains[prefix+"."+domain] = true
		}
	}

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

	// Check for new subdomains discovered during crawling
	if len(scanner.DiscoveredSubdomains) > 0 {
		fmt.Printf("\n🔍 Phase 2b: Verifying subdomains found in content...\n")

		// Track what we already have
		existingHosts := make(map[string]bool)
		for _, h := range liveHosts {
			existingHosts[h] = true
		}

		newSubsToCheck := []string{}
		checkedPrefixes := make(map[string]bool)

		for sub := range scanner.DiscoveredSubdomains {
			// Skip if we already have this exact subdomain
			if existingHosts[sub] {
				continue
			}

			// Extract subdomain prefix
			prefix := strings.TrimSuffix(sub, "."+domain)
			if prefix != sub && prefix != "" && !checkedPrefixes[prefix] {
				checkedPrefixes[prefix] = true
				newSubsToCheck = append(newSubsToCheck, prefix)
			}
		}

		if len(newSubsToCheck) > 0 {
			fmt.Printf("   Found %d new subdomain references, verifying...\n", len(newSubsToCheck))
			newSubResults := subScanner.Scan(domain, newSubsToCheck)
			for _, r := range newSubResults {
				if r.Live && !existingHosts[r.Subdomain] {
					existingHosts[r.Subdomain] = true
					liveHosts = append(liveHosts, r.Subdomain)
					fmt.Printf("   ✅ NEW: %s (%s)\n", r.Subdomain, r.IP)

					scanReport.Subdomains = append(scanReport.Subdomains, report.SubdomainEntry{
						Subdomain:  r.Subdomain,
						IP:         r.IP,
						StatusCode: r.StatusCode,
						Scheme:     r.Scheme,
					})

					// Crawl the new subdomain too
					baseURL := fmt.Sprintf("https://%s", r.Subdomain)
					results := crawler.Crawl(baseURL)
					for _, cr := range results {
						if cr.StatusCode == 200 && allEndpoints[cr.URL].URL == "" {
							allEndpoints[cr.URL] = cr
							scanReport.Paths = append(scanReport.Paths, report.PathEntry{
								URL:        cr.URL,
								Path:       cr.URL,
								StatusCode: cr.StatusCode,
								Risk:       "INFO",
								Category:   cr.Type,
							})
						}
					}
				}
			}
		}
	}

	// ==========================================
	// PHASE 3: Port Scanning
	// ==========================================
	// Deduplicate hosts by IP
	ipToHost := make(map[string]string)    // IP -> first hostname with that IP
	hostToIP := make(map[string]string)    // hostname -> IP (for reference)
	hostsToScan := []string{}
	proxiedHosts := []string{}

	for _, h := range liveHosts {
		ips, err := net.LookupHost(h)
		if err != nil || len(ips) == 0 {
			continue
		}
		ip := ips[0]
		hostToIP[h] = ip

		// Track if Cloudflare-proxied
		if isCloudflareIP(ip) {
			proxiedHosts = append(proxiedHosts, h)
		}

		if _, exists := ipToHost[ip]; !exists {
			// First host with this IP - scan it
			ipToHost[ip] = h
			hostsToScan = append(hostsToScan, h)
		}
	}

	// Show redundant hosts
	if len(liveHosts) > len(hostsToScan) {
		fmt.Printf("\n   ℹ️  Skipping redundant hosts (same IP):\n")
		for _, h := range liveHosts {
			ip := hostToIP[h]
			primaryHost := ipToHost[ip]
			if h != primaryHost {
				fmt.Printf("      %s → same as %s (%s)\n", h, primaryHost, ip)
			}
		}
	}

	// Filter out Cloudflare-proxied ports
	ports := scanner.Top100Ports
	portsToScan := ports
	if len(proxiedHosts) > 0 {
		fmt.Printf("\n   ☁️  Cloudflare detected - skipping proxied ports (80, 443, 8080, 8443, 2052-2096)\n")
		portsToScan = filterCloudfarePorts(ports)
	}

	fmt.Printf("\n🔌 Phase 3: Port Scanning (%d unique IPs, %d ports each)\n", len(hostsToScan), len(portsToScan))
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

	portScanner.ScanMultipleHosts(hostsToScan, portsToScan)
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
  endpoint example.com -brute             # Include DNS brute forcing
  endpoint example.com -stealth           # Stealth mode (slower, evades WAF)
  endpoint example.com -depth 5           # Deeper crawl
  endpoint example.com -o report.html     # Custom report name

Options:
`, version)
	flag.PrintDefaults()
	fmt.Println(`
Discovery Methods:
  - Certificate Transparency logs (crt.sh)
  - DNS Records (MX, NS, TXT, CNAME)
  - Web crawling (HTML links, JavaScript API endpoints)
  - robots.txt and sitemap.xml parsing
  - DNS brute forcing (-brute flag)

Top 25 Brute Force Subdomains:
  www, mail, api, admin, dev, staging, test, app, portal, secure,
  vpn, remote, login, dashboard, cdn, static, assets, blog, shop,
  support, docs, help, status, auth, token

Compliance:
  Reports include OWASP Top 10, CWE, and NIST 800-53 mappings
`)
}

// Cloudflare proxied ports - these just show Cloudflare, not origin
var cloudflareProxiedPorts = map[int]bool{
	80: true, 443: true, 8080: true, 8443: true,
	2052: true, 2053: true, 2082: true, 2083: true,
	2086: true, 2087: true, 2095: true, 2096: true,
	8880: true,
}

// filterCloudfarePorts removes Cloudflare-proxied ports from the list
func filterCloudfarePorts(ports []int) []int {
	filtered := []int{}
	for _, p := range ports {
		if !cloudflareProxiedPorts[p] {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// isCloudflareIP checks if an IP belongs to Cloudflare's network
func isCloudflareIP(ip string) bool {
	// Cloudflare IPv4 ranges
	cfPrefixes := []string{
		"104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
		"104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "104.29.", "104.30.", "104.31.",
		"172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71.",
		"173.245.", "141.101.", "108.162.", "162.158.", "162.159.",
		"190.93.", "188.114.", "197.234.", "198.41.",
		"103.21.", "103.22.", "103.31.",
	}

	// Cloudflare IPv6 prefixes
	cfIPv6Prefixes := []string{
		"2606:4700:", "2803:f800:", "2400:cb00:", "2405:b500:", "2405:8100:", "2a06:98c0:",
	}

	for _, prefix := range cfPrefixes {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}

	for _, prefix := range cfIPv6Prefixes {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}

	return false
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
