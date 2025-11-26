package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/timastras9/kali_tools/endpoint/pkg/auth"
	"github.com/timastras9/kali_tools/endpoint/pkg/report"
	"github.com/timastras9/kali_tools/endpoint/pkg/scanner"
)

// ScanRequest is the JSON request body for a scan
type ScanRequest struct {
	Domain  string `json:"domain"`
	Brute   bool   `json:"brute"`
	Stealth bool   `json:"stealth"`
	Depth   int    `json:"depth"`
}

// ScanResponse is the JSON response from a scan
type ScanResponse struct {
	Success    bool               `json:"success"`
	Error      string             `json:"error,omitempty"`
	Target     string             `json:"target"`
	Duration   string             `json:"duration"`
	Report     *report.ScanReport `json:"report,omitempty"`
	ReportHTML string             `json:"report_html,omitempty"`
}

// StartAPIServer starts the HTTP API server
func StartAPIServer() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()

	// Health check endpoint (required by Cloud Run)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Scan endpoint
	mux.HandleFunc("/scan", handleScan)

	// CORS middleware
	handler := corsMiddleware(mux)

	log.Printf("Starting API server on port %s", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow requests from nsicorp.org
		origin := r.Header.Get("Origin")
		if origin == "https://nsicorp.org" || origin == "https://www.nsicorp.org" ||
			strings.HasSuffix(origin, ".nsicorp.pages.dev") ||
			origin == "http://localhost:4321" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate domain
	domain := strings.TrimSpace(req.Domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")

	if domain == "" {
		sendError(w, "Domain is required", http.StatusBadRequest)
		return
	}

	// Set defaults
	if req.Depth <= 0 {
		req.Depth = 3
	}

	workers := 50
	timeout := 10 * time.Second
	delay := 0

	if req.Stealth {
		workers = 10
		delay = 500
	}

	// Run the scan
	log.Printf("Starting scan for domain: %s (brute=%v, stealth=%v, depth=%d)",
		domain, req.Brute, req.Stealth, req.Depth)

	scanReport, err := runScan(domain, workers, timeout, delay, req.Depth, req.Brute)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Generate HTML report
	htmlReport, err := report.GenerateHTMLReportString(scanReport)
	if err != nil {
		log.Printf("Warning: could not generate HTML report: %v", err)
	}

	response := ScanResponse{
		Success:    true,
		Target:     domain,
		Duration:   time.Since(scanReport.StartTime).Round(time.Second).String(),
		Report:     scanReport,
		ReportHTML: htmlReport,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func sendError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ScanResponse{
		Success: false,
		Error:   message,
	})
}

func runScan(domain string, workers int, timeout time.Duration, delay, depth int, brute bool) (*report.ScanReport, error) {
	scanReport := &report.ScanReport{
		Target:    domain,
		Mode:      "API Scan",
		StartTime: time.Now(),
	}

	// Phase 1: Subdomain Discovery
	discoveredSubdomains := make(map[string]bool)
	var subMu sync.Mutex

	var phase1Wg sync.WaitGroup
	ctLookup := scanner.NewCTLookup(timeout)
	dnsEnum := scanner.NewDNSEnumerator(timeout)

	// CT logs
	phase1Wg.Add(1)
	go func() {
		defer phase1Wg.Done()
		ctSubs, err := ctLookup.FindSubdomains(domain)
		if err == nil {
			subMu.Lock()
			for _, sub := range ctSubs {
				discoveredSubdomains[sub] = true
			}
			subMu.Unlock()
		}
	}()

	// DNS records
	phase1Wg.Add(1)
	go func() {
		defer phase1Wg.Done()
		dnsSubs := dnsEnum.FindSubdomainsViaDNS(domain)
		subMu.Lock()
		for _, sub := range dnsSubs {
			discoveredSubdomains[sub] = true
		}
		subMu.Unlock()
	}()

	// Gather DNS records
	var mxRecords []*net.MX
	var nsRecords, txtRecords, aRecords []string

	phase1Wg.Add(4)
	go func() {
		defer phase1Wg.Done()
		mxRecords = dnsEnum.GetMXRecords(domain)
	}()
	go func() {
		defer phase1Wg.Done()
		nsRecords = dnsEnum.GetNSRecords(domain)
	}()
	go func() {
		defer phase1Wg.Done()
		txtRecords = dnsEnum.GetTXTRecords(domain)
	}()
	go func() {
		defer phase1Wg.Done()
		aRecords = dnsEnum.GetARecords(domain)
	}()

	phase1Wg.Wait()

	// Store DNS records in report
	for _, mx := range mxRecords {
		scanReport.DNSRecords.MXRecords = append(scanReport.DNSRecords.MXRecords,
			fmt.Sprintf("%s (priority %d)", strings.TrimSuffix(mx.Host, "."), mx.Pref))
	}
	scanReport.DNSRecords.NSRecords = nsRecords
	scanReport.DNSRecords.TXTRecords = txtRecords
	scanReport.DNSRecords.ARecords = aRecords

	// Geolocate IPs
	ipv4s := []string{}
	for _, ip := range aRecords {
		if !strings.Contains(ip, ":") {
			ipv4s = append(ipv4s, ip)
		}
	}
	if len(ipv4s) > 0 {
		geoResults := scanner.GeolocateIPs(ipv4s)
		for ip, geo := range geoResults {
			scanReport.GeoLocations = append(scanReport.GeoLocations, report.GeoInfo{
				IP:      ip,
				Country: geo.Country,
				City:    geo.City,
				ISP:     geo.ISP,
				Org:     geo.Org,
			})
		}
	}

	// Add base domain
	discoveredSubdomains[domain] = true
	discoveredSubdomains["www."+domain] = true

	// Brute force subdomains
	if brute {
		for _, prefix := range Top25Subdomains {
			discoveredSubdomains[prefix+"."+domain] = true
		}
	}

	// Verify subdomains
	subScanner := scanner.NewSubdomainScanner(workers, timeout)
	subsToCheck := make([]string, 0)
	for sub := range discoveredSubdomains {
		if strings.HasSuffix(sub, "."+domain) {
			sub = strings.TrimSuffix(sub, "."+domain)
		}
		if sub != domain && sub != "" {
			subsToCheck = append(subsToCheck, sub)
		}
	}

	subResults := subScanner.Scan(domain, subsToCheck)
	mainDomainResult := subScanner.CheckSubdomain(domain)
	if mainDomainResult.Live {
		subResults = append(subResults, mainDomainResult)
	}

	liveHosts := []string{}
	for _, r := range subResults {
		if r.Live {
			liveHosts = append(liveHosts, r.Subdomain)
			scanReport.Subdomains = append(scanReport.Subdomains, report.SubdomainEntry{
				Subdomain:  r.Subdomain,
				IP:         r.IP,
				StatusCode: r.StatusCode,
				Scheme:     r.Scheme,
			})
		}
	}

	// Phase 2: Crawling
	crawler := scanner.NewCrawler(workers, timeout)
	crawler.MaxDepth = depth
	crawler.RateLimit = time.Duration(delay) * time.Millisecond

	pathToURLs := make(map[string][]scanner.CrawlResult)
	var pathMu sync.Mutex

	var crawlWg sync.WaitGroup
	hostSem := make(chan struct{}, 5)

	for _, host := range liveHosts {
		crawlWg.Add(1)
		go func(h string) {
			defer crawlWg.Done()
			hostSem <- struct{}{}
			defer func() { <-hostSem }()

			hostCrawler := scanner.NewCrawler(workers, timeout)
			hostCrawler.MaxDepth = depth
			hostCrawler.RateLimit = time.Duration(delay) * time.Millisecond

			for _, scheme := range []string{"https", "http"} {
				baseURL := fmt.Sprintf("%s://%s", scheme, h)
				results := hostCrawler.Crawl(baseURL)
				for _, r := range results {
					if r.StatusCode == 200 {
						path := extractPath(r.URL)
						pathMu.Lock()
						pathToURLs[path] = append(pathToURLs[path], r)
						pathMu.Unlock()
					}
				}
			}
		}(host)
	}
	crawlWg.Wait()

	// Deduplicate paths
	for path, urls := range pathToURLs {
		if len(urls) == 0 {
			continue
		}
		canonical := urls[0]
		for _, u := range urls {
			if strings.Contains(u.URL, "www.") {
				canonical = u
				break
			}
		}
		scanReport.Paths = append(scanReport.Paths, report.PathEntry{
			URL:        canonical.URL,
			Path:       path,
			StatusCode: canonical.StatusCode,
			Risk:       "INFO",
			Category:   canonical.Type,
		})
	}

	// Phase 3: Port Scanning
	ipToHost := make(map[string]string)
	hostToIP := make(map[string]string)
	hostsToScan := []string{}
	proxiedHosts := []string{}

	for _, h := range liveHosts {
		ips, err := net.LookupHost(h)
		if err != nil || len(ips) == 0 {
			continue
		}
		ip := ips[0]
		hostToIP[h] = ip

		if isCloudflareIP(ip) {
			proxiedHosts = append(proxiedHosts, h)
		}

		if _, exists := ipToHost[ip]; !exists {
			ipToHost[ip] = h
			hostsToScan = append(hostsToScan, h)
		}
	}

	ports := scanner.Top100Ports
	portsToScan := ports
	isCloudflareHost := len(proxiedHosts) > 0

	if isCloudflareHost {
		portsToScan = filterCloudfarePorts(ports)
		scanReport.CloudflareHosts = strings.Join(hostsToScan, ", ")

		for port := range cloudflareProxiedPorts {
			scanReport.Ports = append(scanReport.Ports, report.PortEntry{
				Port:         port,
				Service:      getServiceName(port),
				Risk:         "INFO",
				IsCloudflare: true,
			})
		}
	}

	portScanner := scanner.NewPortScanner(workers, timeout)
	portScanner.OnResult = func(r scanner.PortResult) {
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
	}

	portScanner.ScanMultipleHosts(hostsToScan, portsToScan)

	// Phase 4: Auth Testing
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
		authTester := auth.NewAuthTester(timeout, workers)
		authTester.OnResult = func(r auth.AuthResult) {
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
		}

		for _, s := range servicesToTest {
			authTester.TestService(s.host, s.port, s.service)
		}
	}

	return scanReport, nil
}
