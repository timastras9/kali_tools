package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CTResult holds a certificate transparency log entry
type CTResult struct {
	NameValue string `json:"name_value"`
	CommonName string `json:"common_name"`
}

// CTLookup queries Certificate Transparency logs to find real subdomains
type CTLookup struct {
	Timeout time.Duration
	client  *http.Client
}

// NewCTLookup creates a new CT lookup client
func NewCTLookup(timeout time.Duration) *CTLookup {
	return &CTLookup{
		Timeout: timeout,
		client: &http.Client{
			Timeout: timeout * 3, // CT queries can be slow
		},
	}
}

// FindSubdomains queries crt.sh for all subdomains of a domain
func (ct *CTLookup) FindSubdomains(domain string) ([]string, error) {
	subdomains := make(map[string]bool)

	// Query crt.sh (Certificate Transparency log aggregator)
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

	resp, err := ct.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CT lookup failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CT lookup returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var results []CTResult
	if err := json.Unmarshal(body, &results); err != nil {
		// Sometimes crt.sh returns empty or invalid JSON
		return ct.extractFromText(string(body), domain), nil
	}

	// Extract unique subdomains
	for _, r := range results {
		// name_value can contain multiple domains separated by newlines
		names := strings.Split(r.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(strings.ToLower(name))
			if ct.isValidSubdomain(name, domain) {
				subdomains[name] = true
			}
		}

		// Also check common_name
		cn := strings.TrimSpace(strings.ToLower(r.CommonName))
		if ct.isValidSubdomain(cn, domain) {
			subdomains[cn] = true
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(subdomains))
	for sub := range subdomains {
		result = append(result, sub)
	}

	return result, nil
}

// extractFromText extracts subdomains from raw text (fallback)
func (ct *CTLookup) extractFromText(text, domain string) []string {
	subdomains := make(map[string]bool)

	// Regex to find subdomains
	escapedDomain := regexp.QuoteMeta(domain)
	pattern := regexp.MustCompile(`([a-zA-Z0-9][-a-zA-Z0-9]*\.)*` + escapedDomain)

	matches := pattern.FindAllString(text, -1)
	for _, match := range matches {
		match = strings.ToLower(match)
		if ct.isValidSubdomain(match, domain) {
			subdomains[match] = true
		}
	}

	result := make([]string, 0, len(subdomains))
	for sub := range subdomains {
		result = append(result, sub)
	}
	return result
}

// isValidSubdomain checks if a string is a valid subdomain of the target
func (ct *CTLookup) isValidSubdomain(name, domain string) bool {
	if name == "" || name == domain {
		return false
	}

	// Must end with the domain
	if !strings.HasSuffix(name, "."+domain) && name != domain {
		return false
	}

	// Skip wildcards
	if strings.Contains(name, "*") {
		return false
	}

	// Skip very long subdomains (likely garbage)
	if len(name) > 100 {
		return false
	}

	return true
}

// FindSubdomainsMultiSource queries multiple sources for subdomains
func (ct *CTLookup) FindSubdomainsMultiSource(domain string) ([]string, error) {
	allSubdomains := make(map[string]bool)

	// Source 1: crt.sh (Certificate Transparency)
	ctSubs, err := ct.FindSubdomains(domain)
	if err == nil {
		for _, sub := range ctSubs {
			allSubdomains[sub] = true
		}
	}

	// Source 2: DNS common records check
	dnsSubs := ct.checkCommonDNSRecords(domain)
	for _, sub := range dnsSubs {
		allSubdomains[sub] = true
	}

	// Convert to slice
	result := make([]string, 0, len(allSubdomains))
	for sub := range allSubdomains {
		result = append(result, sub)
	}

	return result, nil
}

// checkCommonDNSRecords checks for common DNS record patterns
func (ct *CTLookup) checkCommonDNSRecords(domain string) []string {
	// This just returns the wordlist subdomains to check via DNS
	// The actual DNS resolution happens in SubdomainScanner
	return nil
}

// DNSEnumerator discovers subdomains via DNS records
type DNSEnumerator struct {
	Timeout time.Duration
}

// NewDNSEnumerator creates a new DNS enumerator
func NewDNSEnumerator(timeout time.Duration) *DNSEnumerator {
	return &DNSEnumerator{Timeout: timeout}
}

// FindSubdomainsViaDNS tries to discover subdomains through DNS records
func (de *DNSEnumerator) FindSubdomainsViaDNS(domain string) []string {
	subdomains := make(map[string]bool)

	// Check various DNS record types that might reveal subdomains
	// MX records often reveal mail subdomains
	mxRecords, _ := net.LookupMX(domain)
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		if de.isSubdomain(host, domain) {
			subdomains[host] = true
		}
	}

	// NS records
	nsRecords, _ := net.LookupNS(domain)
	for _, ns := range nsRecords {
		host := strings.TrimSuffix(ns.Host, ".")
		if de.isSubdomain(host, domain) {
			subdomains[host] = true
		}
	}

	// TXT records sometimes contain subdomain references
	txtRecords, _ := net.LookupTXT(domain)
	for _, txt := range txtRecords {
		// Look for domain references in TXT records
		pattern := regexp.MustCompile(`([a-zA-Z0-9][-a-zA-Z0-9]*\.)+` + regexp.QuoteMeta(domain))
		matches := pattern.FindAllString(txt, -1)
		for _, match := range matches {
			if de.isSubdomain(match, domain) {
				subdomains[match] = true
			}
		}
	}

	// Convert to slice
	result := make([]string, 0, len(subdomains))
	for sub := range subdomains {
		result = append(result, sub)
	}
	return result
}

// CheckCNAME checks if a subdomain has a CNAME record
func (de *DNSEnumerator) CheckCNAME(subdomain string) (string, bool) {
	cname, err := net.LookupCNAME(subdomain)
	if err != nil {
		return "", false
	}
	cname = strings.TrimSuffix(cname, ".")
	if cname != subdomain && cname != "" {
		return cname, true
	}
	return "", false
}

// isSubdomain checks if host is a subdomain of domain
func (de *DNSEnumerator) isSubdomain(host, domain string) bool {
	host = strings.ToLower(host)
	domain = strings.ToLower(domain)
	return strings.HasSuffix(host, "."+domain) || host == domain
}

// GetMXRecords returns MX records for a domain
func (de *DNSEnumerator) GetMXRecords(domain string) []*net.MX {
	records, err := net.LookupMX(domain)
	if err != nil {
		return nil
	}
	return records
}

// GetNSRecords returns NS records for a domain
func (de *DNSEnumerator) GetNSRecords(domain string) []string {
	records, err := net.LookupNS(domain)
	if err != nil {
		return nil
	}
	result := make([]string, 0, len(records))
	for _, ns := range records {
		result = append(result, strings.TrimSuffix(ns.Host, "."))
	}
	return result
}

// GetTXTRecords returns TXT records for a domain
func (de *DNSEnumerator) GetTXTRecords(domain string) []string {
	records, err := net.LookupTXT(domain)
	if err != nil {
		return nil
	}
	return records
}

// GetARecords returns A and AAAA records for a domain
func (de *DNSEnumerator) GetARecords(domain string) []string {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil
	}
	return ips
}

// GeoLocation holds IP geolocation data
type GeoLocation struct {
	IP          string  `json:"query"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"regionName"`
	City        string  `json:"city"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

// GeolocateIP looks up geographic location for an IP address
func GeolocateIP(ip string) (*GeoLocation, error) {
	// Skip IPv6 for now (ip-api.com supports it but results vary)
	if strings.Contains(ip, ":") {
		return nil, fmt.Errorf("IPv6 not supported")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://ip-api.com/json/%s", ip)

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var geo GeoLocation
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return nil, err
	}

	return &geo, nil
}

// GeolocateIPs looks up multiple IPs in parallel
func GeolocateIPs(ips []string) map[string]*GeoLocation {
	results := make(map[string]*GeoLocation)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()
			geo, err := GeolocateIP(ipAddr)
			if err == nil && geo != nil {
				mu.Lock()
				results[ipAddr] = geo
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return results
}
