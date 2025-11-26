package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
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
