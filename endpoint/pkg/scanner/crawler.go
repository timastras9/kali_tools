package scanner

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CrawlResult holds a discovered endpoint
type CrawlResult struct {
	URL        string
	StatusCode int
	Source     string // Where we found this URL (parent page, robots.txt, sitemap, js)
	Type       string // page, api, asset, etc.
}

// Crawler discovers endpoints dynamically by crawling
type Crawler struct {
	Workers     int
	Timeout     time.Duration
	MaxDepth    int
	Results     []CrawlResult
	visited     map[string]bool
	mu          sync.Mutex
	OnResult    func(CrawlResult)
	OnProgress  func(found, queued int)
	RateLimit   time.Duration
	baseDomain  string
	client      *http.Client
}

// NewCrawler creates a new crawler
func NewCrawler(workers int, timeout time.Duration) *Crawler {
	return &Crawler{
		Workers:  workers,
		Timeout:  timeout,
		MaxDepth: 3,
		Results:  make([]CrawlResult, 0),
		visited:  make(map[string]bool),
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Crawl starts crawling from a base URL
func (c *Crawler) Crawl(baseURL string) []CrawlResult {
	// Parse base URL to get domain
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return c.Results
	}
	c.baseDomain = parsed.Host

	// Queue for URLs to visit
	queue := make(chan string, 10000)
	var wg sync.WaitGroup

	// Start with base URL
	queue <- baseURL

	// Mark as visited
	c.visited[baseURL] = true

	// Also check common entry points
	go func() {
		c.checkRobotsTxt(baseURL, queue)
		c.checkSitemap(baseURL, queue)
	}()

	// Track active workers
	var activeWorkers int32
	done := make(chan struct{})

	// Start workers
	for i := 0; i < c.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case targetURL, ok := <-queue:
					if !ok {
						return
					}
					atomic.AddInt32(&activeWorkers, 1)
					if c.RateLimit > 0 {
						time.Sleep(c.RateLimit)
					}
					c.crawlPage(targetURL, queue)
					atomic.AddInt32(&activeWorkers, -1)
				case <-done:
					return
				}
			}
		}()
	}

	// Smart wait: check if queue is idle (no active workers and empty queue)
	maxWait := 5 * time.Second
	checkInterval := 200 * time.Millisecond
	idleCount := 0
	startWait := time.Now()

	for time.Since(startWait) < maxWait {
		time.Sleep(checkInterval)
		if atomic.LoadInt32(&activeWorkers) == 0 && len(queue) == 0 {
			idleCount++
			if idleCount >= 3 { // Idle for 600ms
				break
			}
		} else {
			idleCount = 0
		}
	}

	close(done)
	close(queue)
	wg.Wait()

	return c.Results
}

// crawlPage fetches a page and extracts links
func (c *Crawler) crawlPage(pageURL string, queue chan<- string) {
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Record this endpoint
	result := CrawlResult{
		URL:        pageURL,
		StatusCode: resp.StatusCode,
		Source:     "crawl",
		Type:       c.classifyURL(pageURL, resp.Header.Get("Content-Type")),
	}

	// Only add if it's a valid response (200, or redirect)
	if resp.StatusCode == 200 || (resp.StatusCode >= 300 && resp.StatusCode < 400) {
		c.mu.Lock()
		c.Results = append(c.Results, result)
		c.mu.Unlock()

		if c.OnResult != nil {
			c.OnResult(result)
		}
	}

	// Only parse HTML pages for more links
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "application/javascript") {
		return
	}

	// Read body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5MB limit
	if err != nil {
		return
	}

	// Extract links
	links := c.extractLinks(string(body), pageURL)
	for _, link := range links {
		c.mu.Lock()
		if !c.visited[link] {
			c.visited[link] = true
			c.mu.Unlock()
			select {
			case queue <- link:
			default:
				// Queue full, skip
			}
		} else {
			c.mu.Unlock()
		}
	}

	// Extract subdomain references from content
	foundSubs := c.ExtractSubdomains(string(body), c.baseDomain)
	for _, sub := range foundSubs {
		AddDiscoveredSubdomain(sub)
	}

	// Extract API endpoints from JavaScript
	if strings.Contains(contentType, "javascript") || strings.Contains(string(body), "<script") {
		apis := c.extractAPIEndpoints(string(body), pageURL)
		for _, api := range apis {
			c.mu.Lock()
			if !c.visited[api] {
				c.visited[api] = true
				c.mu.Unlock()
				select {
				case queue <- api:
				default:
				}
			} else {
				c.mu.Unlock()
			}
		}
	}
}

// extractLinks extracts all links from HTML
func (c *Crawler) extractLinks(body, baseURL string) []string {
	var links []string
	base, _ := url.Parse(baseURL)

	// Patterns to find URLs
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`href=["']([^"']+)["']`),
		regexp.MustCompile(`src=["']([^"']+)["']`),
		regexp.MustCompile(`action=["']([^"']+)["']`),
		regexp.MustCompile(`url\(["']?([^"')]+)["']?\)`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 1 {
				link := c.normalizeURL(match[1], base)
				if link != "" && c.isSameDomain(link) {
					links = append(links, link)
				}
			}
		}
	}

	return links
}

// extractAPIEndpoints extracts API endpoints from JavaScript
func (c *Crawler) extractAPIEndpoints(body, baseURL string) []string {
	var endpoints []string
	base, _ := url.Parse(baseURL)

	// Patterns for API endpoints in JS
	patterns := []*regexp.Regexp{
		// API paths in quotes
		regexp.MustCompile(`[\"']/api/[^\"'\s]+[\"']`),
		regexp.MustCompile(`[\"']/v[0-9]+/[^\"'\s]+[\"']`),
		// Full URLs
		regexp.MustCompile(`[\"'](https?://[^\"'\s]+)[\"']`),
		// Relative paths
		regexp.MustCompile(`[\"'](/[a-zA-Z][a-zA-Z0-9_/\-]*)[\"']`),
		// fetch calls
		regexp.MustCompile(`fetch\s*\(\s*[\"']([^\"']+)[\"']`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 1 {
				endpoint := strings.Trim(match[1], "\"'")
				endpoint = c.normalizeURL(endpoint, base)
				if endpoint != "" && c.isSameDomain(endpoint) {
					endpoints = append(endpoints, endpoint)
				}
			} else if len(match) > 0 {
				endpoint := strings.Trim(match[0], "\"'")
				endpoint = c.normalizeURL(endpoint, base)
				if endpoint != "" && c.isSameDomain(endpoint) {
					endpoints = append(endpoints, endpoint)
				}
			}
		}
	}

	return endpoints
}

// checkRobotsTxt parses robots.txt for paths
func (c *Crawler) checkRobotsTxt(baseURL string, queue chan<- string) {
	robotsURL := strings.TrimSuffix(baseURL, "/") + "/robots.txt"

	resp, err := c.client.Get(robotsURL)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	base, _ := url.Parse(baseURL)

	// Extract paths from robots.txt
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Disallow:") || strings.HasPrefix(line, "Allow:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				path := strings.TrimSpace(parts[1])
				if path != "" && path != "/" && !strings.Contains(path, "*") {
					fullURL := c.normalizeURL(path, base)
					if fullURL != "" {
						c.mu.Lock()
						if !c.visited[fullURL] {
							c.visited[fullURL] = true
							c.mu.Unlock()

							// Record from robots.txt
							result := CrawlResult{
								URL:    fullURL,
								Source: "robots.txt",
								Type:   "discovered",
							}
							c.Results = append(c.Results, result)
							if c.OnResult != nil {
								c.OnResult(result)
							}

							select {
							case queue <- fullURL:
							default:
							}
						} else {
							c.mu.Unlock()
						}
					}
				}
			}
		}

		// Also check Sitemap directive
		if strings.HasPrefix(line, "Sitemap:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				sitemapURL := strings.TrimSpace(parts[1])
				c.parseSitemap(sitemapURL, queue)
			}
		}
	}
}

// checkSitemap checks for sitemap.xml
func (c *Crawler) checkSitemap(baseURL string, queue chan<- string) {
	sitemapURL := strings.TrimSuffix(baseURL, "/") + "/sitemap.xml"
	c.parseSitemap(sitemapURL, queue)
}

// parseSitemap parses a sitemap XML
func (c *Crawler) parseSitemap(sitemapURL string, queue chan<- string) {
	resp, err := c.client.Get(sitemapURL)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Extract URLs from sitemap
	pattern := regexp.MustCompile(`<loc>([^<]+)</loc>`)
	matches := pattern.FindAllStringSubmatch(string(body), -1)

	for _, match := range matches {
		if len(match) > 1 {
			pageURL := strings.TrimSpace(match[1])
			if c.isSameDomain(pageURL) {
				c.mu.Lock()
				if !c.visited[pageURL] {
					c.visited[pageURL] = true
					c.mu.Unlock()

					result := CrawlResult{
						URL:    pageURL,
						Source: "sitemap",
						Type:   "discovered",
					}
					c.Results = append(c.Results, result)
					if c.OnResult != nil {
						c.OnResult(result)
					}

					select {
					case queue <- pageURL:
					default:
					}
				} else {
					c.mu.Unlock()
				}
			}
		}
	}
}

// normalizeURL converts relative URLs to absolute
func (c *Crawler) normalizeURL(rawURL string, base *url.URL) string {
	// Skip empty, anchors, javascript, mailto
	if rawURL == "" || strings.HasPrefix(rawURL, "#") ||
		strings.HasPrefix(rawURL, "javascript:") ||
		strings.HasPrefix(rawURL, "mailto:") ||
		strings.HasPrefix(rawURL, "tel:") ||
		strings.HasPrefix(rawURL, "data:") {
		return ""
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(parsed)

	// Remove fragments
	resolved.Fragment = ""

	return resolved.String()
}

// isSameDomain checks if URL belongs to target domain
func (c *Crawler) isSameDomain(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Check if it's the same domain or a subdomain
	host := parsed.Host
	if host == c.baseDomain {
		return true
	}
	if strings.HasSuffix(host, "."+c.baseDomain) {
		return true
	}

	// Also match if baseDomain has www and this doesn't (or vice versa)
	baseWithoutWWW := strings.TrimPrefix(c.baseDomain, "www.")
	hostWithoutWWW := strings.TrimPrefix(host, "www.")
	return hostWithoutWWW == baseWithoutWWW || strings.HasSuffix(hostWithoutWWW, "."+baseWithoutWWW)
}

// ExtractSubdomains finds subdomain references in crawled content
func (c *Crawler) ExtractSubdomains(body, baseDomain string) []string {
	subdomains := make(map[string]bool)

	// Pattern to find subdomains of the target domain
	escapedDomain := regexp.QuoteMeta(baseDomain)
	pattern := regexp.MustCompile(`([a-zA-Z0-9][-a-zA-Z0-9]*\.)+` + escapedDomain)

	matches := pattern.FindAllString(body, -1)
	for _, match := range matches {
		match = strings.ToLower(match)
		if match != baseDomain && strings.HasSuffix(match, baseDomain) {
			subdomains[match] = true
		}
	}

	// Also look for subdomains in URLs
	urlPattern := regexp.MustCompile(`https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.)*` + escapedDomain)
	urlMatches := urlPattern.FindAllString(body, -1)
	for _, match := range urlMatches {
		// Extract just the hostname
		if u, err := url.Parse(match); err == nil {
			host := strings.ToLower(u.Host)
			if host != baseDomain && strings.HasSuffix(host, baseDomain) {
				subdomains[host] = true
			}
		}
	}

	result := make([]string, 0, len(subdomains))
	for sub := range subdomains {
		result = append(result, sub)
	}
	return result
}

// DiscoveredSubdomains holds subdomains found during crawling
var DiscoveredSubdomains = make(map[string]bool)
var discoveredSubMu sync.Mutex

// AddDiscoveredSubdomain safely adds a subdomain to the discovered list
func AddDiscoveredSubdomain(sub string) {
	discoveredSubMu.Lock()
	DiscoveredSubdomains[sub] = true
	discoveredSubMu.Unlock()
}

// GetDiscoveredSubdomains returns a copy of discovered subdomains
func GetDiscoveredSubdomains() map[string]bool {
	discoveredSubMu.Lock()
	defer discoveredSubMu.Unlock()
	copy := make(map[string]bool)
	for k, v := range DiscoveredSubdomains {
		copy[k] = v
	}
	return copy
}

// classifyURL determines the type of endpoint
func (c *Crawler) classifyURL(rawURL, contentType string) string {
	lowerURL := strings.ToLower(rawURL)

	if strings.Contains(lowerURL, "/api/") || strings.Contains(lowerURL, "/v1/") || strings.Contains(lowerURL, "/v2/") {
		return "api"
	}
	if strings.Contains(contentType, "json") {
		return "api"
	}
	if strings.Contains(contentType, "javascript") {
		return "script"
	}
	if strings.Contains(contentType, "css") {
		return "style"
	}
	if strings.Contains(contentType, "image") {
		return "image"
	}
	if strings.Contains(contentType, "html") {
		return "page"
	}

	return "other"
}
