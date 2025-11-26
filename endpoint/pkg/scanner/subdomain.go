package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// SubdomainResult holds discovered subdomain info
type SubdomainResult struct {
	Subdomain  string
	IP         string
	StatusCode int
	Scheme     string // http or https
	Live       bool
}

// SubdomainScanner handles async subdomain enumeration
type SubdomainScanner struct {
	Workers    int
	Timeout    time.Duration
	Results    []SubdomainResult
	mu         sync.Mutex
	OnResult   func(SubdomainResult)
	OnProgress func(current, total int)
}

// Default subdomains (prioritized by likelihood)
var DefaultSubdomains = []string{
	"www", "mail", "api", "admin", "dev", "staging", "test", "beta",
	"app", "portal", "secure", "vpn", "remote", "login", "dashboard",
	"cms", "blog", "shop", "store", "support", "help", "docs",
	"cdn", "static", "assets", "media", "images", "img", "files",
	"ns1", "ns2", "dns", "mx", "smtp", "pop", "imap", "webmail",
	"ftp", "sftp", "ssh", "git", "gitlab", "github", "svn",
	"jenkins", "ci", "build", "deploy", "docker", "k8s", "kubernetes",
	"db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
	"api-v1", "api-v2", "v1", "v2", "graphql", "rest",
	"internal", "intranet", "extranet", "corp", "corporate",
	"hr", "finance", "sales", "marketing", "engineering",
	"dev1", "dev2", "stage", "uat", "qa", "prod", "production",
	// Auth & Security
	"auth", "oauth", "sso", "token", "tokens", "jwt", "identity", "id",
	"accounts", "account", "signin", "signup", "register", "password",
	"2fa", "mfa", "otp", "verify", "verification", "activate",
	// Cloud & Services
	"aws", "azure", "gcp", "cloud", "s3", "storage", "backup",
	"pay", "payment", "payments", "billing", "checkout", "cart",
}

// Top 50 high-risk subdomains
var Top50Subdomains = []string{
	"admin", "api", "dev", "staging", "test", "beta", "internal",
	"jenkins", "gitlab", "docker", "kubernetes", "k8s", "elastic",
	"kibana", "grafana", "prometheus", "vault", "consul",
	"db", "mysql", "postgres", "mongo", "redis", "memcache",
	"vpn", "remote", "ssh", "ftp", "sftp", "backup",
	"ci", "cd", "build", "deploy", "releases", "artifacts",
	"git", "svn", "repo", "registry", "harbor",
	"logs", "monitoring", "metrics", "status", "health",
	"debug", "trace", "profile", "admin-panel", "phpmyadmin",
	// Auth critical
	"auth", "oauth", "sso", "token", "jwt", "identity", "accounts",
}

// Extended subdomains for -all mode
var ExtendedSubdomains = []string{
	"www", "mail", "api", "admin", "dev", "staging", "test", "beta",
	"app", "portal", "secure", "vpn", "remote", "login", "dashboard",
	"cms", "blog", "shop", "store", "support", "help", "docs",
	"cdn", "static", "assets", "media", "images", "img", "files",
	"ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
	"mx", "mx1", "mx2", "smtp", "pop", "pop3", "imap", "webmail",
	"ftp", "sftp", "ssh", "git", "gitlab", "github", "svn", "hg",
	"jenkins", "ci", "cd", "build", "deploy", "docker", "k8s", "kubernetes",
	"db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
	"elasticsearch", "kibana", "grafana", "prometheus", "influx",
	"api-v1", "api-v2", "api-v3", "v1", "v2", "v3", "graphql", "rest",
	"internal", "intranet", "extranet", "corp", "corporate", "private",
	"hr", "finance", "sales", "marketing", "engineering", "legal",
	"dev1", "dev2", "dev3", "stage", "stage1", "stage2", "uat", "qa", "prod",
	"www1", "www2", "www3", "web", "web1", "web2",
	"mobile", "m", "ios", "android", "tablet",
	"old", "new", "legacy", "archive", "backup", "bak",
	"sandbox", "demo", "preview", "temp", "tmp",
	"auth", "oauth", "sso", "identity", "id", "accounts",
	"pay", "payment", "payments", "billing", "invoice",
	"search", "solr", "sphinx", "lucene",
	"chat", "im", "irc", "slack", "teams",
	"video", "stream", "live", "rtmp", "hls",
	"news", "press", "pr", "media", "brand",
	"jobs", "careers", "hiring", "recruit",
	"events", "calendar", "schedule", "booking",
	"forum", "community", "social", "connect",
	"wiki", "kb", "knowledge", "faq",
	"track", "tracking", "analytics", "stats", "metrics",
	"s3", "aws", "azure", "gcp", "cloud",
	"vault", "secrets", "config", "settings",
	"proxy", "gateway", "lb", "loadbalancer",
	"cache", "memcached", "varnish",
	"queue", "mq", "rabbitmq", "kafka", "activemq",
	"crm", "erp", "sap", "salesforce",
	"mail1", "mail2", "email", "newsletter",
	"origin", "edge", "node", "cluster",
}

// NewSubdomainScanner creates a new scanner
func NewSubdomainScanner(workers int, timeout time.Duration) *SubdomainScanner {
	return &SubdomainScanner{
		Workers: workers,
		Timeout: timeout,
		Results: make([]SubdomainResult, 0),
	}
}

// Scan enumerates subdomains for a domain
func (ss *SubdomainScanner) Scan(domain string, subdomains []string) []SubdomainResult {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, ss.Workers)
	total := len(subdomains)

	for i, sub := range subdomains {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(subdomain string, idx int) {
			defer wg.Done()
			defer func() { <-semaphore }()

			fullDomain := fmt.Sprintf("%s.%s", subdomain, domain)
			result := ss.checkSubdomain(fullDomain)

			if result.Live {
				ss.mu.Lock()
				ss.Results = append(ss.Results, result)
				ss.mu.Unlock()

				if ss.OnResult != nil {
					ss.OnResult(result)
				}
			}

			if ss.OnProgress != nil {
				ss.OnProgress(idx+1, total)
			}
		}(sub, i)
	}

	wg.Wait()
	return ss.Results
}

// checkSubdomain verifies if a subdomain exists and is live
func (ss *SubdomainScanner) checkSubdomain(domain string) SubdomainResult {
	result := SubdomainResult{
		Subdomain: domain,
		Live:      false,
	}

	// DNS resolution check
	ips, err := net.LookupHost(domain)
	if err != nil || len(ips) == 0 {
		return result
	}
	result.IP = ips[0]

	// HTTP client
	client := &http.Client{
		Timeout: ss.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Try HTTPS first
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, domain)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		result.Live = true
		result.Scheme = scheme
		result.StatusCode = resp.StatusCode
		return result
	}

	// Even without HTTP, if DNS resolves, report it
	if result.IP != "" {
		result.Live = true
	}

	return result
}

// GetLiveHosts returns just the hostnames that are live
func (ss *SubdomainScanner) GetLiveHosts() []string {
	hosts := make([]string, 0, len(ss.Results))
	for _, r := range ss.Results {
		if r.Live {
			hosts = append(hosts, r.Subdomain)
		}
	}
	return hosts
}
