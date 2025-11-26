package scanner

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// PathResult holds discovered path info
type PathResult struct {
	URL        string
	Path       string
	StatusCode int
	Size       int64
	Risk       string
	Category   string
}

// Baseline holds the response characteristics of a non-existent path
type Baseline struct {
	StatusCode int
	Size       int64
	SizeRange  int64 // Allow +/- this much variance
}

// PathScanner handles async path discovery
type PathScanner struct {
	Workers    int
	Timeout    time.Duration
	Results    []PathResult
	mu         sync.Mutex
	OnResult   func(PathResult)
	OnProgress func(current, total int)
	UserAgents []string
	agentIdx   int
	Baseline   *Baseline
}

// Top 50 high-risk paths (for -top50)
var Top50Paths = []string{
	"/.env", "/.git/config", "/.git/HEAD", "/admin", "/wp-admin",
	"/phpmyadmin", "/api/config", "/debug", "/console", "/actuator",
	"/actuator/env", "/actuator/health", "/swagger", "/swagger-ui.html",
	"/graphql", "/graphiql", "/.aws/credentials", "/backup.sql",
	"/db.sql", "/dump.sql", "/config.php", "/wp-config.php",
	"/.htpasswd", "/.htaccess", "/server-status", "/server-info",
	"/phpinfo.php", "/.svn/entries", "/web.config", "/crossdomain.xml",
	"/api/v1/users", "/admin/login", "/.docker/config.json",
	"/Dockerfile", "/docker-compose.yml", "/id_rsa", "/.ssh/id_rsa",
	"/settings.py", "/database.yml", "/credentials.json", "/secrets",
	"/private", "/.npmrc", "/.pypirc", "/composer.json", "/package.json",
	"/Gemfile", "/requirements.txt", "/application.yml", "/bootstrap.yml",
	"/.kube/config",
}

// Top 100 paths (includes Top50 + more)
var Top100Paths = append(Top50Paths, []string{
	"/robots.txt", "/sitemap.xml", "/api", "/api/v1", "/api/v2",
	"/login", "/signin", "/signup", "/register", "/logout",
	"/dashboard", "/panel", "/manage", "/management", "/administrator",
	"/wp-login.php", "/wp-content", "/wp-includes", "/xmlrpc.php",
	"/cgi-bin", "/cgi-bin/test-cgi", "/test", "/testing", "/dev",
	"/backup", "/backups", "/bak", "/old", "/temp", "/tmp",
	"/upload", "/uploads", "/files", "/documents", "/download",
	"/static", "/assets", "/css", "/js", "/images", "/media",
	"/api-docs", "/swagger.json", "/openapi.json", "/redoc",
	"/metrics", "/prometheus", "/health", "/healthz", "/ready",
	"/status", "/info", "/version", "/.well-known/security.txt",
	"/security.txt", "/humans.txt", "/favicon.ico",
	"/jenkins", "/hudson", "/bamboo", "/teamcity", "/travis",
	"/sonarqube", "/grafana", "/kibana", "/elasticsearch",
	"/solr", "/admin.php", "/admin.html", "/index.php", "/index.html",
}...)

// Extended paths for -all mode
var ExtendedPaths = append(Top100Paths, []string{
	// Config files
	"/config.json", "/config.xml", "/config.yaml", "/config.yml",
	"/settings.json", "/settings.xml", "/settings.yaml",
	"/app.config", "/web.config", "/applicationContext.xml",
	"/.env.local", "/.env.development", "/.env.production", "/.env.backup",
	"/local.settings.json", "/appsettings.json", "/appsettings.Development.json",
	// Backup files
	"/backup.zip", "/backup.tar.gz", "/backup.tar", "/site.zip",
	"/www.zip", "/html.zip", "/public.zip", "/data.zip",
	"/database.zip", "/db.zip", "/sql.zip", "/mysql.zip",
	// Log files
	"/error.log", "/access.log", "/debug.log", "/app.log",
	"/error_log", "/access_log", "/logs/error.log", "/logs/access.log",
	// Framework specific
	"/vendor", "/node_modules", "/bower_components",
	"/laravel.log", "/storage/logs/laravel.log",
	"/var/log/apache2/error.log", "/var/log/nginx/error.log",
	// Admin panels
	"/cpanel", "/plesk", "/webmin", "/directadmin",
	"/manager/html", "/manager/status", "/jmx-console",
	"/web-console", "/admin-console", "/system-admin",
	// APIs
	"/api/admin", "/api/internal", "/api/private", "/api/debug",
	"/api/test", "/api/dev", "/api/swagger", "/api/docs",
	"/rest/api", "/services/api", "/ws/api",
	// Auth endpoints
	"/oauth", "/oauth2", "/oauth/token", "/oauth/authorize",
	"/saml", "/sso", "/cas", "/adfs", "/auth/login", "/auth/token",
	"/jwt", "/token", "/refresh", "/session",
	// GraphQL
	"/graphql/console", "/graphql/playground", "/graphql/schema",
	"/__graphql", "/altair", "/voyager",
	// Debug
	"/debug/vars", "/debug/pprof", "/debug/requests",
	"/trace", "/profiler", "/xdebug", "/_debugbar",
	"/elmah.axd", "/trace.axd", "/glimpse.axd",
	// Database
	"/phpmyadmin/", "/pma/", "/myadmin/", "/mysql/",
	"/pgadmin/", "/adminer/", "/adminer.php",
	"/mongodb/", "/mongo-express/", "/redis-commander/",
	// CMS
	"/wp-json", "/wp-json/wp/v2/users", "/wp-cron.php",
	"/joomla/administrator", "/drupal/admin",
	"/magento/admin", "/prestashop/admin",
	// Cloud/DevOps
	"/.circleci/config.yml", "/.github/workflows",
	"/.gitlab-ci.yml", "/Jenkinsfile", "/azure-pipelines.yml",
	"/terraform.tfstate", "/terraform.tfvars",
	"/ansible.cfg", "/playbook.yml", "/inventory",
	"/kubernetes.yml", "/k8s.yml", "/helm/values.yaml",
}...)

// Path risk levels
var pathRisk = map[string]string{
	"/.env":              "CRITICAL",
	"/.git/config":       "CRITICAL",
	"/.git/HEAD":         "CRITICAL",
	"/.aws/credentials":  "CRITICAL",
	"/id_rsa":            "CRITICAL",
	"/.ssh/id_rsa":       "CRITICAL",
	"/.kube/config":      "CRITICAL",
	"/backup.sql":        "CRITICAL",
	"/dump.sql":          "CRITICAL",
	"/db.sql":            "CRITICAL",
	"/credentials.json":  "CRITICAL",
	"/.docker/config.json": "CRITICAL",
	"/wp-config.php":     "HIGH",
	"/config.php":        "HIGH",
	"/database.yml":      "HIGH",
	"/settings.py":       "HIGH",
	"/phpinfo.php":       "HIGH",
	"/server-status":     "HIGH",
	"/actuator/env":      "HIGH",
	"/.htpasswd":         "HIGH",
	"/admin":             "MEDIUM",
	"/phpmyadmin":        "MEDIUM",
	"/swagger":           "MEDIUM",
	"/graphql":           "MEDIUM",
	"/debug":             "MEDIUM",
	"/console":           "MEDIUM",
}

// Path categories
var pathCategory = map[string]string{
	"/.env":          "Config",
	"/.git":          "Source",
	"/admin":         "Admin",
	"/api":           "API",
	"/swagger":       "API",
	"/graphql":       "API",
	"/backup":        "Backup",
	"/phpmyadmin":    "Database",
	"/actuator":      "Debug",
	"/debug":         "Debug",
	"/wp-":           "CMS",
	"/jenkins":       "CI/CD",
	"/login":         "Auth",
	"/oauth":         "Auth",
}

// Common User-Agents for rotation
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

// NewPathScanner creates a new scanner
func NewPathScanner(workers int, timeout time.Duration) *PathScanner {
	return &PathScanner{
		Workers:    workers,
		Timeout:    timeout,
		Results:    make([]PathResult, 0),
		UserAgents: userAgents,
	}
}

// EstablishBaseline checks a random non-existent path to detect catch-all routes
func (ps *PathScanner) EstablishBaseline(baseURL string) {
	// Generate random path that shouldn't exist
	randomPath := "/zxcvbnm98765432qwerty_nonexistent_path_test"

	result := ps.checkPath(baseURL, randomPath)

	// If we get a 200 response, this site has a catch-all
	if result.StatusCode == 200 {
		ps.Baseline = &Baseline{
			StatusCode: result.StatusCode,
			Size:       result.Size,
			SizeRange:  500, // Allow 500 bytes variance for dynamic content
		}
	}
}

// IsFalsePositive checks if a result matches the baseline (catch-all response)
func (ps *PathScanner) IsFalsePositive(result PathResult) bool {
	if ps.Baseline == nil {
		return false
	}

	// If status code matches baseline and size is within range, it's likely a false positive
	if result.StatusCode == ps.Baseline.StatusCode {
		sizeDiff := result.Size - ps.Baseline.Size
		if sizeDiff < 0 {
			sizeDiff = -sizeDiff
		}
		if sizeDiff <= ps.Baseline.SizeRange {
			return true
		}
	}

	return false
}

// Scan discovers paths on a host
func (ps *PathScanner) Scan(baseURL string, paths []string) []PathResult {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, ps.Workers)
	total := len(paths)

	// Ensure baseURL has scheme
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "https://" + baseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Establish baseline to detect catch-all routes
	ps.EstablishBaseline(baseURL)

	for i, path := range paths {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(p string, idx int) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result := ps.checkPath(baseURL, p)

			// Skip 404s, errors, and false positives (catch-all routes)
			if result.StatusCode == 404 || result.StatusCode == 0 {
				if ps.OnProgress != nil {
					ps.OnProgress(idx+1, total)
				}
				return
			}

			// Check if this is a false positive (matches catch-all baseline)
			if ps.IsFalsePositive(result) {
				if ps.OnProgress != nil {
					ps.OnProgress(idx+1, total)
				}
				return
			}

			ps.mu.Lock()
			ps.Results = append(ps.Results, result)
			ps.mu.Unlock()

			if ps.OnResult != nil {
				ps.OnResult(result)
			}

			if ps.OnProgress != nil {
				ps.OnProgress(idx+1, total)
			}
		}(path, i)
	}

	wg.Wait()
	return ps.Results
}

// checkPath checks if a path exists
func (ps *PathScanner) checkPath(baseURL, path string) PathResult {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	url := baseURL + path
	result := PathResult{
		URL:  url,
		Path: path,
		Risk: "INFO",
	}

	// Determine risk and category
	for prefix, risk := range pathRisk {
		if strings.HasPrefix(path, prefix) || path == prefix {
			result.Risk = risk
			break
		}
	}

	for prefix, cat := range pathCategory {
		if strings.Contains(path, prefix) {
			result.Category = cat
			break
		}
	}

	client := &http.Client{
		Timeout: ps.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return result
	}

	// Rotate User-Agent
	ps.mu.Lock()
	req.Header.Set("User-Agent", ps.UserAgents[ps.agentIdx%len(ps.UserAgents)])
	ps.agentIdx++
	ps.mu.Unlock()

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Get content length
	if resp.ContentLength > 0 {
		result.Size = resp.ContentLength
	} else {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		result.Size = int64(len(body))
	}

	return result
}

// ScanMultipleHosts scans paths on multiple hosts
func (ps *PathScanner) ScanMultipleHosts(hosts []string, paths []string) []PathResult {
	var wg sync.WaitGroup

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			ps.Scan(h, paths)
		}(host)
	}

	wg.Wait()
	return ps.Results
}

// GetCriticalFindings returns only critical/high risk findings
func (ps *PathScanner) GetCriticalFindings() []PathResult {
	var critical []PathResult
	for _, r := range ps.Results {
		if r.Risk == "CRITICAL" || r.Risk == "HIGH" {
			critical = append(critical, r)
		}
	}
	return critical
}
