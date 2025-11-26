package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL    string
	Status int
	Type   string // "subdomain" or "path"
}

func main() {
	domain := flag.String("d", "", "Target domain (e.g., nsicorp.org)")
	threads := flag.Int("t", 20, "Number of concurrent threads")
	timeout := flag.Int("timeout", 5, "HTTP timeout in seconds")
	subdomainFile := flag.String("subs", "", "Custom subdomain wordlist file")
	pathFile := flag.String("paths", "", "Custom path wordlist file")
	outputFile := flag.String("o", "", "Output file for results")
	flag.Parse()

	if *domain == "" {
		fmt.Println("Usage: endpoint -d <domain>")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Clean domain input
	*domain = strings.TrimPrefix(*domain, "http://")
	*domain = strings.TrimPrefix(*domain, "https://")
	*domain = strings.TrimSuffix(*domain, "/")

	fmt.Printf("\n[*] Target: %s\n", *domain)
	fmt.Printf("[*] Threads: %d\n", *threads)
	fmt.Printf("[*] Timeout: %ds\n\n", *timeout)

	results := make([]Result, 0)
	var resultsMu sync.Mutex

	// HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Load wordlists
	subdomains := loadWordlist(*subdomainFile, getDefaultSubdomains())
	paths := loadWordlist(*pathFile, getDefaultPaths())

	// Scan subdomains
	fmt.Println("[+] Scanning subdomains...")
	scanSubdomains(*domain, subdomains, *threads, client, &results, &resultsMu)

	// Scan paths on main domain
	fmt.Println("\n[+] Scanning paths...")
	scanPaths(*domain, paths, *threads, client, &results, &resultsMu)

	// Print summary
	fmt.Printf("\n[+] Scan complete! Found %d endpoints\n", len(results))

	// Save results if output file specified
	if *outputFile != "" {
		saveResults(*outputFile, results)
		fmt.Printf("[+] Results saved to %s\n", *outputFile)
	}
}

func loadWordlist(filepath string, defaults []string) []string {
	if filepath == "" {
		return defaults
	}

	file, err := os.Open(filepath)
	if err != nil {
		fmt.Printf("[!] Could not open %s, using defaults\n", filepath)
		return defaults
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	if len(words) == 0 {
		return defaults
	}
	return words
}

func scanSubdomains(domain string, subdomains []string, threads int, client *http.Client, results *[]Result, mu *sync.Mutex) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, threads)

	for _, sub := range subdomains {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(subdomain string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			fullDomain := fmt.Sprintf("%s.%s", subdomain, domain)

			// First check if DNS resolves
			_, err := net.LookupHost(fullDomain)
			if err != nil {
				return
			}

			// Try HTTPS first, then HTTP
			for _, scheme := range []string{"https", "http"} {
				url := fmt.Sprintf("%s://%s", scheme, fullDomain)
				resp, err := client.Get(url)
				if err != nil {
					continue
				}
				resp.Body.Close()

				result := Result{
					URL:    url,
					Status: resp.StatusCode,
					Type:   "subdomain",
				}

				mu.Lock()
				*results = append(*results, result)
				mu.Unlock()

				fmt.Printf("  [FOUND] %s [%d]\n", url, resp.StatusCode)
				break
			}
		}(sub)
	}

	wg.Wait()
}

func scanPaths(domain string, paths []string, threads int, client *http.Client, results *[]Result, mu *sync.Mutex) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, threads)

	// Determine base URL
	baseURL := ""
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, domain)
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			baseURL = url
			break
		}
	}

	if baseURL == "" {
		fmt.Println("[!] Could not connect to main domain")
		return
	}

	for _, path := range paths {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(p string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}

			url := baseURL + p
			resp, err := client.Get(url)
			if err != nil {
				return
			}
			resp.Body.Close()

			// Filter out common "not found" responses
			if resp.StatusCode == 404 {
				return
			}

			result := Result{
				URL:    url,
				Status: resp.StatusCode,
				Type:   "path",
			}

			mu.Lock()
			*results = append(*results, result)
			mu.Unlock()

			fmt.Printf("  [FOUND] %s [%d]\n", url, resp.StatusCode)
		}(path)
	}

	wg.Wait()
}

func saveResults(filepath string, results []Result) {
	file, err := os.Create(filepath)
	if err != nil {
		fmt.Printf("[!] Could not create output file: %v\n", err)
		return
	}
	defer file.Close()

	for _, r := range results {
		fmt.Fprintf(file, "%s,%d,%s\n", r.URL, r.Status, r.Type)
	}
}

func getDefaultSubdomains() []string {
	return []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
		"dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "dev", "staging", "test",
		"admin", "administrator", "app", "apps", "beta", "blog", "cdn", "cloud",
		"cms", "cpanel", "dashboard", "db", "demo", "docs", "email", "files",
		"forum", "git", "gitlab", "help", "home", "host", "images", "img", "info",
		"internal", "intranet", "irc", "lab", "labs", "login", "manage", "media",
		"mobile", "monitor", "mysql", "new", "news", "old", "portal", "preview",
		"private", "prod", "production", "proxy", "remote", "repo", "resources",
		"search", "secure", "security", "server", "shop", "sip", "ssh", "ssl",
		"stage", "static", "stats", "status", "store", "support", "svn", "sync",
		"syslog", "system", "tools", "upload", "video", "videos", "vpn", "web",
		"webdisk", "wiki", "www1", "www2", "www3",
	}
}

func getDefaultPaths() []string {
	return []string{
		"/", "/about", "/admin", "/administrator", "/api", "/app", "/assets",
		"/backup", "/blog", "/cache", "/cgi-bin", "/config", "/console",
		"/contact", "/css", "/dashboard", "/data", "/db", "/debug", "/demo",
		"/dev", "/docs", "/download", "/downloads", "/error", "/errors",
		"/faq", "/files", "/fonts", "/forum", "/help", "/home", "/images",
		"/img", "/include", "/includes", "/index", "/info", "/js", "/lib",
		"/license", "/log", "/login", "/logout", "/logs", "/mail", "/media",
		"/members", "/misc", "/news", "/old", "/panel", "/php", "/phpinfo",
		"/phpmyadmin", "/plugins", "/portal", "/private", "/profile", "/public",
		"/readme", "/register", "/resources", "/robots.txt", "/rss", "/scripts",
		"/search", "/secure", "/security", "/server-status", "/services",
		"/settings", "/setup", "/signin", "/signup", "/sitemap", "/sitemap.xml",
		"/src", "/staff", "/static", "/stats", "/status", "/storage", "/store",
		"/support", "/system", "/temp", "/test", "/testing", "/tmp", "/tools",
		"/upload", "/uploads", "/user", "/users", "/vendor", "/video", "/videos",
		"/web", "/webmail", "/wp-admin", "/wp-content", "/wp-includes", "/wp-login.php",
		"/.env", "/.git", "/.gitignore", "/.htaccess", "/web.config", "/crossdomain.xml",
	}
}
