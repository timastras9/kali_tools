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
	threads := flag.Int("t", 20, "Number of concurrent threads")
	timeout := flag.Int("timeout", 5, "HTTP timeout in seconds")
	subdomainFile := flag.String("subs", "", "Custom subdomain wordlist file")
	pathFile := flag.String("paths", "", "Custom path wordlist file")
	outputFile := flag.String("o", "", "Output file for results")
	allMode := flag.Bool("all", false, "Run comprehensive scan with extended wordlists")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: go run . <domain> [options]")
		fmt.Println("       go run . nsicorp.org -t 50 -o results.csv")
		fmt.Println("       go run . nsicorp.org -all")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	domain := args[0]

	// Clean domain input
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")

	fmt.Printf("\n[*] Target: %s\n", domain)
	fmt.Printf("[*] Threads: %d\n", *threads)
	fmt.Printf("[*] Timeout: %ds\n", *timeout)
	if *allMode {
		fmt.Println("[*] Mode: Comprehensive (-all)")
	}
	fmt.Println()

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

	// Load wordlists based on mode
	var subdomains, paths []string
	if *allMode {
		subdomains = loadWordlist(*subdomainFile, getExtendedSubdomains())
		paths = loadWordlist(*pathFile, getExtendedPaths())
	} else {
		subdomains = loadWordlist(*subdomainFile, getDefaultSubdomains())
		paths = loadWordlist(*pathFile, getDefaultPaths())
	}

	// Scan subdomains
	fmt.Printf("[+] Scanning %d subdomains...\n", len(subdomains))
	scanSubdomains(domain, subdomains, *threads, client, &results, &resultsMu)

	// Scan paths on main domain
	fmt.Printf("\n[+] Scanning %d paths...\n", len(paths))
	scanPaths(domain, paths, *threads, client, &results, &resultsMu)

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

func getExtendedSubdomains() []string {
	base := getDefaultSubdomains()
	extended := []string{
		"acc", "acceptance", "accounts", "ad", "adm", "ads", "alpha", "analytics",
		"android", "api1", "api2", "api3", "apis", "apollo", "archive", "assets",
		"auth", "auto", "autodiscover", "aws", "backend", "backup", "backup1",
		"billing", "board", "books", "broker", "build", "builder", "business",
		"calendar", "careers", "cart", "catalog", "cdn1", "cdn2", "chat", "checkout",
		"ci", "citrix", "client", "clients", "code", "community", "conf", "config",
		"connect", "console", "contact", "content", "corp", "corporate", "cpanel",
		"crm", "cron", "css", "customer", "customers", "cvs", "data", "database",
		"demo1", "demo2", "deploy", "desktop", "dev1", "dev2", "dev3", "developer",
		"developers", "development", "devops", "direct", "director", "directory",
		"dl", "dns3", "doc", "docker", "documents", "download", "downloads",
		"drupal", "e", "echo", "edge", "edit", "editor", "edu", "elastic", "email",
		"employee", "engineering", "enterprise", "erp", "events", "exchange",
		"export", "external", "extranet", "facebook", "feed", "feeds", "file",
		"fileserver", "finance", "firewall", "forms", "forum", "ftp1", "ftp2",
		"ftps", "g", "game", "games", "gateway", "gis", "github", "go", "google",
		"gov", "graphql", "group", "groups", "guest", "guide", "health", "helpdesk",
		"hg", "hidden", "hiring", "history", "hn", "hosted", "hosting", "hr",
		"hub", "i", "id", "identity", "image", "imap", "import", "index", "inside",
		"install", "int", "integration", "investor", "investors", "invoice", "ios",
		"ip", "ips", "ipv4", "ipv6", "ir", "it", "java", "jenkins", "jira", "job",
		"jobs", "join", "joomla", "journal", "js", "jump", "kb", "kerberos", "key",
		"kubernetes", "l", "lab1", "lab2", "landing", "ldap", "legacy", "legal",
		"library", "link", "links", "linux", "list", "lists", "live", "lms", "load",
		"local", "localhost", "log", "logger", "logging", "logs", "lync", "m",
		"magento", "mailbox", "mailer", "mailgate", "mailing", "main", "maintenance",
		"manage", "management", "manager", "map", "maps", "marketing", "master",
		"mc", "mdm", "meet", "meeting", "member", "members", "memcache", "memcached",
		"mercury", "message", "messages", "metrics", "microsoft", "mirror", "mk",
		"ml", "mms", "mobi", "mobile", "mongodb", "monitor", "monitoring", "moodle",
		"mq", "ms", "mssql", "mta", "mtest", "music", "mx3", "my", "mysql1", "mysql2",
		"n", "nagios", "nas", "nat", "net", "netscaler", "network", "newsite",
		"nexus", "nginx", "node", "notes", "notify", "ns", "ns3", "ns4", "ntp",
		"o", "oa", "oauth", "office", "office365", "ok", "old", "olm", "online",
		"op", "open", "openid", "ops", "oracle", "order", "orders", "origin",
		"oss", "outlook", "owa", "p", "page", "pages", "panel", "partner", "partners",
		"pay", "payment", "payments", "pbx", "pc", "pentest", "people", "photo",
		"photos", "php", "pilot", "piwik", "platform", "play", "plesk", "pma",
		"podcast", "poll", "polls", "pool", "pop3", "portal2", "post", "postgres",
		"power", "ppc", "pre", "preprod", "press", "preview", "print", "printer",
		"priv", "pro", "prod1", "prod2", "product", "products", "profile", "promo",
		"proxy2", "pt", "pub", "public", "push", "q", "qa", "qa1", "qa2", "qr",
		"queue", "quote", "r", "rabbitmq", "radio", "radius", "ras", "raw", "rdp",
		"rds", "read", "realm", "receiver", "record", "recruit", "recruiting",
		"redis", "redirect", "ref", "reference", "reg", "registration", "relay",
		"release", "releases", "remote2", "report", "reports", "research", "rest",
		"review", "reviews", "ris", "root", "router", "rs", "rss", "rtmp", "s",
		"s1", "s2", "s3", "safe", "sales", "salt", "sam", "sample", "samples",
		"sandbox", "sap", "saml", "sc", "scan", "scheduler", "schema", "school",
		"scm", "script", "scripts", "sdc", "sdn", "sec", "secret", "secrets",
		"secureftp", "sem", "send", "seo", "server1", "server2", "service",
		"services", "sf", "sftp", "share", "sharepoint", "shell", "shop",
		"shopping", "sign", "signin", "signup", "sim", "site", "sites", "skype",
		"slack", "sms", "snapshot", "social", "software", "solr", "sonar",
		"source", "sp", "spam", "sphinx", "splunk", "spoc", "sql", "sqlserver",
		"srs", "ss", "ssa", "ssd", "sso", "stag", "stage1", "stage2", "staging2",
		"start", "stat", "static1", "static2", "statistics", "stg", "stock",
		"storage", "stream", "streaming", "student", "students", "submit", "sub",
		"subversion", "sun", "sup", "super", "supply", "support2", "survey",
		"surveys", "sv", "svn", "sw", "swift", "switch", "sys", "sysadmin",
		"t", "talk", "task", "tasks", "tc", "team", "teams", "tech", "telnet",
		"temp", "templates", "terminal", "test1", "test2", "test3", "testing",
		"text", "tftp", "ticket", "tickets", "time", "tmp", "tools", "top",
		"tour", "trac", "track", "tracker", "tracking", "trade", "traffic",
		"train", "training", "transfer", "translate", "travel", "ts", "tunnel",
		"tv", "tw", "u", "uat", "udp", "uk", "union", "unix", "up", "update",
		"updates", "upgrade", "upload", "uploader", "ups", "us", "user", "users",
		"util", "utilities", "utility", "v", "v1", "v2", "v3", "vault", "vb",
		"vc", "vdi", "vendor", "vhost", "video", "videos", "view", "virtual",
		"virus", "vista", "vm", "vmail", "vmware", "vod", "voip", "vps", "vpn1",
		"vpn2", "vr", "vs", "w", "w1", "w2", "w3", "waf", "warehouse", "wc",
		"weather", "web1", "web2", "web3", "webapi", "webapp", "webcam", "webcast",
		"webconf", "weblog", "webmaster", "webmin", "webproxy", "webserver",
		"webservice", "webservices", "website", "welcome", "wh", "whois", "wifi",
		"win", "windows", "wm", "wms", "word", "wordpress", "work", "workday",
		"workflow", "world", "wp", "write", "ws", "wss", "ww", "ww1", "ww2", "ww3",
		"www4", "www5", "www6", "x", "xen", "xmpp", "xml", "y", "yahoo", "z",
		"zabbix", "zen", "zendesk", "zimbra", "zone", "zoom",
	}
	return append(base, extended...)
}

func getExtendedPaths() []string {
	base := getDefaultPaths()
	extended := []string{
		"/api/v1", "/api/v2", "/api/v3", "/api/users", "/api/auth", "/api/login",
		"/api/config", "/api/health", "/api/status", "/api/docs", "/api/swagger",
		"/v1", "/v2", "/v3", "/graphql", "/graphiql", "/playground",
		"/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
		"/openapi", "/openapi.json", "/openapi.yaml", "/redoc",
		"/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
		"/metrics", "/prometheus", "/health", "/healthz", "/ready", "/readiness",
		"/ping", "/pong", "/version", "/info.php", "/phpinfo.php", "/test.php",
		"/wp-json", "/wp-json/wp/v2/users", "/xmlrpc.php", "/wp-cron.php",
		"/feed", "/atom", "/rss.xml", "/atom.xml", "/feed.xml",
		"/humans.txt", "/security.txt", "/.well-known/security.txt",
		"/favicon.ico", "/apple-touch-icon.png", "/manifest.json",
		"/.svn", "/.svn/entries", "/.hg", "/.bzr", "/CVS",
		"/.git/config", "/.git/HEAD", "/.gitattributes",
		"/.env.local", "/.env.development", "/.env.production", "/.env.backup",
		"/config.php", "/config.inc.php", "/configuration.php", "/settings.php",
		"/config.yml", "/config.yaml", "/config.json", "/config.xml",
		"/database.yml", "/database.php", "/db.php", "/db.sql",
		"/backup.sql", "/backup.zip", "/backup.tar.gz", "/backup.tar",
		"/dump.sql", "/database.sql", "/data.sql", "/export.sql",
		"/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
		"/yarn.lock", "/Gemfile", "/Gemfile.lock", "/requirements.txt",
		"/Pipfile", "/Pipfile.lock", "/go.mod", "/go.sum", "/Cargo.toml",
		"/Makefile", "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
		"/Vagrantfile", "/Procfile", "/build.xml", "/pom.xml", "/build.gradle",
		"/.travis.yml", "/.gitlab-ci.yml", "/Jenkinsfile", "/.circleci/config.yml",
		"/node_modules", "/vendor", "/bower_components",
		"/elmah.axd", "/trace.axd", "/webresource.axd",
		"/server-info", "/server-status", "/jmx-console", "/manager/html",
		"/solr/admin", "/jenkins", "/hudson", "/bamboo", "/teamcity",
		"/nagios", "/cacti", "/munin", "/awstats", "/webalizer",
		"/console", "/admin.php", "/admin.html", "/admin/login", "/administrator/login",
		"/manager", "/manager/status", "/management", "/manage.py",
		"/ckeditor", "/fckeditor", "/tinymce", "/elfinder",
		"/filemanager", "/files", "/upload.php", "/uploader",
		"/.DS_Store", "/Thumbs.db", "/.idea", "/.vscode",
		"/debug/default/view", "/debug/pprof", "/server/status",
		"/cgi-bin/test-cgi", "/cgi-bin/printenv",
		"/soap", "/wsdl", "/asmx", "/svc",
		"/rest", "/restapi", "/api-docs", "/apidocs",
		"/oauth", "/oauth2", "/oauth/token", "/oauth/authorize",
		"/saml", "/sso", "/cas", "/adfs",
		"/.aws/credentials", "/.docker/config.json", "/.kube/config",
		"/id_rsa", "/id_rsa.pub", "/authorized_keys",
		"/error_log", "/error.log", "/debug.log", "/access.log", "/access_log",
	}
	return append(base, extended...)
}
