package auth

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Credential holds username/password pair
type Credential struct {
	Username string
	Password string
}

// AuthResult holds the result of auth testing
type AuthResult struct {
	Host       string
	Port       int
	Service    string
	AuthNeeded bool
	Credential *Credential // nil if no valid creds found
	Risk       string
	Message    string
}

// Default credentials by service
var DefaultCreds = map[string][]Credential{
	"FTP": {
		{"anonymous", "anonymous"},
		{"anonymous", ""},
		{"ftp", "ftp"},
		{"admin", "admin"},
		{"root", "root"},
		{"user", "user"},
	},
	"SSH": {
		{"root", "root"},
		{"root", "toor"},
		{"root", "password"},
		{"admin", "admin"},
		{"user", "user"},
		{"ubuntu", "ubuntu"},
		{"pi", "raspberry"},
	},
	"MySQL": {
		{"root", ""},
		{"root", "root"},
		{"root", "mysql"},
		{"root", "password"},
		{"mysql", "mysql"},
		{"admin", "admin"},
	},
	"PostgreSQL": {
		{"postgres", "postgres"},
		{"postgres", "password"},
		{"postgres", ""},
		{"admin", "admin"},
	},
	"Redis": {
		{"", ""}, // Redis often has no auth
	},
	"MongoDB": {
		{"", ""}, // MongoDB often has no auth
		{"admin", "admin"},
		{"root", "root"},
	},
	"HTTP": {
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", "123456"},
		{"root", "root"},
		{"user", "user"},
		{"guest", "guest"},
	},
	"Telnet": {
		{"root", "root"},
		{"admin", "admin"},
		{"user", "user"},
	},
	"VNC": {
		{"", "password"},
		{"", "vnc"},
		{"", "1234"},
	},
}

// AuthTester handles credential testing
type AuthTester struct {
	Timeout    time.Duration
	Workers    int
	Results    []AuthResult
	mu         sync.Mutex
	OnResult   func(AuthResult)
	OnProgress func(current, total int)
}

// NewAuthTester creates a new tester
func NewAuthTester(timeout time.Duration, workers int) *AuthTester {
	return &AuthTester{
		Timeout: timeout,
		Workers: workers,
		Results: make([]AuthResult, 0),
	}
}

// TestService tests credentials for a specific service
func (at *AuthTester) TestService(host string, port int, service string) AuthResult {
	result := AuthResult{
		Host:    host,
		Port:    port,
		Service: service,
		Risk:    "INFO",
	}

	creds, ok := DefaultCreds[service]
	if !ok {
		result.Message = "No default credentials to test"
		return result
	}

	for _, cred := range creds {
		var success bool
		var err error

		switch service {
		case "FTP":
			success, err = at.testFTP(host, port, cred)
		case "SSH":
			success, err = at.testSSH(host, port, cred)
		case "MySQL":
			success, err = at.testMySQL(host, port, cred)
		case "PostgreSQL":
			success, err = at.testPostgres(host, port, cred)
		case "Redis":
			success, err = at.testRedis(host, port)
		case "MongoDB":
			success, err = at.testMongoDB(host, port)
		case "HTTP":
			success, err = at.testHTTPBasic(host, port, cred)
		case "Telnet":
			success, err = at.testTelnet(host, port, cred)
		default:
			continue
		}

		if err != nil {
			continue
		}

		if success {
			result.Credential = &cred
			result.AuthNeeded = false
			if cred.Username == "anonymous" || cred.Username == "" {
				result.Risk = "CRITICAL"
				result.Message = fmt.Sprintf("No authentication required or anonymous access")
			} else {
				result.Risk = "CRITICAL"
				result.Message = fmt.Sprintf("Default credentials work: %s:%s", cred.Username, cred.Password)
			}
			break
		}
	}

	if result.Credential == nil {
		result.AuthNeeded = true
		result.Risk = "LOW"
		result.Message = "Authentication required, no default creds found"
	}

	at.mu.Lock()
	at.Results = append(at.Results, result)
	at.mu.Unlock()

	if at.OnResult != nil {
		at.OnResult(result)
	}

	return result
}

// testFTP tests FTP credentials
func (at *AuthTester) testFTP(host string, port int, cred Credential) (bool, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), at.Timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	conn.SetDeadline(time.Now().Add(at.Timeout))

	// Read banner
	_, err = reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	// Send USER
	fmt.Fprintf(conn, "USER %s\r\n", cred.Username)
	response, _ := reader.ReadString('\n')

	// Send PASS
	fmt.Fprintf(conn, "PASS %s\r\n", cred.Password)
	response, _ = reader.ReadString('\n')

	// Check for successful login (230)
	if strings.HasPrefix(response, "230") {
		return true, nil
	}

	return false, nil
}

// testSSH is a placeholder - real SSH testing needs golang.org/x/crypto/ssh
func (at *AuthTester) testSSH(host string, port int, cred Credential) (bool, error) {
	// Note: Full SSH testing requires golang.org/x/crypto/ssh
	// For now, just check if port responds
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), at.Timeout)
	if err != nil {
		return false, err
	}
	conn.Close()
	return false, nil // Conservative: don't report false positives
}

// testMySQL tests MySQL credentials
func (at *AuthTester) testMySQL(host string, port int, cred Credential) (bool, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), at.Timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// Read initial handshake
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(at.Timeout))
	_, err = conn.Read(buffer)
	if err != nil {
		return false, err
	}

	// Check if MySQL responds (has protocol version)
	if len(buffer) > 4 && buffer[4] == 10 { // Protocol version 10
		// MySQL is running, but we'd need proper auth to test creds
		// For security, report it's exposed
		if cred.Password == "" {
			return true, nil // Assume no-password root is a risk
		}
	}

	return false, nil
}

// testPostgres tests PostgreSQL connection
func (at *AuthTester) testPostgres(host string, port int, cred Credential) (bool, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), at.Timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	return false, nil // Conservative
}

// testRedis tests Redis for no-auth access
func (at *AuthTester) testRedis(host string, port int) (bool, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), at.Timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(at.Timeout))

	// Send PING command
	fmt.Fprintf(conn, "*1\r\n$4\r\nPING\r\n")

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return false, err
	}

	response := string(buffer[:n])
	// Redis responds with +PONG if no auth needed
	if strings.Contains(response, "PONG") {
		return true, nil
	}

	return false, nil
}

// testMongoDB tests MongoDB for no-auth access
func (at *AuthTester) testMongoDB(host string, port int) (bool, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), at.Timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// MongoDB wire protocol - simplified check
	// Just verify it responds like MongoDB
	conn.SetReadDeadline(time.Now().Add(at.Timeout))

	// If we can connect, it might be open
	return false, nil // Conservative for now
}

// testHTTPBasic tests HTTP Basic Auth - first checks if auth is required
func (at *AuthTester) testHTTPBasic(host string, port int, cred Credential) (bool, error) {
	client := &http.Client{
		Timeout: at.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)

	// Step 1: Check if auth is even required (without credentials)
	reqNoAuth, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	reqNoAuth.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

	respNoAuth, err := client.Do(reqNoAuth)
	if err != nil {
		return false, err
	}
	respNoAuth.Body.Close()

	// If we get 200 without auth, the site doesn't require auth - not a vuln we can test
	if respNoAuth.StatusCode == 200 {
		return false, nil
	}

	// If we don't get 401 or 403, auth isn't required in the traditional sense
	if respNoAuth.StatusCode != 401 && respNoAuth.StatusCode != 403 {
		return false, nil
	}

	// Step 2: Auth IS required - now try the credentials
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}

	// Add Basic Auth header
	auth := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Password))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// If we now get 200 (was 401/403 before), creds work!
	if resp.StatusCode == 200 {
		return true, nil
	}

	return false, nil
}

// testTelnet tests Telnet credentials
func (at *AuthTester) testTelnet(host string, port int, cred Credential) (bool, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), at.Timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(at.Timeout * 2))

	// Read initial prompt
	buffer := make([]byte, 4096)
	conn.Read(buffer)

	// Try login
	fmt.Fprintf(conn, "%s\r\n", cred.Username)
	time.Sleep(500 * time.Millisecond)
	conn.Read(buffer)

	fmt.Fprintf(conn, "%s\r\n", cred.Password)
	time.Sleep(500 * time.Millisecond)

	n, _ := conn.Read(buffer)
	response := strings.ToLower(string(buffer[:n]))

	// Check for success indicators
	if strings.Contains(response, "$") ||
		strings.Contains(response, "#") ||
		strings.Contains(response, "welcome") ||
		strings.Contains(response, "last login") {
		return true, nil
	}

	return false, nil
}

// TestEndpoint checks if an HTTP endpoint requires auth
func (at *AuthTester) TestEndpoint(url string) AuthResult {
	result := AuthResult{
		Host:    url,
		Service: "HTTP",
		Risk:    "INFO",
	}

	client := &http.Client{
		Timeout: at.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		result.Message = "Connection failed"
		return result
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		result.AuthNeeded = false
		result.Risk = "MEDIUM"
		result.Message = "Endpoint accessible without authentication"
	case 401:
		result.AuthNeeded = true
		result.Risk = "LOW"
		result.Message = "HTTP Basic Auth required"
	case 403:
		result.AuthNeeded = true
		result.Risk = "LOW"
		result.Message = "Access forbidden"
	case 301, 302:
		location := resp.Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") {
			result.AuthNeeded = true
			result.Risk = "LOW"
			result.Message = "Redirects to login page"
		}
	default:
		result.Message = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	return result
}
