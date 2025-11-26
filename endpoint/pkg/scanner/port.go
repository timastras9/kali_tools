package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// PortResult holds the result of a port scan
type PortResult struct {
	Host    string
	Port    int
	Open    bool
	Service string
	Banner  string
	Risk    string // CRITICAL, HIGH, MEDIUM, LOW, INFO
}

// Top 50 high-risk ports
var Top50Ports = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 993, 995, 1433, 1521, 2375, 2376, 3306,
	3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017, 11211,
	6443, 10250, 2377, 5000, 8000, 9000, 3000, 4443, 8888,
	9090, 5601, 15672, 5672, 1883, 8883, 6666, 7001, 9001,
	50000, 50070, 50075,
}

// Top 100 ports (includes Top50 + more)
var Top100Ports = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 993, 995, 1433, 1521, 2375, 2376, 3306,
	3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017, 11211,
	6443, 10250, 2377, 5000, 8000, 9000, 3000, 4443, 8888,
	9090, 5601, 15672, 5672, 1883, 8883, 6666, 7001, 9001,
	50000, 50070, 50075,
	// Additional ports
	20, 69, 79, 81, 82, 83, 84, 85, 88, 89,
	102, 104, 106, 113, 119, 123, 137, 138, 161, 162,
	177, 179, 199, 389, 427, 465, 500, 512, 513, 514,
	515, 520, 548, 554, 587, 631, 636, 646, 873, 902,
	912, 990, 1080, 1099, 1194, 1352, 1434, 1500, 1723, 1801,
}

// Service signatures for banner detection
var serviceSignatures = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	111:   "RPC",
	135:   "MSRPC",
	139:   "NetBIOS",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1521:  "Oracle",
	2375:  "Docker",
	2376:  "Docker-TLS",
	2377:  "Docker-Swarm",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	6443:  "K8s-API",
	8080:  "HTTP-Proxy",
	8443:  "HTTPS-Alt",
	9200:  "Elasticsearch",
	10250: "Kubelet",
	11211: "Memcached",
	27017: "MongoDB",
}

// Risk levels for services
var serviceRisk = map[string]string{
	"Docker":        "CRITICAL",
	"Docker-TLS":    "HIGH",
	"Docker-Swarm":  "CRITICAL",
	"Redis":         "CRITICAL",
	"MongoDB":       "CRITICAL",
	"Memcached":     "CRITICAL",
	"Elasticsearch": "HIGH",
	"K8s-API":       "CRITICAL",
	"Kubelet":       "CRITICAL",
	"MySQL":         "HIGH",
	"PostgreSQL":    "HIGH",
	"MSSQL":         "HIGH",
	"FTP":           "MEDIUM",
	"Telnet":        "HIGH",
	"SMB":           "HIGH",
	"RDP":           "MEDIUM",
	"VNC":           "MEDIUM",
	"SSH":           "LOW",
	"HTTP":          "INFO",
	"HTTPS":         "INFO",
}

// PortScanner handles async port scanning
type PortScanner struct {
	Workers    int
	Timeout    time.Duration
	Results    []PortResult
	mu         sync.Mutex
	OnResult   func(PortResult) // Callback for live results
	OnProgress func(current, total int)
}

// NewPortScanner creates a new scanner
func NewPortScanner(workers int, timeout time.Duration) *PortScanner {
	return &PortScanner{
		Workers: workers,
		Timeout: timeout,
		Results: make([]PortResult, 0),
	}
}

// ScanHost scans all specified ports on a host
func (ps *PortScanner) ScanHost(host string, ports []int) []PortResult {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, ps.Workers)
	total := len(ports)

	for i, port := range ports {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(p int, idx int) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result := ps.scanPort(host, p)
			if result.Open {
				ps.mu.Lock()
				ps.Results = append(ps.Results, result)
				ps.mu.Unlock()

				if ps.OnResult != nil {
					ps.OnResult(result)
				}
			}

			if ps.OnProgress != nil {
				ps.OnProgress(idx+1, total)
			}
		}(port, i)
	}

	wg.Wait()
	return ps.Results
}

// scanPort checks a single port
func (ps *PortScanner) scanPort(host string, port int) PortResult {
	result := PortResult{
		Host: host,
		Port: port,
		Open: false,
		Risk: "INFO",
	}

	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, ps.Timeout)
	if err != nil {
		return result
	}
	defer conn.Close()

	result.Open = true

	// Identify service
	if service, ok := serviceSignatures[port]; ok {
		result.Service = service
		if risk, ok := serviceRisk[service]; ok {
			result.Risk = risk
		}
	} else {
		result.Service = "Unknown"
	}

	// Try to grab banner
	result.Banner = ps.grabBanner(conn, port)

	return result
}

// grabBanner attempts to read a service banner
func (ps *PortScanner) grabBanner(conn net.Conn, port int) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// For HTTP services, send a request
	if port == 80 || port == 8080 || port == 8000 || port == 8888 || port == 3000 || port == 5000 {
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	banner := string(buffer[:n])
	// Truncate long banners
	if len(banner) > 100 {
		banner = banner[:100] + "..."
	}
	return banner
}

// ScanMultipleHosts scans ports on multiple hosts concurrently
func (ps *PortScanner) ScanMultipleHosts(hosts []string, ports []int) []PortResult {
	var wg sync.WaitGroup
	hostSem := make(chan struct{}, 10) // Max 10 hosts at once

	for _, host := range hosts {
		wg.Add(1)
		hostSem <- struct{}{}

		go func(h string) {
			defer wg.Done()
			defer func() { <-hostSem }()
			ps.ScanHost(h, ports)
		}(host)
	}

	wg.Wait()
	return ps.Results
}
