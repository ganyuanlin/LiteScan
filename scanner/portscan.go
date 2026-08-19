package scanner

import (
	"LiteScan/report"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var commonPorts = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	111:   "RPCBind",
	135:   "MSRPC",
	139:   "NetBIOS-SSN",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	465:   "SMTPS",
	587:   "SMTP-Submission",
	636:   "LDAPS",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1521:  "Oracle",
	1723:  "PPTP",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	5985:  "WinRM-HTTP",
	5986:  "WinRM-HTTPS",
	6379:  "Redis",
	6443:  "Kubernetes-API",
	8080:  "HTTP-Proxy",
	8443:  "HTTPS-Alt",
	8888:  "HTTP-Alt",
	9090:  "Web-Console",
	9200:  "Elasticsearch",
	11211: "Memcached",
	27017: "MongoDB",
}

var defaultScanPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
	465, 587, 636, 993, 995, 1433, 1521, 1723, 3306, 3389,
	5432, 5900, 5985, 5986, 6379, 8080, 8443, 8888, 9090,
	9200, 11211, 27017,
}

func ScanPorts(targets []string, threadCount int) []report.PortScanResult {
	results := make(chan report.PortScanResult, len(targets))
	sem := make(chan struct{}, threadCount)

	var wg sync.WaitGroup

	for _, ip := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := scanPortsSingle(targetIP, defaultScanPorts, 1500*time.Millisecond)
			results <- result
		}(ip)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var portResults []report.PortScanResult
	for r := range results {
		if len(r.Ports) > 0 {
			portResults = append(portResults, r)
		}
	}

	return portResults
}

func ScanCustomPorts(targets []string, ports []int, threadCount int) []report.PortScanResult {
	results := make(chan report.PortScanResult, len(targets))
	sem := make(chan struct{}, threadCount)

	var wg sync.WaitGroup

	for _, ip := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := scanPortsSingle(targetIP, ports, 1500*time.Millisecond)
			results <- result
		}(ip)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var portResults []report.PortScanResult
	for r := range results {
		portResults = append(portResults, r)
	}

	return portResults
}

func scanPortsSingle(ip string, ports []int, timeout time.Duration) report.PortScanResult {
	result := report.PortScanResult{IP: ip}

	portSem := make(chan struct{}, 50)
	var portWg sync.WaitGroup
	var mu sync.Mutex

	for _, port := range ports {
		portWg.Add(1)
		portSem <- struct{}{}
		go func(p int) {
			defer portWg.Done()
			defer func() { <-portSem }()

			addr := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				return
			}

			sp := report.ServicePort{
				Port:  p,
				State: "open",
			}

			if service, ok := commonPorts[p]; ok {
				sp.Service = service
			} else {
				sp.Service = "unknown"
			}

			banner := grabBanner(conn, p)
			if banner != "" {
				sp.Banner = banner
			}

			conn.Close()

			mu.Lock()
			result.Ports = append(result.Ports, sp)
			mu.Unlock()
		}(port)
	}

	portWg.Wait()

	return result
}

func grabBanner(conn net.Conn, port int) string {
	bannerPorts := map[int]bool{21: true, 22: true, 25: true, 80: true, 110: true, 143: true, 443: true}

	if !bannerPorts[port] {
		return ""
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	if port == 80 || port == 443 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", conn.RemoteAddr().String())
	}

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n > 0 {
		banner := strings.TrimSpace(string(buf[:n]))
		if len(banner) > 100 {
			banner = banner[:100]
		}
		return banner
	}

	return ""
}

func ParsePortRange(s string) ([]int, error) {
	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("无效端口: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("无效端口: %s", rangeParts[1])
			}
			if start > end {
				start, end = end, start
			}
			if end-start > 1000 {
				return nil, fmt.Errorf("端口范围过大（最多1000个端口）")
			}
			for p := start; p <= end; p++ {
				if p < 1 || p > 65535 {
					continue
				}
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("无效端口: %s", part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("端口超出范围: %d", p)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("未指定有效端口")
	}

	return ports, nil
}

func GetDefaultScanPorts() []int {
	return defaultScanPorts
}