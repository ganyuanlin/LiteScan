package scanner

import (
	"LiteScan/report"
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var commonServicePorts = map[int]string{
	21:   "ftp",
	22:   "ssh",
	23:   "telnet",
	25:   "smtp",
	53:   "dns",
	80:   "http",
	110:  "pop3",
	135:  "msrpc",
	139:  "netbios-ssn",
	143:  "imap",
	443:  "https",
	445:  "microsoft-ds",
	465:  "smtps",
	587:  "submission",
	993:  "imaps",
	995:  "pop3s",
	1433: "mssql",
	1521: "oracle",
	3306: "mysql",
	3389: "rdp",
	5432: "postgresql",
	5900: "vnc",
	6379: "redis",
	8080: "http-proxy",
	8443: "https-alt",
	27017: "mongodb",
}

func DetectServices(targets []string, threadCount int) []report.ServiceDetectResult {
	results := make(chan report.ServiceDetectResult, len(targets)*len(commonServicePorts))
	sem := make(chan struct{}, threadCount)
	var wg sync.WaitGroup

	for _, target := range targets {
		for port := range commonServicePorts {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip string, port int) {
				defer wg.Done()
				defer func() { <-sem }()

				result := detectService(ip, port)
				if result != nil {
					results <- *result
				}
			}(target, port)
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var detectResults []report.ServiceDetectResult
	for r := range results {
		detectResults = append(detectResults, r)
	}

	return detectResults
}

func detectService(ip string, port int) *report.ServiceDetectResult {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	service := commonServicePorts[port]
	banner := ""

	if port == 80 || port == 8080 || port == 443 || port == 8443 {
		banner = grabHTTPBanner(conn, port)
	} else if port == 21 {
		banner = grabFTPBanner(conn)
	} else if port == 22 {
		banner = grabSSHBanner(conn)
	} else if port == 3306 {
		banner = grabMySQLBanner(conn)
	} else if port == 1433 {
		banner = grabMSSQLBanner(conn)
	} else if port == 5432 {
		banner = grabPostgreSQLBanner(conn)
	} else if port == 6379 {
		banner = grabRedisBanner(conn)
	} else if port == 5900 {
		banner = grabVNCBanner(conn)
	}

	info := service
	if banner != "" {
		info = banner
	}

	return &report.ServiceDetectResult{
		IP:     ip,
		Type:   service,
		Port:   port,
		Info:   info,
		Banner: banner,
	}
}

func grabHTTPBanner(conn net.Conn, port int) string {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return scheme + " - " + strings.TrimSpace(strings.TrimPrefix(line, "server:"))
		}
		if strings.HasPrefix(strings.ToLower(line), "www-authenticate:") {
			return scheme + " - Basic Auth"
		}
	}
	return scheme
}

func grabFTPBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return "FTP"
}

func grabSSHBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	if n > 0 {
		return strings.TrimSpace(string(buf[:n]))
	}
	return "SSH"
}

func grabMySQLBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	if n > 0 {
		return "MySQL " + strings.TrimSpace(string(buf[:n]))
	}
	return "MySQL"
}

func grabMSSQLBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	if n > 0 {
		return "MSSQL - " + strings.TrimSpace(string(buf[:n]))
	}
	return "MSSQL"
}

func grabPostgreSQLBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	if n > 0 {
		return "PostgreSQL - " + strings.TrimSpace(string(buf[:n]))
	}
	return "PostgreSQL"
}

func grabRedisBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	if n > 0 {
		return "Redis - " + strings.TrimSpace(string(buf[:n]))
	}
	return "Redis"
}

func grabVNCBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	if n > 0 {
		return "VNC - " + strings.TrimSpace(string(buf[:n]))
	}
	return "VNC"
}

func ScanServices(targets []string, customPorts string, threadCount int) []report.ServiceDetectResult {
	portList := parsePorts(customPorts)
	results := make(chan report.ServiceDetectResult, len(targets)*len(portList))
	sem := make(chan struct{}, threadCount)
	var wg sync.WaitGroup

	for _, target := range targets {
		for _, port := range portList {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip string, port int) {
				defer wg.Done()
				defer func() { <-sem }()

				result := detectService(ip, port)
				if result != nil {
					results <- *result
				}
			}(target, port)
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var detectResults []report.ServiceDetectResult
	for r := range results {
		detectResults = append(detectResults, r)
	}

	return detectResults
}

func parsePorts(portStr string) []int {
	var ports []int
	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				var start, end int
				fmt.Sscanf(rangeParts[0], "%d", &start)
				fmt.Sscanf(rangeParts[1], "%d", &end)
				for p := start; p <= end; p++ {
					if p > 0 && p <= 65535 {
						ports = append(ports, p)
					}
				}
			}
		} else {
			var port int
			fmt.Sscanf(part, "%d", &port)
			if port > 0 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}
	return ports
}