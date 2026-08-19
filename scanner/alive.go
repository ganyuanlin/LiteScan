package scanner

import (
	"LiteScan/report"
	"LiteScan/utils"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

func ScanAliveHosts(targets []string, threadCount int) []report.AliveHost {
	results := make(chan report.AliveHost, len(targets))
	sem := make(chan struct{}, threadCount)

	var wg sync.WaitGroup

	for _, ip := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-sem }()

			host := report.AliveHost{
				IP:     targetIP,
				Online: false,
			}

			if pingCheck(targetIP) {
				host.Online = true
				host.OpenPorts = checkPorts(targetIP, []int{135, 139, 445})
				host.MAC = getMACByArp(targetIP)
				results <- host
				return
			}

			openPorts := checkPorts(targetIP, []int{135, 445})
			if len(openPorts) > 0 {
				host.Online = true
				host.OpenPorts = openPorts
				host.MAC = getMACByArp(targetIP)
				results <- host
				return
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var aliveHosts []report.AliveHost
	for host := range results {
		if host.Online {
			aliveHosts = append(aliveHosts, host)
		}
	}

	return aliveHosts
}

func pingCheck(ip string) bool {
	cmd := exec.Command("ping", "-n", "1", "-w", "1000", ip)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	err := cmd.Run()
	return err == nil
}

func checkPorts(ip string, ports []int) []int {
	var openPorts []int
	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, port)
		}
	}
	return openPorts
}

func getMACByArp(ip string) string {
	output, err := utils.RunCmd("arp", "-a", ip)
	if err != nil {
		return ""
	}

	macRegex := regexp.MustCompile(`([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})`)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, ip) {
			matches := macRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				return matches[1]
			}
		}
	}
	return ""
}