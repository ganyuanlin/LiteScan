package scanner

import (
	"LiteScan/report"
	"LiteScan/utils"
	"fmt"
	"net"
	"strings"
	"time"
)

type ProbeResult struct {
	IP       string
	Alive    bool
	Ports    []int
	MAC      string
	NetBIOS  *report.NetBIOSInfo
	SMB      *report.SMBHostInfo
}

func ProbeIP(ip string) *ProbeResult {
	result := &ProbeResult{IP: ip}

	fmt.Printf("  [*] 探测 %s ...\n", ip)

	if pingCheck(ip) {
		result.Alive = true
	} else {
		openPorts := checkPorts(ip, []int{135, 139, 445})
		if len(openPorts) > 0 {
			result.Alive = true
		}
	}

	if !result.Alive {
		fmt.Printf("  [-] %s 不存活\n", ip)
		return result
	}

	result.Ports = checkPorts(ip, []int{135, 139, 445, 80, 443, 3389, 8080})
	result.MAC = getMACByArp(ip)

	fmt.Printf("  [+] %s 存活 | 开放端口: %v\n", ip, result.Ports)

	nbInfo := queryNetBIOS(ip)
	if nbInfo.Hostname != "" || nbInfo.Workgroup != "" {
		result.NetBIOS = &nbInfo
		fmt.Printf("  [+] NetBIOS: 主机=%s 工作组/域=%s 类型=%s\n",
			nbInfo.Hostname, nbInfo.Workgroup, nbInfo.DeviceType)
	}

	smbInfo := querySMB(ip)
	if smbInfo.SMBEnabled {
		result.SMB = &smbInfo
		fmt.Printf("  [+] SMB: OS=%s 共享=%v 匿名访问=%v\n",
			smbInfo.OSVersion, smbInfo.Shares, smbInfo.AnonymousAccess)
	}

	return result
}

func ProbeCIDR(cidr string, threadCount int) []*ProbeResult {
	ips, err := utils.ParseTarget(cidr)
	if err != nil {
		fmt.Printf("  [!] 解析目标失败: %v\n", err)
		return nil
	}
	fmt.Printf("  [+] 解析目标: %d 个IP\n", len(ips))

	aliveHosts := ScanAliveHosts(ips, threadCount)

	var results []*ProbeResult
	aliveIPs := make([]string, 0, len(aliveHosts))

	for _, h := range aliveHosts {
		pr := &ProbeResult{
			IP:    h.IP,
			Alive: true,
			Ports: h.OpenPorts,
			MAC:   h.MAC,
		}
		results = append(results, pr)
		aliveIPs = append(aliveIPs, h.IP)
	}

	if len(aliveIPs) == 0 {
		return results
	}

	fmt.Printf("  [+] 存活主机: %d 台，开始深度探测...\n", len(aliveIPs))

	netbiosResults := ScanNetBIOS(aliveIPs, threadCount)
	nbMap := make(map[string]*report.NetBIOSInfo)
	for i := range netbiosResults {
		nbMap[netbiosResults[i].IP] = &netbiosResults[i]
	}

	smbResults := ScanSMB(aliveIPs, threadCount)
	smbMap := make(map[string]*report.SMBHostInfo)
	for i := range smbResults {
		smbMap[smbResults[i].IP] = &smbResults[i]
	}

	for _, pr := range results {
		if nb, ok := nbMap[pr.IP]; ok {
			pr.NetBIOS = nb
		}
		if smb, ok := smbMap[pr.IP]; ok {
			pr.SMB = smb
		}
	}

	return results
}

func QuickPortScan(ip string, ports []int) []int {
	var open []int
	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond)
		if err == nil {
			conn.Close()
			open = append(open, port)
		}
	}
	return open
}

func IsIP(s string) bool {
	return net.ParseIP(s) != nil
}

func IsCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func NormalizeInput(input string) string {
	input = strings.TrimSpace(input)
	if strings.Contains(input, "/") {
		return input
	}
	if net.ParseIP(input) != nil {
		return input
	}
	parts := strings.Split(input, ".")
	if len(parts) == 4 {
		return input + "/32"
	}
	return input
}