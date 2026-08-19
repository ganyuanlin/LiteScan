package scanner

import (
	"LiteScan/report"
	"LiteScan/utils"
	"fmt"
	"regexp"
	"strings"
)

func ScanARPTable() []report.ARPHost {
	output, err := utils.RunCmd("arp", "-a")
	if err != nil || output == "" {
		return nil
	}

	var hosts []report.ARPHost
	lines := strings.Split(output, "\n")

	ipRegex := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
	macRegex := regexp.MustCompile(`([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})`)
	typeRegex := regexp.MustCompile(`(动态|静态|dynamic|Dynamic|Static|static)`)

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.Contains(trimmed, "接口") || strings.Contains(trimmed, "Interface") {
			continue
		}

		ipMatch := ipRegex.FindStringSubmatch(trimmed)
		macMatch := macRegex.FindStringSubmatch(trimmed)
		typeMatch := typeRegex.FindStringSubmatch(trimmed)

		if len(ipMatch) > 1 && len(macMatch) > 1 {
			mac := macMatch[1]
			if mac == "ff-ff-ff-ff-ff-ff" || mac == "FF-FF-FF-FF-FF-FF" {
				continue
			}

			hostType := ""
			if len(typeMatch) > 1 {
				hostType = typeMatch[1]
			}

			host := report.ARPHost{
				IP:   ipMatch[1],
				MAC:  mac,
				Type: hostType,
			}

			hosts = append(hosts, host)
		}
	}

	return hosts
}

func ScanARPForInterface() []report.ARPHost {
	output, err := utils.RunCmd("arp", "-a")
	if err != nil || output == "" {
		return nil
	}

	var hosts []report.ARPHost
	lines := strings.Split(output, "\n")

	ipRegex := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
	macRegex := regexp.MustCompile(`([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})`)
	typeRegex := regexp.MustCompile(`(动态|静态|dynamic|Dynamic|Static|static)`)

	currentInterface := ""

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "接口") || strings.Contains(trimmed, "Interface") {
			ifaceRegex := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
			ifaceMatch := ifaceRegex.FindStringSubmatch(trimmed)
			if len(ifaceMatch) > 1 {
				currentInterface = ifaceMatch[1]
			}
			continue
		}

		if trimmed == "" {
			continue
		}

		ipMatch := ipRegex.FindStringSubmatch(trimmed)
		macMatch := macRegex.FindStringSubmatch(trimmed)
		typeMatch := typeRegex.FindStringSubmatch(trimmed)

		if len(ipMatch) > 1 && len(macMatch) > 1 {
			mac := macMatch[1]
			if mac == "ff-ff-ff-ff-ff-ff" || mac == "FF-FF-FF-FF-FF-FF" {
				continue
			}

			hostType := ""
			if len(typeMatch) > 1 {
				hostType = typeMatch[1]
			}

			host := report.ARPHost{
				IP:        ipMatch[1],
				MAC:       mac,
				Type:      hostType,
				Interface: currentInterface,
			}

			hosts = append(hosts, host)
		}
	}

	return hosts
}

func PrintARPTable(hosts []report.ARPHost) {
	if len(hosts) == 0 {
		fmt.Println("  [!] ARP表为空")
		return
	}

	fmt.Printf("  [+] ARP表中发现 %d 条记录:\n", len(hosts))
	for i, h := range hosts {
		iface := ""
		if h.Interface != "" {
			iface = fmt.Sprintf(" (接口: %s)", h.Interface)
		}
		fmt.Printf("    %d. %s -> %s [%s]%s\n", i+1, h.IP, h.MAC, h.Type, iface)
	}
}