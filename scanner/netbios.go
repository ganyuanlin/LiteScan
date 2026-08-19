package scanner

import (
	"LiteScan/report"
	"LiteScan/utils"
	"regexp"
	"strings"
	"sync"
)

func ScanNetBIOS(targets []string, threadCount int) []report.NetBIOSInfo {
	results := make(chan report.NetBIOSInfo, len(targets))
	sem := make(chan struct{}, threadCount)

	var wg sync.WaitGroup

	for _, ip := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-sem }()

			info := queryNetBIOS(targetIP)
			results <- info
		}(ip)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var infos []report.NetBIOSInfo
	for info := range results {
		if info.Hostname != "" || info.Workgroup != "" {
			infos = append(infos, info)
		}
	}

	return infos
}

func queryNetBIOS(ip string) report.NetBIOSInfo {
	info := report.NetBIOSInfo{IP: ip}

	output, err := utils.RunCmd("nbtstat", "-A", ip)
	if err != nil || output == "" {
		return info
	}

	lines := strings.Split(output, "\n")
	nameRegex := regexp.MustCompile(`^\s*(\S+)\s+<(\w{2})>\s+-\s+(\S+)\s+(\w+)?`)

	var hostname, workgroup string
	var deviceType string

	for _, line := range lines {
		matches := nameRegex.FindStringSubmatch(line)
		if len(matches) < 4 {
			continue
		}

		name := matches[1]
		code := strings.ToUpper(matches[2])
		status := matches[4]

		switch code {
		case "00":
			if status == "GROUP" || strings.Contains(line, "GROUP") {
				workgroup = name
			} else {
				hostname = name
			}
		case "1C":
			deviceType = "域控制器"
			workgroup = name
		case "20":
			if hostname == "" {
				hostname = name
			}
		case "03":
			if strings.Contains(name, "__MSBROWSE__") {
				continue
			}
		}
	}

	if strings.Contains(output, "UNIQUE") && deviceType == "" {
		deviceType = "工作站"
	}
	if strings.Contains(output, "GROUP") && deviceType == "" {
		deviceType = "工作组/服务器"
	}

	info.Hostname = hostname
	info.Workgroup = workgroup
	info.DeviceType = deviceType
	info.Status = "已响应"

	return info
}