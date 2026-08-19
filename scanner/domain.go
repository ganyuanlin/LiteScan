package scanner

import (
	"LiteScan/report"
	"LiteScan/utils"
	"regexp"
	"strings"
)

func CollectDomainInfo() (*report.DomainInfo, error) {
	info := &report.DomainInfo{}

	info.DomainName = getDomainNameFromDC()
	info.DomainCtrlIP = getDomainControllerIP()
	info.DomainCtrlName = getDomainControllerName()
	info.DomainHosts = getDomainHosts()
	info.DomainUsers = getDomainUsers()
	info.DomainGPO = getDomainGPO()
	info.DomainPriv = getDomainPriv()
	info.DomainLogin = getDomainLoginStatus()

	return info, nil
}

func getDomainNameFromDC() string {
	output, err := utils.RunWmic("computersystem get domain /value")
	if err != nil {
		return ""
	}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Domain=") {
			return strings.TrimPrefix(line, "Domain=")
		}
	}
	return ""
}

func getDomainControllerIP() string {
	output, err := utils.RunCmd("nltest", "/dsgetdc:")
	if err != nil {
		return ""
	}

	ipRegex := regexp.MustCompile(`\\(\d+\.\d+\.\d+\.\d+)`)
	matches := ipRegex.FindStringSubmatch(output)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func getDomainControllerName() string {
	output, err := utils.RunCmd("nltest", "/dsgetdc:")
	if err != nil {
		return ""
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "DC") || strings.Contains(line, "域控") {
			parts := strings.Split(line, "\\")
			if len(parts) >= 3 {
				name := strings.TrimSpace(parts[len(parts)-1])
				if name != "" && !strings.Contains(name, ".") {
					return name
				}
			}
		}
	}

	return ""
}

func getDomainHosts() []string {
	output, err := utils.RunCmd("net", "view", "/domain")
	if err != nil {
		return nil
	}

	var hosts []string
	lines := strings.Split(output, "\n")
	hostRegex := regexp.MustCompile(`^\\\\(\S+)`)

	for _, line := range lines {
		matches := hostRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			hosts = append(hosts, matches[1])
		}
	}

	return hosts
}

func getDomainUsers() []string {
	output, err := utils.RunCmd("net", "user", "/domain")
	if err != nil {
		return nil
	}

	var users []string
	lines := strings.Split(output, "\n")
	inList := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "---") {
			inList = true
			continue
		}
		if inList && trimmed != "" && !strings.Contains(trimmed, "命令") &&
			!strings.Contains(trimmed, "The command") {
			parts := strings.Fields(trimmed)
			users = append(users, parts...)
		}
	}

	return users
}

func getDomainGPO() []string {
	output, err := utils.RunCmd("gpresult", "/r", "/scope", "computer")
	if err != nil {
		return nil
	}

	var gpos []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "组策略对象") || strings.Contains(trimmed, "Group Policy Object") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				gpo := strings.TrimSpace(parts[1])
				if gpo != "" {
					gpos = append(gpos, gpo)
				}
			}
		}
	}

	return gpos
}

func getDomainPriv() string {
	output, err := utils.RunCmd("whoami", "/priv")
	if err != nil {
		return "未知"
	}

	if strings.Contains(output, "SeDebugPrivilege") {
		return "高权限(SeDebugPrivilege)"
	}
	if strings.Contains(output, "SeTcbPrivilege") {
		return "系统权限(SeTcbPrivilege)"
	}

	return "普通域用户权限"
}

func getDomainLoginStatus() string {
	output, err := utils.RunCmd("whoami")
	if err != nil {
		return "未登录"
	}

	if strings.Contains(output, "\\") {
		return "已登录: " + output
	}

	return "本地登录"
}