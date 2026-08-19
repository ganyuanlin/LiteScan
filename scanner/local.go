package scanner

import (
	"LiteScan/report"
	"LiteScan/utils"
	"fmt"
	"regexp"
	"strings"
)

func CollectLocalInfo() (*report.LocalInfo, error) {
	info := &report.LocalInfo{}

	info.Hostname = getHostname()
	info.OSVersion = getOSVersion()
	info.CurrentUser = getCurrentUser()
	info.IsDomainEnv = checkDomainEnv()

	if info.IsDomainEnv {
		info.DomainName = getDomainName()
		info.Workgroup = info.DomainName
	} else {
		info.Workgroup = getWorkgroup()
		info.DomainName = ""
	}

	info.Adapters = getNetworkAdapters()
	info.OpenPorts = getOpenPorts()
	info.AdminUsers = getAdminUsers()
	info.RouteTable = getRouteTable()
	info.SystemPatches = getSystemPatches()
	info.PasswordPolicy = getPasswordPolicy()
	info.FirewallStatus = getFirewallStatus()
	info.SharedFolders = getSharedFolders()
	info.UserSessions = getUserSessions()
	info.StartupItems = getStartupItems()
	info.ScheduledTasks = getScheduledTasks()
	info.ProcessList = getProcessList()

	return info, nil
}

func getHostname() string {
	output, err := utils.RunCmd("hostname")
	if err != nil {
		return ""
	}
	return output
}

func getOSVersion() string {
	output, err := utils.RunWmic("os get caption /value")
	if err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Caption=") {
				return strings.TrimPrefix(line, "Caption=")
			}
		}
	}

	output, err = utils.RunCmd("net", "config", "workstation")
	if err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			line = strings.TrimRight(line, "\r")
			if strings.Contains(line, "软件版本") || strings.Contains(line, "Software version") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					return strings.Join(fields[1:], " ")
				}
			}
		}
	}

	return ""
}

func getCurrentUser() string {
	output, err := utils.RunCmd("whoami")
	if err != nil {
		return ""
	}
	return output
}

func checkDomainEnv() bool {
	output, err := utils.RunWmic("computersystem get partofdomain /value")
	if err == nil {
		if strings.Contains(strings.ToLower(output), "true") {
			return true
		}
	}

	output, err = utils.RunCmd("net", "config", "workstation")
	if err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "workstation domain") || strings.Contains(lower, "工作站域") {
				if strings.Contains(line, " : ") || strings.Contains(line, ":") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						domain := strings.TrimSpace(parts[1])
						if domain != "" && !strings.Contains(lower, "workgroup") && !strings.Contains(lower, "工作组") {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

func getDomainName() string {
	output, err := utils.RunWmic("computersystem get domain /value")
	if err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Domain=") {
				return strings.TrimPrefix(line, "Domain=")
			}
		}
	}

	output, err = utils.RunCmd("net", "config", "workstation")
	if err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Logon domain") || strings.Contains(line, "登录域") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}

	return ""
}

func getWorkgroup() string {
	output, err := utils.RunCmd("net", "config", "workstation")
	if err != nil {
		return ""
	}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.Contains(line, "工作站域") || strings.Contains(line, "Workstation domain") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[len(fields)-1]
			}
		}
	}
	return ""
}

func getNetworkAdapters() []report.Adapter {
	output, err := utils.RunCmd("ipconfig", "/all")
	if err != nil {
		return nil
	}

	var adapters []report.Adapter
	lines := strings.Split(output, "\n")

	var current *report.Adapter
	ipv4Regex := regexp.MustCompile(`IPv4\s*[^:]*:\s*(\S+)`)
	ipRegexEn := regexp.MustCompile(`IPv4 Address[^:]*:\s*(\S+)`)
	maskRegex := regexp.MustCompile(`子网掩码[^:]*:\s*(\S+)`)
	maskRegexEn := regexp.MustCompile(`Subnet Mask[^:]*:\s*(\S+)`)
	gwRegex := regexp.MustCompile(`默认网关[^:]*:\s*(\S+)`)
	gwRegexEn := regexp.MustCompile(`Default Gateway[^:]*:\s*(\S+)`)
	gwRegex4 := regexp.MustCompile(`默认网关[^:]*:\s*(\d+\.\d+\.\d+\.\d+)`)
	gwRegex4En := regexp.MustCompile(`Default Gateway[^:]*:\s*(\d+\.\d+\.\d+\.\d+)`)
	dnsRegex := regexp.MustCompile(`DNS\s*服务器[^:]*:\s*(\S+)`)
	dnsRegexEn := regexp.MustCompile(`DNS Servers[^:]*:\s*(\S+)`)
	dnsRegex4 := regexp.MustCompile(`DNS\s*服务器[^:]*:\s*(\d+\.\d+\.\d+\.\d+)`)
	dnsRegex4En := regexp.MustCompile(`DNS Servers[^:]*:\s*(\d+\.\d+\.\d+\.\d+)`)
	macRegex := regexp.MustCompile(`物理地址[^:]*:\s*(\S+)`)
	macRegexEn := regexp.MustCompile(`Physical Address[^:]*:\s*(\S+)`)
	adapterNameRegex := regexp.MustCompile(`^.+适配器\s+(.+):$`)
	adapterNameRegexEn := regexp.MustCompile(`^.+adapter\s+(.+):$`)

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			continue
		}

		isIndented := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")

		if !isIndented {
			matches := adapterNameRegex.FindStringSubmatch(trimmed)
			if len(matches) <= 1 {
				matches = adapterNameRegexEn.FindStringSubmatch(trimmed)
			}
			if len(matches) > 1 {
				name := matches[1]
				if current != nil && current.IPAddress != "" {
					adapters = append(adapters, *current)
				}
				current = &report.Adapter{Name: name}
				continue
			}
		}

		if current == nil {
			continue
		}

		if matches := ipv4Regex.FindStringSubmatch(trimmed); len(matches) > 1 {
			ip := matches[1]
			ip = strings.TrimSuffix(ip, "(Preferred)")
			ip = strings.TrimSuffix(ip, "(首选)")
			ip = strings.TrimSpace(strings.Split(ip, "(")[0])
			current.IPAddress = ip
		} else if matches := ipRegexEn.FindStringSubmatch(trimmed); len(matches) > 1 {
			ip := matches[1]
			ip = strings.TrimSuffix(ip, "(Preferred)")
			ip = strings.TrimSpace(strings.Split(ip, "(")[0])
			current.IPAddress = ip
		}

		if matches := maskRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
			current.SubnetMask = matches[1]
		} else if matches := maskRegexEn.FindStringSubmatch(trimmed); len(matches) > 1 {
			current.SubnetMask = matches[1]
		}

		if matches := gwRegex4.FindStringSubmatch(trimmed); len(matches) > 1 {
			current.Gateway = matches[1]
		} else if matches := gwRegex4En.FindStringSubmatch(trimmed); len(matches) > 1 {
			current.Gateway = matches[1]
		} else if current.Gateway == "" {
			if matches := gwRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
				current.Gateway = matches[1]
			} else if matches := gwRegexEn.FindStringSubmatch(trimmed); len(matches) > 1 {
				current.Gateway = matches[1]
			}
		}

		if matches := dnsRegex4.FindStringSubmatch(trimmed); len(matches) > 1 {
			if current.DNS == "" {
				current.DNS = matches[1]
			}
		} else if matches := dnsRegex4En.FindStringSubmatch(trimmed); len(matches) > 1 {
			if current.DNS == "" {
				current.DNS = matches[1]
			}
		} else if current.DNS == "" {
			if matches := dnsRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
				current.DNS = matches[1]
			} else if matches := dnsRegexEn.FindStringSubmatch(trimmed); len(matches) > 1 {
				current.DNS = matches[1]
			}
		}

		if matches := macRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
			current.MACAddress = matches[1]
		} else if matches := macRegexEn.FindStringSubmatch(trimmed); len(matches) > 1 {
			current.MACAddress = matches[1]
		}
	}

	if current != nil && current.IPAddress != "" {
		adapters = append(adapters, *current)
	}

	return adapters
}

func getOpenPorts() []report.PortInfo {
	output, err := utils.RunCmd("netstat", "-ano", "-p", "TCP")
	if err != nil {
		return nil
	}

	var ports []report.PortInfo
	lines := strings.Split(output, "\n")
	listenRegex := regexp.MustCompile(`^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING`)

	for _, line := range lines {
		matches := listenRegex.FindStringSubmatch(line)
		if len(matches) == 3 {
			port := 0
			fmt.Sscanf(matches[2], "%d", &port)
			if port > 0 {
				ports = append(ports, report.PortInfo{
					Protocol: "TCP",
					Port:     port,
					State:    "LISTENING",
				})
			}
		}
	}

	return ports
}

func getAdminUsers() []string {
	output, err := utils.RunCmd("net", "localgroup", "administrators")
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
			users = append(users, trimmed)
		}
	}

	return users
}

func getRouteTable() []string {
	output, err := utils.RunCmd("route", "print")
	if err != nil {
		return nil
	}

	var routes []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			routes = append(routes, line)
		}
	}
	return routes
}

func getSystemPatches() []string {
	output, err := utils.RunWmic("qfe get hotfixid /value")
	if err != nil {
		return nil
	}

	var patches []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "HotFixID=") {
			patch := strings.TrimPrefix(line, "HotFixID=")
			if patch != "" {
				patches = append(patches, patch)
			}
		}
	}
	return patches
}

func getPasswordPolicy() *report.PasswordPolicy {
	policy := &report.PasswordPolicy{}

	output, err := utils.RunCmd("net", "accounts")
	if err != nil || output == "" {
		return nil
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		lower := strings.ToLower(trimmed)

		if strings.Contains(lower, "minimum password age") || strings.Contains(lower, "密码最短存留期") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 1 {
				policy.MinPasswordAge = parts[len(parts)-1]
			}
		} else if strings.Contains(lower, "maximum password age") || strings.Contains(lower, "密码最大存留期") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 1 {
				policy.MaxPasswordAge = parts[len(parts)-1]
			}
		} else if strings.Contains(lower, "minimum password length") || strings.Contains(lower, "密码最小长度") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 1 {
				policy.MinPasswordLen = parts[len(parts)-1]
			}
		} else if strings.Contains(lower, "password history length") || strings.Contains(lower, "保持密码历史记录的长度") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 1 {
				policy.PasswordHistory = parts[len(parts)-1]
			}
		} else if strings.Contains(lower, "lockout threshold") || strings.Contains(lower, "锁定阈值") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 1 {
				policy.LockoutThreshold = parts[len(parts)-1]
			}
		} else if strings.Contains(lower, "lockout duration") || strings.Contains(lower, "锁定持续时间") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 1 {
				policy.LockoutDuration = parts[len(parts)-1]
			}
		} else if strings.Contains(lower, "complexity") || strings.Contains(lower, "复杂性") {
			if strings.Contains(lower, "enabled") || strings.Contains(lower, "已启用") || strings.Contains(lower, "是") {
				policy.ComplexityEnabled = "已启用"
			} else {
				policy.ComplexityEnabled = "未启用"
			}
		}
	}

	return policy
}

func getFirewallStatus() string {
	output, err := utils.RunCmd("netsh", "advfirewall", "show", "currentprofile", "state")
	if err != nil || output == "" {
		output, err = utils.RunCmd("netsh", "firewall", "show", "opmode")
		if err != nil || output == "" {
			return "未知"
		}
	}

	if strings.Contains(output, "ON") || strings.Contains(output, "启用") || strings.Contains(output, "开启") {
		return "已启用"
	}
	if strings.Contains(output, "OFF") || strings.Contains(output, "关闭") || strings.Contains(output, "禁用") {
		return "已关闭"
	}

	return "未知"
}

func getSharedFolders() []string {
	output, err := utils.RunCmd("net", "share")
	if err != nil || output == "" {
		return nil
	}

	var shares []string
	lines := strings.Split(output, "\n")
	inShareList := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "---") {
			inShareList = true
			continue
		}
		if inShareList && trimmed != "" {
			fields := strings.Fields(trimmed)
			if len(fields) >= 1 {
				name := fields[0]
				if name != "The" && name != "命令" && !strings.HasPrefix(name, "---") {
					shares = append(shares, name)
				}
			}
		}
	}

	return shares
}

func getUserSessions() []string {
	output, err := utils.RunCmd("query", "session")
	if err != nil || output == "" {
		return nil
	}

	var sessions []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.Contains(trimmed, "SESSIONNAME") && !strings.Contains(trimmed, "会话名称") {
			sessions = append(sessions, trimmed)
		}
	}

	return sessions
}

func getStartupItems() []string {
	output, err := utils.RunWmic("startup list brief")
	if err != nil || output == "" {
		return nil
	}

	var items []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.Contains(trimmed, "Caption") && !strings.Contains(trimmed, "命令") {
			items = append(items, trimmed)
		}
	}

	return items
}

func getScheduledTasks() []string {
	output, err := utils.RunCmd("schtasks", "/query", "/fo", "list", "/nh")
	if err != nil || output == "" {
		return nil
	}

	var tasks []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "任务名:") || strings.HasPrefix(trimmed, "TaskName:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				taskName := strings.TrimSpace(parts[1])
				if taskName != "" {
					tasks = append(tasks, taskName)
				}
			}
		}
	}

	return tasks
}

func getProcessList() []report.ProcessInfo {
	output, err := utils.RunWmic("process get processid,name,workingsetsize /format:csv")
	if err != nil || output == "" {
		return nil
	}

	var processes []report.ProcessInfo
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		fields := strings.Split(line, ",")
		if len(fields) < 4 {
			continue
		}

		pid := 0
		name := ""
		memBytes := int64(0)

		for i, f := range fields {
			f = strings.TrimSpace(f)
			switch strings.ToLower(fields[0]) {
			case "node":
				if i == 1 && f != "Name" {
					name = f
				}
				if i == 2 && f != "ProcessId" {
					fmt.Sscanf(f, "%d", &pid)
				}
				if i == 3 && f != "WorkingSetSize" {
					fmt.Sscanf(f, "%d", &memBytes)
				}
			default:
				if i == 1 {
					name = f
				}
				if i == 2 {
					fmt.Sscanf(f, "%d", &pid)
				}
				if i == 3 {
					fmt.Sscanf(f, "%d", &memBytes)
				}
			}
		}

		if pid > 0 && name != "" {
			processes = append(processes, report.ProcessInfo{
				PID:   pid,
				Name:  name,
				MemMB: int(memBytes / 1024 / 1024),
			})
		}
	}

	if len(processes) > 50 {
		processes = processes[:50]
	}

	return processes
}