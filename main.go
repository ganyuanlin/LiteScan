package main

import (
	"LiteScan/report"
	"LiteScan/scanner"
	"LiteScan/utils"
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const version = "2.1.0"

func main() {
	var (
		target    string
		thread    int
		outDir    string
		local     bool
		domain    bool
		probe     bool
		showHelp  bool
		portScan  bool
		arpScan   bool
		vulnScan  bool
		ports     string
		timeout   int
		silent    bool
	)

	flag.StringVar(&target, "t", "", "扫描目标网段/IP，例: -t 192.168.1.0/24 或 -t 192.168.1.1")
	flag.StringVar(&target, "target", "", "扫描目标网段/IP（长格式）")
	flag.IntVar(&thread, "th", 20, "扫描线程数（默认20，最大50）")
	flag.IntVar(&thread, "thread", 20, "扫描线程数（长格式）")
	flag.StringVar(&outDir, "o", "", "报告输出路径")
	flag.StringVar(&outDir, "out", "", "报告输出路径（长格式）")
	flag.BoolVar(&local, "local", false, "仅采集本机信息")
	flag.BoolVar(&domain, "domain", false, "强制采集域信息")
	flag.BoolVar(&probe, "probe", false, "交互式探测模式（逐IP探测）")
	flag.BoolVar(&portScan, "ps", false, "启用端口扫描（常见端口）")
	flag.BoolVar(&portScan, "portscan", false, "启用端口扫描（长格式）")
	flag.BoolVar(&arpScan, "arp", false, "启用ARP表扫描")
	flag.BoolVar(&vulnScan, "vuln", false, "启用漏洞检测（MS17-010等）")
	flag.StringVar(&ports, "p", "", "自定义扫描端口，例: -p 80,443,3389 或 -p 1-1000")
	flag.StringVar(&ports, "ports", "", "自定义扫描端口（长格式）")
	flag.IntVar(&timeout, "timeout", 3, "连接超时秒数（默认3）")
	flag.BoolVar(&silent, "silent", false, "静默模式（减少输出）")
	flag.BoolVar(&showHelp, "h", false, "帮助文档")
	flag.BoolVar(&showHelp, "help", false, "帮助文档（长格式）")

	flag.Usage = printHelp
	flag.Parse()

	if showHelp {
		printHelp()
		return
	}

	if thread < 1 {
		thread = 1
	}
	if thread > 50 {
		thread = 50
	}

	if outDir == "" {
		outDir, _ = os.Getwd()
	}

	if !silent {
		printBanner()
	}

	startTime := time.Now()
	result := &report.ScanResult{
		StartTime:  startTime.Format("2006-01-02 15:04:05"),
		Target:     target,
		Threads:    thread,
		Version:    version,
		IsDomain:   false,
		LocalInfo:  nil,
		AliveHosts: nil,
		ARPHosts:   nil,
		NetBIOS:    nil,
		SMBInfo:    nil,
		PortScan:   nil,
		Services:   nil,
		WiFiInfo:   nil,
		LDAPInfo:   nil,
		VulnInfo:   nil,
		DomainInfo: nil,
		RiskStats:  nil,
	}

	if !silent {
		fmt.Println("[*] 开始信息收集...")
	}

	if probe {
		if !silent {
			fmt.Println("[*] 模式：交互式探测")
		}
		runInteractiveProbe(thread, outDir, silent)
		return
	} else if local {
		if !silent {
			fmt.Println("[*] 模式：仅本机信息采集")
		}
		collectLocalInfo(result, silent)
	} else if target != "" {
		if !silent {
			fmt.Printf("[*] 模式：扫描目标 %s\n", target)
		}
		collectLocalInfo(result, silent)
		scanTarget(target, thread, result, silent)
	} else {
		if !silent {
			fmt.Println("[*] 模式：默认模式（本机信息 + 自动网段探测）")
		}
		collectLocalInfo(result, silent)
		autoScan(thread, result, silent)
	}

	if domain || result.IsDomain {
		collectDomainInfo(result, silent)
	}

	if arpScan {
		collectARPInfo(result, silent)
	}

	if portScan || ports != "" {
		collectPortScanInfo(result, ports, thread, silent)
	}

	if vulnScan {
		collectVulnInfo(result, thread, silent)
	}

	result.EndTime = time.Now().Format("2006-01-02 15:04:05")
	result.Duration = time.Since(startTime).String()

	calcRiskStats(result)

	if !silent {
		fmt.Println("\n[*] 生成报告...")
	}
	report.GenerateReports(result, outDir)
	if !silent {
		fmt.Printf("[+] 报告已输出至: %s\n", outDir)
		fmt.Println("[+] scan_result.json + scan_report.html")
		fmt.Printf("[+] 共耗时: %s\n", result.Duration)
	}
}

func printBanner() {
	banner := `
  _      _   ___  ___       _
 | |    | |  |  \/  |      | |
 | |    | |  | .  . |  ___ | |_
 | |    | |  | |\/| | / _ \| __|
 | |____| |  | |  | || (_) | |_
 |______|_|  |_|  |_| \___/ \__|

 LiteScan - 内网轻量信息收集工具 v%s
 仅用于授权安全测试，禁止非法使用
========================================
`
	fmt.Printf(banner, version)
}

func printHelp() {
	printBanner()
	fmt.Println("用法: LiteScan.exe [选项]")
	fmt.Println()
	fmt.Println("扫描模式:")
	fmt.Println("  (默认)           本机信息 + 自动网段探测")
	fmt.Println("  -t / --target    指定扫描网段/IP")
	fmt.Println("                   例: -t 192.168.1.0/24")
	fmt.Println("                   例: -t 192.168.1.1,192.168.1.2")
	fmt.Println("  --local          仅采集本机信息")
	fmt.Println("  --probe          交互式探测模式（逐IP/CIDR输入）")
	fmt.Println()
	fmt.Println("扫描模块:")
	fmt.Println("  --arp            启用ARP表扫描")
	fmt.Println("  --ps / --portscan 启用端口扫描（常见端口）")
	fmt.Println("  -p / --ports     自定义端口扫描")
	fmt.Println("                   例: -p 80,443,3389")
	fmt.Println("                   例: -p 1-1000")
	fmt.Println("  --vuln           启用漏洞检测（MS17-010等）")
	fmt.Println("  --domain         强制采集域信息")
	fmt.Println()
	fmt.Println("扫描参数:")
	fmt.Println("  -th / --thread   设置扫描线程数 (默认20，最大50)")
	fmt.Println("  --timeout        连接超时秒数 (默认3)")
	fmt.Println("  --silent         静默模式（减少输出）")
	fmt.Println()
	fmt.Println("输出:")
	fmt.Println("  -o / --out       指定报告输出路径")
	fmt.Println("  -h / --help      显示帮助文档")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  LiteScan.exe                        默认模式")
	fmt.Println("  LiteScan.exe -t 192.168.1.0/24      扫描C段")
	fmt.Println("  LiteScan.exe -t 10.0.0.1 -th 30     指定线程")
	fmt.Println("  LiteScan.exe --local                仅本机信息")
	fmt.Println("  LiteScan.exe --domain               强制域信息")
	fmt.Println("  LiteScan.exe --probe                交互式探测")
	fmt.Println("  LiteScan.exe -t 192.168.1.0/24 --ps 端口扫描")
	fmt.Println("  LiteScan.exe -t 192.168.1.0/24 --vuln 漏洞检测")
	fmt.Println("  LiteScan.exe -t 192.168.1.0/24 --arp ARP扫描")
	fmt.Println("  LiteScan.exe -t 192.168.1.0/24 -p 80,443,445,3389")
	fmt.Println("  LiteScan.exe --probe -th 30         交互式探测(30线程)")
	fmt.Println("  LiteScan.exe -t 192.168.1.0/24 --silent 静默扫描")
}

func runInteractiveProbe(thread int, outDir string, silent bool) {
	reader := bufio.NewReader(os.Stdin)
	var allResults []*scanner.ProbeResult
	var allAliveHosts []report.AliveHost
	var allNetBIOS []report.NetBIOSInfo
	var allSMB []report.SMBHostInfo
	var allPortResults []report.PortScanResult
	var allVulnResults []report.VulnResult

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("  交互式探测模式")
	fmt.Println("  输入 IP 或 CIDR 进行探测")
	fmt.Println("  例: 192.168.1.1 | 192.168.1.0/24")
	fmt.Println("  输入 q 退出 | 输入 report 生成报告")
	fmt.Println("========================================")

	for {
		fmt.Print("\n[LiteScan] > ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			continue
		}

		if strings.EqualFold(input, "q") || strings.EqualFold(input, "quit") || strings.EqualFold(input, "exit") {
			fmt.Println("[*] 退出交互式探测")
			if len(allResults) > 0 {
				generateProbeReport(allResults, allAliveHosts, allNetBIOS, allSMB, allPortResults, allVulnResults, thread, outDir)
			}
			return
		}

		if strings.EqualFold(input, "report") {
			if len(allResults) == 0 && len(allPortResults) == 0 && len(allVulnResults) == 0 {
				fmt.Println("  [!] 暂无探测结果")
				continue
			}
			generateProbeReport(allResults, allAliveHosts, allNetBIOS, allSMB, allPortResults, allVulnResults, thread, outDir)
			continue
		}

		if strings.EqualFold(input, "clear") || strings.EqualFold(input, "reset") {
			allResults = nil
			allAliveHosts = nil
			allNetBIOS = nil
			allSMB = nil
			allPortResults = nil
			allVulnResults = nil
			fmt.Println("  [+] 已清空探测记录")
			continue
		}

		if strings.EqualFold(input, "list") || strings.EqualFold(input, "ls") {
			if len(allResults) == 0 {
				fmt.Println("  [!] 暂无探测记录")
				continue
			}
			fmt.Printf("  [+] 已探测 %d 个目标:\n", len(allResults))
			for i, r := range allResults {
				status := "不存活"
				if r.Alive {
					status = "存活"
				}
				fmt.Printf("    %d. %s [%s]\n", i+1, r.IP, status)
			}
			continue
		}

		if strings.EqualFold(input, "arp") {
			fmt.Println("\n[ARP表扫描]")
			arpHosts := scanner.ScanARPTable()
			scanner.PrintARPTable(arpHosts)
			continue
		}

		if strings.EqualFold(input, "help") {
			printProbeHelp()
			continue
		}

		if strings.HasPrefix(strings.ToLower(input), "ps ") || strings.HasPrefix(strings.ToLower(input), "portscan ") {
			portArg := strings.TrimSpace(input[3:])
			if strings.HasPrefix(strings.ToLower(input), "portscan ") {
				portArg = strings.TrimSpace(input[9:])
			}
			var scanPorts []int
			if portArg != "" {
				customPorts, err := scanner.ParsePortRange(portArg)
				if err != nil {
					fmt.Printf("  [!] 端口解析失败: %v\n", err)
					continue
				}
				scanPorts = customPorts
			} else {
				scanPorts = scanner.GetDefaultScanPorts()
			}

			if len(allAliveHosts) == 0 {
				fmt.Println("  [!] 暂无存活主机，请先探测目标")
				continue
			}

			aliveIPs := make([]string, 0, len(allAliveHosts))
			for _, h := range allAliveHosts {
				aliveIPs = append(aliveIPs, h.IP)
			}

			fmt.Printf("\n[端口扫描] %d 台主机, %d 个端口\n", len(aliveIPs), len(scanPorts))
			portResults := scanner.ScanCustomPorts(aliveIPs, scanPorts, thread)
			allPortResults = append(allPortResults, portResults...)
			for _, pr := range portResults {
				fmt.Printf("  [+] %s: ", pr.IP)
				for i, sp := range pr.Ports {
					if i > 0 {
						fmt.Print(", ")
					}
					fmt.Printf("%d/%s", sp.Port, sp.Service)
				}
				fmt.Println()
			}
			continue
		}

		if strings.EqualFold(input, "vuln") {
			if len(allAliveHosts) == 0 {
				fmt.Println("  [!] 暂无存活主机，请先探测目标")
				continue
			}
			aliveIPs := make([]string, 0, len(allAliveHosts))
			for _, h := range allAliveHosts {
				aliveIPs = append(aliveIPs, h.IP)
			}
			fmt.Printf("\n[漏洞检测] %d 台主机\n", len(aliveIPs))
			vulnResults := scanner.ScanMS17010(aliveIPs, thread)
			allVulnResults = append(allVulnResults, vulnResults...)
			for _, v := range vulnResults {
				fmt.Printf("  [!] %s: %s [%s] - %s\n", v.IP, v.VulnName, v.Severity, v.Detail)
			}
			continue
		}

		parts := strings.Split(input, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}

			if net.ParseIP(part) != nil {
				fmt.Printf("\n[单IP探测] %s\n", part)
				pr := scanner.ProbeIP(part)
				allResults = append(allResults, pr)
				if pr.Alive {
					ah := report.AliveHost{
						IP:        pr.IP,
						Online:    true,
						OpenPorts: pr.Ports,
						MAC:       pr.MAC,
					}
					allAliveHosts = append(allAliveHosts, ah)
					if pr.NetBIOS != nil {
						allNetBIOS = append(allNetBIOS, *pr.NetBIOS)
					}
					if pr.SMB != nil {
						allSMB = append(allSMB, *pr.SMB)
					}
				}
			} else if _, _, err := net.ParseCIDR(part); err == nil {
				fmt.Printf("\n[网段探测] %s (线程: %d)\n", part, thread)
				results := scanner.ProbeCIDR(part, thread)
				for _, pr := range results {
					allResults = append(allResults, pr)
					if pr.Alive {
						ah := report.AliveHost{
							IP:        pr.IP,
							Online:    true,
							OpenPorts: pr.Ports,
							MAC:       pr.MAC,
						}
						allAliveHosts = append(allAliveHosts, ah)
						if pr.NetBIOS != nil {
							allNetBIOS = append(allNetBIOS, *pr.NetBIOS)
						}
						if pr.SMB != nil {
							allSMB = append(allSMB, *pr.SMB)
						}
					}
				}
				fmt.Printf("  [+] 网段探测完成，存活 %d 台\n", countAlive(results))
			} else {
				fmt.Printf("  [!] 无效输入: %s (请输入IP或CIDR)\n", part)
			}
		}
	}
}

func countAlive(results []*scanner.ProbeResult) int {
	c := 0
	for _, r := range results {
		if r.Alive {
			c++
		}
	}
	return c
}

func printProbeHelp() {
	fmt.Println()
	fmt.Println("  交互式探测命令:")
	fmt.Println("    <IP>            探测单个IP，例: 192.168.1.1")
	fmt.Println("    <CIDR>          探测网段，例: 192.168.1.0/24")
	fmt.Println("    <IP1>,<IP2>     逗号分隔多目标")
	fmt.Println("    ps [端口]       端口扫描存活主机")
	fmt.Println("                    例: ps | ps 80,443,3389 | ps 1-1000")
	fmt.Println("    vuln            漏洞检测存活主机(MS17-010)")
	fmt.Println("    arp             扫描ARP表")
	fmt.Println("    list / ls       查看已探测记录")
	fmt.Println("    report          生成报告")
	fmt.Println("    clear / reset   清空探测记录")
	fmt.Println("    q / quit        退出（自动生成报告）")
	fmt.Println("    help            显示此帮助")
	fmt.Println()
}

func generateProbeReport(results []*scanner.ProbeResult, aliveHosts []report.AliveHost, netbiosInfos []report.NetBIOSInfo, smbInfos []report.SMBHostInfo, portResults []report.PortScanResult, vulnResults []report.VulnResult, thread int, outDir string) {
	now := time.Now()
	result := &report.ScanResult{
		StartTime:  now.Format("2006-01-02 15:04:05"),
		EndTime:    now.Format("2006-01-02 15:04:05"),
		Duration:   "interactive",
		Target:     "interactive probe",
		Threads:    thread,
		Version:    version,
		IsDomain:   false,
		AliveHosts: aliveHosts,
		NetBIOS:    netbiosInfos,
		SMBInfo:    smbInfos,
		PortScan:   portResults,
		VulnInfo:   vulnResults,
	}

	calcRiskStats(result)

	fmt.Println("\n[*] 生成报告...")
	report.GenerateReports(result, outDir)
	fmt.Printf("[+] 报告已输出至: %s\n", outDir)
	fmt.Println("[+] scan_result.json + scan_report.html")
}

func collectLocalInfo(result *report.ScanResult, silent bool) {
	if !silent {
		fmt.Println("\n[模块四] 本机内网基础信息收集...")
	}
	info, err := scanner.CollectLocalInfo()
	if err != nil {
		if !silent {
			fmt.Printf("  [!] 本机信息采集异常: %v\n", err)
		}
		return
	}
	result.LocalInfo = info
	result.IsDomain = info.IsDomainEnv
	if !silent {
		fmt.Println("  [+] 本机信息采集完成")
		if info.IsDomainEnv {
			fmt.Printf("  [+] 检测到域环境: %s\n", info.DomainName)
		} else {
			fmt.Println("  [+] 工作组环境")
		}
		if info.FirewallStatus != "" {
			fmt.Printf("  [+] 防火墙状态: %s\n", info.FirewallStatus)
		}
		if info.PasswordPolicy != nil {
			fmt.Printf("  [+] 密码最小长度: %s\n", info.PasswordPolicy.MinPasswordLen)
		}
		if len(info.SharedFolders) > 0 {
			fmt.Printf("  [+] 共享文件夹: %d 个\n", len(info.SharedFolders))
		}
		if len(info.ScheduledTasks) > 0 {
			fmt.Printf("  [+] 计划任务: %d 个\n", len(info.ScheduledTasks))
		}
	}
}

func scanTarget(target string, thread int, result *report.ScanResult, silent bool) {
	ips, err := utils.ParseTarget(target)
	if err != nil {
		if !silent {
			fmt.Printf("  [!] 目标解析失败: %v\n", err)
		}
		return
	}
	if !silent {
		fmt.Printf("  [+] 解析目标: %d 个IP\n", len(ips))
	}

	if !silent {
		fmt.Println("\n[模块一] 内网存活主机探测...")
	}
	aliveHosts := scanner.ScanAliveHosts(ips, thread)
	result.AliveHosts = aliveHosts
	if !silent {
		fmt.Printf("  [+] 存活主机: %d 台\n", len(aliveHosts))
	}

	if len(aliveHosts) == 0 {
		return
	}

	aliveIPs := make([]string, 0, len(aliveHosts))
	for _, h := range aliveHosts {
		aliveIPs = append(aliveIPs, h.IP)
	}

	if !silent {
		fmt.Println("\n[模块二] NetBIOS信息抓取...")
	}
	netbiosResults := scanner.ScanNetBIOS(aliveIPs, thread)
	result.NetBIOS = netbiosResults
	if !silent {
		fmt.Printf("  [+] NetBIOS信息: %d 条\n", len(netbiosResults))
	}

	if !silent {
		fmt.Println("\n[模块三] SMB基础信息采集...")
	}
	smbResults := scanner.ScanSMB(aliveIPs, thread)
	result.SMBInfo = smbResults
	if !silent {
		fmt.Printf("  [+] SMB信息: %d 条\n", len(smbResults))
	}
}

func autoScan(thread int, result *report.ScanResult, silent bool) {
	if result.LocalInfo == nil {
		return
	}

	var allIPs []string
	for _, adapter := range result.LocalInfo.Adapters {
		if adapter.IPAddress == "" || strings.HasPrefix(adapter.IPAddress, "127.") {
			continue
		}
		cidr := utils.IPToCIDR(adapter.IPAddress, adapter.SubnetMask)
		if cidr == "" {
			continue
		}
		ips, err := utils.ParseTarget(cidr)
		if err != nil {
			continue
		}
		allIPs = append(allIPs, ips...)
	}

	if len(allIPs) == 0 {
		if !silent {
			fmt.Println("  [!] 未发现可扫描网段")
		}
		return
	}

	allIPs = utils.DeduplicateStrings(allIPs)
	if !silent {
		fmt.Printf("  [+] 自动发现 %d 个IP待探测\n", len(allIPs))
	}

	if !silent {
		fmt.Println("\n[模块一] 内网存活主机探测...")
	}
	aliveHosts := scanner.ScanAliveHosts(allIPs, thread)
	result.AliveHosts = aliveHosts
	if !silent {
		fmt.Printf("  [+] 存活主机: %d 台\n", len(aliveHosts))
	}

	if len(aliveHosts) == 0 {
		return
	}

	aliveIPs := make([]string, 0, len(aliveHosts))
	for _, h := range aliveHosts {
		aliveIPs = append(aliveIPs, h.IP)
	}

	if !silent {
		fmt.Println("\n[模块二] NetBIOS信息抓取...")
	}
	netbiosResults := scanner.ScanNetBIOS(aliveIPs, thread)
	result.NetBIOS = netbiosResults
	if !silent {
		fmt.Printf("  [+] NetBIOS信息: %d 条\n", len(netbiosResults))
	}

	if !silent {
		fmt.Println("\n[模块三] SMB基础信息采集...")
	}
	smbResults := scanner.ScanSMB(aliveIPs, thread)
	result.SMBInfo = smbResults
	if !silent {
		fmt.Printf("  [+] SMB信息: %d 条\n", len(smbResults))
	}
}

func collectDomainInfo(result *report.ScanResult, silent bool) {
	if !silent {
		fmt.Println("\n[模块五] 域环境信息采集...")
	}
	domainInfo, err := scanner.CollectDomainInfo()
	if err != nil {
		if !silent {
			fmt.Printf("  [!] 域信息采集异常: %v\n", err)
		}
		return
	}
	result.DomainInfo = domainInfo
	if !silent {
		fmt.Println("  [+] 域信息采集完成")
	}
}

func collectARPInfo(result *report.ScanResult, silent bool) {
	if !silent {
		fmt.Println("\n[模块六] ARP表扫描...")
	}
	arpHosts := scanner.ScanARPForInterface()
	result.ARPHosts = arpHosts
	if !silent {
		fmt.Printf("  [+] ARP表记录: %d 条\n", len(arpHosts))
	}
}

func collectPortScanInfo(result *report.ScanResult, customPorts string, thread int, silent bool) {
	if !silent {
		fmt.Println("\n[模块七] 端口扫描...")
	}

	if len(result.AliveHosts) == 0 {
		if !silent {
			fmt.Println("  [!] 暂无存活主机，跳过端口扫描")
		}
		return
	}

	aliveIPs := make([]string, 0, len(result.AliveHosts))
	for _, h := range result.AliveHosts {
		aliveIPs = append(aliveIPs, h.IP)
	}

	var portResults []report.PortScanResult

	if customPorts != "" {
		ports, err := scanner.ParsePortRange(customPorts)
		if err != nil {
			if !silent {
				fmt.Printf("  [!] 端口解析失败: %v\n", err)
			}
			return
		}
		if !silent {
			fmt.Printf("  [+] 自定义端口: %v\n", ports)
		}
		portResults = scanner.ScanCustomPorts(aliveIPs, ports, thread)
	} else {
		if !silent {
			fmt.Printf("  [+] 扫描常见端口: %d 个\n", len(scanner.GetDefaultScanPorts()))
		}
		portResults = scanner.ScanPorts(aliveIPs, thread)
	}

	result.PortScan = portResults
	if !silent {
		totalOpen := 0
		for _, pr := range portResults {
			totalOpen += len(pr.Ports)
		}
		fmt.Printf("  [+] 端口扫描完成: %d 台主机共发现 %d 个开放端口\n", len(portResults), totalOpen)
	}

	collectServiceDetectInfo(result, thread, silent)
	collectWiFiInfo(result, silent)
	collectLDAPInfo(result, silent)
}

func collectServiceDetectInfo(result *report.ScanResult, thread int, silent bool) {
	if !silent {
		fmt.Println("\n[模块七-2] 服务识别...")
	}

	if len(result.AliveHosts) == 0 {
		return
	}

	aliveIPs := make([]string, 0, len(result.AliveHosts))
	for _, h := range result.AliveHosts {
		aliveIPs = append(aliveIPs, h.IP)
	}

	serviceResults := scanner.DetectServices(aliveIPs, thread)
	result.Services = serviceResults

	if !silent {
		fmt.Printf("  [+] 服务识别完成: %d 个服务\n", len(serviceResults))
	}
}

func collectWiFiInfo(result *report.ScanResult, silent bool) {
	if !silent {
		fmt.Println("\n[模块九] WiFi信息收集...")
	}

	wifiResults := scanner.ScanWiFi()
	result.WiFiInfo = wifiResults

	if !silent {
		fmt.Printf("  [+] WiFi扫描完成: %d 个网络\n", len(wifiResults))
	}
}

func collectLDAPInfo(result *report.ScanResult, silent bool) {
	if !silent {
		fmt.Println("\n[模块十] LDAP信息收集...")
	}

	var domainName string
	if result.LocalInfo != nil && result.LocalInfo.IsDomainEnv {
		domainName = result.LocalInfo.DomainName
	} else if result.DomainInfo != nil {
		domainName = result.DomainInfo.DomainName
	}

	if domainName == "" {
		if !silent {
			fmt.Println("  [!] 非域环境，跳过LDAP扫描")
		}
		return
	}

	ldapResult := scanner.ScanLDAP(domainName)
	result.LDAPInfo = ldapResult

	if !silent {
		if ldapResult != nil {
			fmt.Printf("  [+] LDAP服务器: %s\n", ldapResult.ServerIP)
		} else {
			fmt.Println("  [!] 未发现LDAP服务器")
		}
	}
}

func collectVulnInfo(result *report.ScanResult, thread int, silent bool) {
	if !silent {
		fmt.Println("\n[模块八] 漏洞检测...")
	}

	if len(result.AliveHosts) == 0 {
		if !silent {
			fmt.Println("  [!] 暂无存活主机，跳过漏洞检测")
		}
		return
	}

	aliveIPs := make([]string, 0, len(result.AliveHosts))
	for _, h := range result.AliveHosts {
		aliveIPs = append(aliveIPs, h.IP)
	}

	if !silent {
		fmt.Println("  [*] MS17-010 永恒之蓝检测...")
	}
	vulnResults := scanner.ScanMS17010(aliveIPs, thread)
	result.VulnInfo = vulnResults
	if !silent {
		highCount := 0
		for _, v := range vulnResults {
			if v.Severity == "high" {
				highCount++
			}
		}
		fmt.Printf("  [+] 漏洞检测完成: %d 条结果（高危: %d）\n", len(vulnResults), highCount)
	}
}

func calcRiskStats(result *report.ScanResult) {
	result.RiskStats = &report.RiskStats{}

	for _, h := range result.AliveHosts {
		for _, p := range h.OpenPorts {
			switch p {
			case 445:
				result.RiskStats.Open445Count++
			case 3389:
				result.RiskStats.Open3389Count++
			case 22:
				result.RiskStats.OpenSSHCount++
			case 21:
				result.RiskStats.OpenFTPCount++
			case 3306:
				result.RiskStats.OpenMySQLCount++
			case 1433:
				result.RiskStats.OpenMSSQLCount++
			case 6379:
				result.RiskStats.OpenRedisCount++
			case 80, 443, 8080, 8443:
				result.RiskStats.OpenHTTPCount++
			case 389, 636:
				result.RiskStats.OpenLDAPCount++
			}
		}
	}

	for _, s := range result.SMBInfo {
		if s.AnonymousAccess {
			result.RiskStats.AnonymousSMBCount++
		}
		if s.SMBSigning == "disabled" {
			result.RiskStats.SMBNoSignCount++
		}
	}

	for _, v := range result.VulnInfo {
		if v.VulnID == "MS17-010" && (v.Severity == "high" || v.Severity == "medium") {
			result.RiskStats.MS17010Count++
		}
	}
}