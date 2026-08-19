package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func GenerateReports(result *ScanResult, outDir string) error {
	if err := generateJSON(result, outDir); err != nil {
		return fmt.Errorf("生成JSON报告失败: %v", err)
	}

	if err := generateHTML(result, outDir); err != nil {
		return fmt.Errorf("生成HTML报告失败: %v", err)
	}

	return nil
}

func generateJSON(result *ScanResult, outDir string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(outDir, "scan_result.json")
	return os.WriteFile(path, data, 0644)
}

func generateHTML(result *ScanResult, outDir string) error {
	html := buildHTMLReport(result)
	path := filepath.Join(outDir, "scan_report.html")
	return os.WriteFile(path, []byte(html), 0644)
}

func buildHTMLReport(r *ScanResult) string {
	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LiteScan 内网信息收集报告</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: "Microsoft YaHei", "Segoe UI", Arial, sans-serif; background: #0a0e27; color: #e0e0e0; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
.header { background: linear-gradient(135deg, #1a1f3a, #2d1b69); padding: 30px; border-radius: 12px; margin-bottom: 20px; text-align: center; border: 1px solid #3d3d7a; }
.header h1 { color: #00d4ff; font-size: 28px; margin-bottom: 10px; }
.header .subtitle { color: #8888aa; font-size: 14px; }
.meta { display: flex; flex-wrap: wrap; gap: 15px; justify-content: center; margin-top: 15px; }
.meta-item { background: rgba(0,212,255,0.1); padding: 6px 14px; border-radius: 20px; font-size: 13px; color: #00d4ff; border: 1px solid rgba(0,212,255,0.3); }
.section { background: #111633; border-radius: 12px; margin-bottom: 20px; border: 1px solid #2a2a5a; overflow: hidden; }
.section-title { background: linear-gradient(90deg, #1a1f3a, #2d1b69); padding: 15px 20px; font-size: 18px; color: #00d4ff; border-bottom: 1px solid #2a2a5a; display: flex; align-items: center; gap: 10px; }
.section-title .icon { font-size: 20px; }
.section-body { padding: 20px; }
table { width: 100%; border-collapse: collapse; margin: 10px 0; }
th { background: #1a1f3a; color: #00d4ff; padding: 10px 12px; text-align: left; font-size: 13px; border-bottom: 2px solid #2d1b69; }
td { padding: 8px 12px; border-bottom: 1px solid #1a1f3a; font-size: 13px; }
tr:hover td { background: rgba(0,212,255,0.05); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: bold; }
.badge-green { background: rgba(0,255,100,0.15); color: #00ff64; border: 1px solid rgba(0,255,100,0.3); }
.badge-red { background: rgba(255,50,50,0.15); color: #ff5050; border: 1px solid rgba(255,50,50,0.3); }
.badge-yellow { background: rgba(255,200,0,0.15); color: #ffc800; border: 1px solid rgba(255,200,0,0.3); }
.badge-blue { background: rgba(0,150,255,0.15); color: #0096ff; border: 1px solid rgba(0,150,255,0.3); }
.info-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; }
.info-card { background: #0d1230; padding: 15px; border-radius: 8px; border: 1px solid #2a2a5a; }
.info-card .label { color: #8888aa; font-size: 12px; margin-bottom: 4px; }
.info-card .value { color: #e0e0e0; font-size: 14px; word-break: break-all; }
.risk-box { background: rgba(255,50,50,0.1); border: 1px solid rgba(255,50,50,0.3); border-radius: 8px; padding: 15px; margin-top: 10px; }
.risk-box .risk-title { color: #ff5050; font-size: 16px; margin-bottom: 10px; }
.risk-item { display: flex; align-items: center; gap: 10px; margin: 5px 0; }
.risk-item .count { color: #ff5050; font-size: 24px; font-weight: bold; }
.risk-item .desc { color: #e0e0e0; font-size: 13px; }
.patch-list { display: flex; flex-wrap: wrap; gap: 6px; }
.patch-tag { background: rgba(0,150,255,0.1); color: #0096ff; padding: 2px 8px; border-radius: 4px; font-size: 11px; border: 1px solid rgba(0,150,255,0.3); }
.empty { color: #555; text-align: center; padding: 20px; font-style: italic; }
.footer { text-align: center; color: #555; padding: 20px; font-size: 12px; }
</style>
</head>
<body>
<div class="container">
`

	html += `<div class="header">
<h1>LiteScan 内网信息收集报告</h1>
<div class="subtitle">轻量化内网资产探测 | 仅限授权安全测试使用</div>
<div class="meta">
<span class="meta-item">版本: ` + r.Version + `</span>
<span class="meta-item">开始: ` + r.StartTime + `</span>
<span class="meta-item">结束: ` + r.EndTime + `</span>
<span class="meta-item">耗时: ` + r.Duration + `</span>
`
	if r.Target != "" {
		html += `<span class="meta-item">目标: ` + r.Target + `</span>`
	}
	html += `<span class="meta-item">线程: ` + fmt.Sprintf("%d", r.Threads) + `</span>`
	if r.IsDomain {
		html += `<span class="meta-item">环境: 域环境</span>`
	} else {
		html += `<span class="meta-item">环境: 工作组</span>`
	}
	html += `</div></div>`

	html += buildLocalInfoHTML(r)
	html += buildAliveHostsHTML(r)
	html += buildARPHTML(r)
	html += buildNetBIOSHTML(r)
	html += buildSMBHTML(r)
	html += buildPortScanHTML(r)
	html += buildVulnHTML(r)
	if r.IsDomain {
		html += buildDomainHTML(r)
	}
	html += buildRiskHTML(r)

	html += `<div class="footer">LiteScan v` + r.Version + ` | 本报告仅用于授权安全测试 | ` + r.EndTime + `</div>`
	html += `</div></body></html>`

	return html
}

func buildLocalInfoHTML(r *ScanResult) string {
	if r.LocalInfo == nil {
		return ""
	}
	li := r.LocalInfo
	html := `<div class="section"><div class="section-title"><span class="icon">&#128187;</span> 本机内网基础信息</div><div class="section-body">`

	html += `<div class="info-grid">`
	html += infoCard("主机名", li.Hostname)
	html += infoCard("操作系统", li.OSVersion)
	html += infoCard("当前用户", li.CurrentUser)
	if li.IsDomainEnv {
		html += infoCard("域名称", li.DomainName)
		html += `<div class="info-card"><div class="label">环境类型</div><div class="value"><span class="badge badge-red">域环境</span></div></div>`
	} else {
		html += infoCard("工作组", li.Workgroup)
		html += `<div class="info-card"><div class="label">环境类型</div><div class="value"><span class="badge badge-green">工作组</span></div></div>`
	}
	html += `</div>`

	if len(li.Adapters) > 0 {
		html += `<h3 style="color:#00d4ff;margin:15px 0 10px;font-size:15px;">网络适配器</h3><table><tr><th>名称</th><th>IP地址</th><th>子网掩码</th><th>网关</th><th>DNS</th><th>MAC</th></tr>`
		for _, a := range li.Adapters {
			html += fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, a.Name, a.IPAddress, a.SubnetMask, a.Gateway, a.DNS, a.MACAddress)
		}
		html += `</table>`
	}

	if len(li.OpenPorts) > 0 {
		html += `<h3 style="color:#00d4ff;margin:15px 0 10px;font-size:15px;">监听端口 (前50)</h3><table><tr><th>协议</th><th>端口</th><th>状态</th></tr>`
		count := 0
		for _, p := range li.OpenPorts {
			if count >= 50 {
				break
			}
			html += fmt.Sprintf(`<tr><td>%s</td><td>%d</td><td>%s</td></tr>`, p.Protocol, p.Port, p.State)
			count++
		}
		html += `</table>`
	}

	if len(li.AdminUsers) > 0 {
		html += `<h3 style="color:#00d4ff;margin:15px 0 10px;font-size:15px;">本地管理员</h3><div class="info-grid">`
		for _, u := range li.AdminUsers {
			html += infoCard("", u)
		}
		html += `</div>`
	}

	if len(li.SystemPatches) > 0 {
		html += `<h3 style="color:#00d4ff;margin:15px 0 10px;font-size:15px;">系统补丁</h3><div class="patch-list">`
		for _, p := range li.SystemPatches {
			html += `<span class="patch-tag">` + p + `</span>`
		}
		html += `</div>`
	}

	if li.FirewallStatus != "" {
		html += `<h3 style="color:#00d4ff;margin:15px 0 10px;font-size:15px;">防火墙状态</h3>`
		if li.FirewallStatus == "已启用" {
			html += `<span class="badge badge-green">已启用</span>`
		} else if li.FirewallStatus == "已关闭" {
			html += `<span class="badge badge-red">已关闭</span>`
		} else {
			html += `<span class="badge badge-yellow">` + li.FirewallStatus + `</span>`
		}
	}

	if li.PasswordPolicy != nil {
		html += `<h3 style="color:#00d4ff;margin:15px 0 10px;font-size:15px;">密码策略</h3><div class="info-grid">`
		pp := li.PasswordPolicy
		html += infoCard("最小密码长度", pp.MinPasswordLen)
		html += infoCard("最大密码存留期", pp.MaxPasswordAge)
		html += infoCard("最短密码存留期", pp.MinPasswordAge)
		html += infoCard("密码历史长度", pp.PasswordHistory)
		html += infoCard("锁定阈值", pp.LockoutThreshold)
		html += infoCard("锁定持续时间", pp.LockoutDuration)
		html += infoCard("密码复杂性", pp.ComplexityEnabled)
		html += `</div>`
	}

	if len(li.SharedFolders) > 0 {
		html += `<h3 style="color:#00d4ff;margin:15px 0 10px;font-size:15px;">共享文件夹 (` + fmt.Sprintf("%d", len(li.SharedFolders)) + `)</h3><div class="patch-list">`
		for _, s := range li.SharedFolders {
			html += `<span class="patch-tag">` + s + `</span>`
		}
		html += `</div>`
	}

	if len(li.UserSessions) > 0 {
		html += `<h3 style="color:#00d4ff;margin:15px 0 10px;font-size:15px;">用户会话</h3><table><tr><th>会话信息</th></tr>`
		for _, s := range li.UserSessions {
			html += fmt.Sprintf(`<tr><td>%s</td></tr>`, s)
		}
		html += `</table>`
	}

	if len(li.StartupItems) > 0 {
		html += `<h3 style="color:#00d4ff;margin:15px 0 10px;font-size:15px;">启动项 (` + fmt.Sprintf("%d", len(li.StartupItems)) + `)</h3><div class="patch-list">`
		for _, s := range li.StartupItems {
			html += `<span class="patch-tag">` + s + `</span>`
		}
		html += `</div>`
	}

	if len(li.ScheduledTasks) > 0 {
		html += `<h3 style="color:#00d4ff;margin:15px 0 10px;font-size:15px;">计划任务 (` + fmt.Sprintf("%d", len(li.ScheduledTasks)) + `)</h3><table><tr><th>任务名</th></tr>`
		for _, t := range li.ScheduledTasks {
			html += fmt.Sprintf(`<tr><td>%s</td></tr>`, t)
		}
		html += `</table>`
	}

	if len(li.ProcessList) > 0 {
		html += `<h3 style="color:#00d4ff;margin:15px 0 10px;font-size:15px;">进程列表 (前50)</h3><table><tr><th>PID</th><th>进程名</th><th>内存(MB)</th></tr>`
		for _, p := range li.ProcessList {
			html += fmt.Sprintf(`<tr><td>%d</td><td>%s</td><td>%d</td></tr>`, p.PID, p.Name, p.MemMB)
		}
		html += `</table>`
	}

	html += `</div></div>`
	return html
}

func buildAliveHostsHTML(r *ScanResult) string {
	if len(r.AliveHosts) == 0 {
		return ""
	}
	html := `<div class="section"><div class="section-title"><span class="icon">&#128225;</span> 存活主机资产总表 (` + fmt.Sprintf("%d", len(r.AliveHosts)) + `)</div><div class="section-body">`
	html += `<table><tr><th>IP地址</th><th>MAC地址</th><th>状态</th><th>开放端口</th></tr>`
	for _, h := range r.AliveHosts {
		status := `<span class="badge badge-green">在线</span>`
		ports := ""
		for i, p := range h.OpenPorts {
			if i > 0 {
				ports += ", "
			}
			ports += fmt.Sprintf("%d", p)
		}
		if ports == "" {
			ports = "-"
		}
		mac := h.MAC
		if mac == "" {
			mac = "-"
		}
		html += fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, h.IP, mac, status, ports)
	}
	html += `</table></div></div>`
	return html
}

func buildNetBIOSHTML(r *ScanResult) string {
	if len(r.NetBIOS) == 0 {
		return ""
	}
	html := `<div class="section"><div class="section-title"><span class="icon">&#128421;</span> NetBIOS信息汇总 (` + fmt.Sprintf("%d", len(r.NetBIOS)) + `)</div><div class="section-body">`
	html += `<table><tr><th>IP地址</th><th>主机名</th><th>工作组/域</th><th>设备类型</th><th>状态</th></tr>`
	for _, n := range r.NetBIOS {
		dt := n.DeviceType
		if dt == "" {
			dt = "-"
		}
		html += fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, n.IP, n.Hostname, n.Workgroup, dt, n.Status)
	}
	html += `</table></div></div>`
	return html
}

func buildSMBHTML(r *ScanResult) string {
	if len(r.SMBInfo) == 0 {
		return ""
	}
	html := `<div class="section"><div class="section-title"><span class="icon">&#128272;</span> SMB服务与共享资产 (` + fmt.Sprintf("%d", len(r.SMBInfo)) + `)</div><div class="section-body">`
	html += `<table><tr><th>IP地址</th><th>SMB状态</th><th>SMB版本</th><th>系统版本</th><th>公开共享</th><th>匿名访问</th><th>SMB签名</th></tr>`
	for _, s := range r.SMBInfo {
		smbStatus := `<span class="badge badge-red">关闭</span>`
		if s.SMBEnabled {
			smbStatus = `<span class="badge badge-green">开启</span>`
		}
		smbVer := s.SMBVersion
		if smbVer == "" {
			smbVer = "-"
		}
		shares := ""
		for i, sh := range s.Shares {
			if i > 0 {
				shares += ", "
			}
			shares += sh
		}
		if shares == "" {
			shares = "-"
		}
		anon := `<span class="badge badge-green">拒绝</span>`
		if s.AnonymousAccess {
			anon = `<span class="badge badge-red">允许</span>`
		}
		osVer := s.OSVersion
		if osVer == "" {
			osVer = "-"
		}
		signing := s.SMBSigning
		if signing == "" {
			signing = "-"
		}
		signingBadge := signing
		switch signing {
		case "required":
			signingBadge = `<span class="badge badge-green">必须(required)</span>`
		case "enabled":
			signingBadge = `<span class="badge badge-yellow">启用(enabled)</span>`
		case "disabled":
			signingBadge = `<span class="badge badge-red">禁用(disabled)</span>`
		}
		html += fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, s.IP, smbStatus, smbVer, osVer, shares, anon, signingBadge)
	}
	html += `</table></div></div>`
	return html
}

func buildDomainHTML(r *ScanResult) string {
	if r.DomainInfo == nil {
		return ""
	}
	d := r.DomainInfo
	html := `<div class="section"><div class="section-title"><span class="icon">&#127968;</span> 域环境信息</div><div class="section-body">`

	html += `<div class="info-grid">`
	html += infoCard("域名称", d.DomainName)
	html += infoCard("域控IP", d.DomainCtrlIP)
	html += infoCard("域控主机名", d.DomainCtrlName)
	html += infoCard("域权限", d.DomainPriv)
	html += infoCard("域登录状态", d.DomainLogin)
	html += `</div>`

	if len(d.DomainHosts) > 0 {
		html += `<h3 style="color:#00d4ff;margin:15px 0 10px;font-size:15px;">域内主机 (` + fmt.Sprintf("%d", len(d.DomainHosts)) + `)</h3><table><tr><th>主机名</th></tr>`
		for _, h := range d.DomainHosts {
			html += fmt.Sprintf(`<tr><td>%s</td></tr>`, h)
		}
		html += `</table>`
	}

	if len(d.DomainUsers) > 0 {
		html += `<h3 style="color:#00d4ff;margin:15px 0 10px;font-size:15px;">域用户 (` + fmt.Sprintf("%d", len(d.DomainUsers)) + `)</h3><table><tr><th>用户名</th></tr>`
		for _, u := range d.DomainUsers {
			html += fmt.Sprintf(`<tr><td>%s</td></tr>`, u)
		}
		html += `</table>`
	}

	if len(d.DomainGPO) > 0 {
		html += `<h3 style="color:#00d4ff;margin:15px 0 10px;font-size:15px;">域组策略</h3><div class="patch-list">`
		for _, g := range d.DomainGPO {
			html += `<span class="patch-tag">` + g + `</span>`
		}
		html += `</div>`
	}

	html += `</div></div>`
	return html
}

func buildRiskHTML(r *ScanResult) string {
	if r.RiskStats == nil {
		return ""
	}
	rs := r.RiskStats
	if rs.Open445Count == 0 && rs.AnonymousSMBCount == 0 && rs.Open3389Count == 0 && rs.MS17010Count == 0 && rs.SMBNoSignCount == 0 {
		return ""
	}
	html := `<div class="section"><div class="section-title"><span class="icon">&#9888;</span> 风险简要统计</div><div class="section-body"><div class="risk-box">`
	html += `<div class="risk-title">安全风险提示</div>`
	if rs.Open445Count > 0 {
		html += `<div class="risk-item"><span class="count">` + fmt.Sprintf("%d", rs.Open445Count) + `</span><span class="desc">台主机开放445端口（SMB服务），可能面临永恒之蓝等SMB漏洞风险</span></div>`
	}
	if rs.AnonymousSMBCount > 0 {
		html += `<div class="risk-item"><span class="count">` + fmt.Sprintf("%d", rs.AnonymousSMBCount) + `</span><span class="desc">台主机允许匿名SMB访问，存在信息泄露风险</span></div>`
	}
	if rs.Open3389Count > 0 {
		html += `<div class="risk-item"><span class="count">` + fmt.Sprintf("%d", rs.Open3389Count) + `</span><span class="desc">台主机开放3389端口（RDP远程桌面），可能面临暴力破解风险</span></div>`
	}
	if rs.MS17010Count > 0 {
		html += `<div class="risk-item"><span class="count">` + fmt.Sprintf("%d", rs.MS17010Count) + `</span><span class="desc">台主机可能存在MS17-010永恒之蓝漏洞，高危风险</span></div>`
	}
	if rs.SMBNoSignCount > 0 {
		html += `<div class="risk-item"><span class="count">` + fmt.Sprintf("%d", rs.SMBNoSignCount) + `</span><span class="desc">台主机SMB签名未启用，存在中间人攻击风险</span></div>`
	}
	html += `</div></div></div>`
	return html
}

func buildARPHTML(r *ScanResult) string {
	if len(r.ARPHosts) == 0 {
		return ""
	}
	html := `<div class="section"><div class="section-title"><span class="icon">&#128202;</span> ARP表记录 (` + fmt.Sprintf("%d", len(r.ARPHosts)) + `)</div><div class="section-body">`
	html += `<table><tr><th>IP地址</th><th>MAC地址</th><th>类型</th><th>接口</th></tr>`
	for _, h := range r.ARPHosts {
		iface := h.Interface
		if iface == "" {
			iface = "-"
		}
		hType := h.Type
		if hType == "" {
			hType = "-"
		}
		html += fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, h.IP, h.MAC, hType, iface)
	}
	html += `</table></div></div>`
	return html
}

func buildPortScanHTML(r *ScanResult) string {
	if len(r.PortScan) == 0 {
		return ""
	}
	html := `<div class="section"><div class="section-title"><span class="icon">&#128268;</span> 端口扫描结果 (` + fmt.Sprintf("%d", len(r.PortScan)) + ` 台主机)</div><div class="section-body">`
	html += `<table><tr><th>IP地址</th><th>端口</th><th>服务</th><th>状态</th><th>Banner</th></tr>`
	for _, pr := range r.PortScan {
		for _, sp := range pr.Ports {
			banner := sp.Banner
			if banner == "" {
				banner = "-"
			}
			if len(banner) > 60 {
				banner = banner[:60] + "..."
			}
			stateBadge := `<span class="badge badge-green">open</span>`
			html += fmt.Sprintf(`<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>`, pr.IP, sp.Port, sp.Service, stateBadge, banner)
		}
	}
	html += `</table></div></div>`
	return html
}

func buildVulnHTML(r *ScanResult) string {
	if len(r.VulnInfo) == 0 {
		return ""
	}
	html := `<div class="section"><div class="section-title"><span class="icon">&#9888;</span> 漏洞检测结果 (` + fmt.Sprintf("%d", len(r.VulnInfo)) + `)</div><div class="section-body">`
	html += `<table><tr><th>IP地址</th><th>漏洞编号</th><th>漏洞名称</th><th>严重程度</th><th>详情</th></tr>`
	for _, v := range r.VulnInfo {
		severityBadge := ""
		switch v.Severity {
		case "high":
			severityBadge = `<span class="badge badge-red">高危</span>`
		case "medium":
			severityBadge = `<span class="badge badge-yellow">中危</span>`
		case "low":
			severityBadge = `<span class="badge badge-blue">低危</span>`
		default:
			severityBadge = `<span class="badge badge-blue">未知</span>`
		}
		html += fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, v.IP, v.VulnID, v.VulnName, severityBadge, v.Detail)
	}
	html += `</table></div></div>`
	return html
}

func infoCard(label, value string) string {
	if value == "" {
		value = "-"
	}
	return `<div class="info-card"><div class="label">` + label + `</div><div class="value">` + value + `</div></div>`
}