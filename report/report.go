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
<title>LiteScan - 内网信息收集报告</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
:root {
  --bg-primary: #060b18;
  --bg-secondary: #0c1224;
  --bg-card: #111a2e;
  --bg-card-hover: #152038;
  --border-primary: #1e2d4a;
  --border-accent: #2a3f6a;
  --text-primary: #e8edf5;
  --text-secondary: #8892a8;
  --text-muted: #5a6478;
  --accent-cyan: #00d4ff;
  --accent-cyan-dim: rgba(0,212,255,0.12);
  --accent-purple: #8b5cf6;
  --accent-purple-dim: rgba(139,92,246,0.12);
  --accent-green: #10b981;
  --accent-green-dim: rgba(16,185,129,0.12);
  --accent-red: #ef4444;
  --accent-red-dim: rgba(239,68,68,0.12);
  --accent-yellow: #f59e0b;
  --accent-yellow-dim: rgba(245,158,11,0.12);
  --accent-blue: #3b82f6;
  --accent-blue-dim: rgba(59,130,246,0.12);
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.3);
  --shadow-md: 0 4px 12px rgba(0,0,0,0.4);
  --shadow-lg: 0 8px 24px rgba(0,0,0,0.5);
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 14px;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
html { scroll-behavior: smooth; }
body { font-family: "Inter", "Microsoft YaHei", "Segoe UI", system-ui, sans-serif; background: var(--bg-primary); color: var(--text-primary); line-height: 1.7; min-height: 100vh; }
body::before { content: ""; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: radial-gradient(ellipse at 20% 0%, rgba(0,212,255,0.04) 0%, transparent 50%), radial-gradient(ellipse at 80% 100%, rgba(139,92,246,0.04) 0%, transparent 50%); pointer-events: none; z-index: 0; }
.container { max-width: 1280px; margin: 0 auto; padding: 24px; position: relative; z-index: 1; }
.header { background: linear-gradient(135deg, #0c1224 0%, #151a35 40%, #1a1040 70%, #0c1224 100%); padding: 40px 32px; border-radius: var(--radius-lg); margin-bottom: 24px; text-align: center; border: 1px solid var(--border-accent); box-shadow: var(--shadow-lg), inset 0 1px 0 rgba(255,255,255,0.05); position: relative; overflow: hidden; }
.header::before { content: ""; position: absolute; top: -50%; left: -50%; width: 200%; height: 200%; background: conic-gradient(from 0deg at 50% 50%, transparent 0deg, rgba(0,212,255,0.03) 60deg, transparent 120deg, rgba(139,92,246,0.03) 240deg, transparent 360deg); animation: headerRotate 20s linear infinite; pointer-events: none; }
@keyframes headerRotate { to { transform: rotate(360deg); } }
.header h1 { color: var(--accent-cyan); font-size: 32px; font-weight: 700; margin-bottom: 8px; letter-spacing: -0.5px; position: relative; }
.header h1::after { content: ""; display: block; width: 60px; height: 3px; background: linear-gradient(90deg, var(--accent-cyan), var(--accent-purple)); margin: 12px auto 0; border-radius: 2px; }
.header .subtitle { color: var(--text-secondary); font-size: 14px; font-weight: 400; position: relative; }
.meta { display: flex; flex-wrap: wrap; gap: 10px; justify-content: center; margin-top: 20px; position: relative; }
.meta-item { background: var(--accent-cyan-dim); padding: 5px 14px; border-radius: 20px; font-size: 12px; color: var(--accent-cyan); border: 1px solid rgba(0,212,255,0.2); font-weight: 500; transition: all 0.2s; }
.meta-item:hover { background: rgba(0,212,255,0.2); border-color: rgba(0,212,255,0.4); transform: translateY(-1px); }
.stats-bar { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 24px; }
.stat-card { background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-md); padding: 16px; text-align: center; transition: all 0.3s; box-shadow: var(--shadow-sm); }
.stat-card:hover { border-color: var(--border-accent); transform: translateY(-2px); box-shadow: var(--shadow-md); }
.stat-card .stat-value { font-size: 28px; font-weight: 700; font-family: "JetBrains Mono", monospace; }
.stat-card .stat-label { font-size: 12px; color: var(--text-secondary); margin-top: 4px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }
.stat-cyan .stat-value { color: var(--accent-cyan); }
.stat-purple .stat-value { color: var(--accent-purple); }
.stat-green .stat-value { color: var(--accent-green); }
.stat-red .stat-value { color: var(--accent-red); }
.stat-yellow .stat-value { color: var(--accent-yellow); }
.stat-blue .stat-value { color: var(--accent-blue); }
.section { background: var(--bg-secondary); border-radius: var(--radius-lg); margin-bottom: 20px; border: 1px solid var(--border-primary); overflow: hidden; box-shadow: var(--shadow-sm); transition: all 0.3s; }
.section:hover { border-color: var(--border-accent); box-shadow: var(--shadow-md); }
.section-title { background: linear-gradient(90deg, var(--bg-card) 0%, rgba(0,212,255,0.05) 100%); padding: 16px 24px; font-size: 16px; color: var(--accent-cyan); border-bottom: 1px solid var(--border-primary); display: flex; align-items: center; gap: 10px; font-weight: 600; }
.section-title .icon { font-size: 18px; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; background: var(--accent-cyan-dim); border-radius: var(--radius-sm); }
.section-body { padding: 20px 24px; }
.sub-title { color: var(--accent-cyan); margin: 18px 0 10px; font-size: 14px; font-weight: 600; display: flex; align-items: center; gap: 8px; padding-bottom: 6px; border-bottom: 1px solid var(--border-primary); }
.sub-title::before { content: ""; width: 3px; height: 14px; background: var(--accent-cyan); border-radius: 2px; }
table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 13px; }
th { background: var(--bg-card); color: var(--accent-cyan); padding: 10px 14px; text-align: left; font-size: 12px; font-weight: 600; border-bottom: 1px solid var(--border-accent); text-transform: uppercase; letter-spacing: 0.3px; white-space: nowrap; }
td { padding: 9px 14px; border-bottom: 1px solid var(--border-primary); color: var(--text-primary); }
tr { transition: background 0.15s; }
tr:hover td { background: rgba(0,212,255,0.03); }
tr:last-child td { border-bottom: none; }
.badge { display: inline-flex; align-items: center; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; letter-spacing: 0.3px; gap: 4px; }
.badge-green { background: var(--accent-green-dim); color: var(--accent-green); border: 1px solid rgba(16,185,129,0.25); }
.badge-red { background: var(--accent-red-dim); color: var(--accent-red); border: 1px solid rgba(239,68,68,0.25); }
.badge-yellow { background: var(--accent-yellow-dim); color: var(--accent-yellow); border: 1px solid rgba(245,158,11,0.25); }
.badge-blue { background: var(--accent-blue-dim); color: var(--accent-blue); border: 1px solid rgba(59,130,246,0.25); }
.badge-purple { background: var(--accent-purple-dim); color: var(--accent-purple); border: 1px solid rgba(139,92,246,0.25); }
.info-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }
.info-card { background: var(--bg-card); padding: 14px 16px; border-radius: var(--radius-sm); border: 1px solid var(--border-primary); transition: all 0.2s; }
.info-card:hover { border-color: var(--border-accent); background: var(--bg-card-hover); }
.info-card .label { color: var(--text-muted); font-size: 11px; margin-bottom: 3px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }
.info-card .value { color: var(--text-primary); font-size: 14px; word-break: break-all; font-weight: 500; }
.risk-box { background: linear-gradient(135deg, var(--accent-red-dim), rgba(239,68,68,0.05)); border: 1px solid rgba(239,68,68,0.2); border-radius: var(--radius-md); padding: 20px; margin-top: 10px; }
.risk-box .risk-title { color: var(--accent-red); font-size: 16px; margin-bottom: 12px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
.risk-item { display: flex; align-items: center; gap: 12px; margin: 8px 0; padding: 8px 12px; background: rgba(239,68,68,0.06); border-radius: var(--radius-sm); border-left: 3px solid var(--accent-red); }
.risk-item .count { color: var(--accent-red); font-size: 26px; font-weight: 700; font-family: "JetBrains Mono", monospace; min-width: 40px; text-align: center; }
.risk-item .desc { color: var(--text-primary); font-size: 13px; }
.patch-list { display: flex; flex-wrap: wrap; gap: 6px; }
.patch-tag { background: var(--accent-blue-dim); color: var(--accent-blue); padding: 3px 10px; border-radius: 4px; font-size: 11px; border: 1px solid rgba(59,130,246,0.2); font-family: "JetBrains Mono", monospace; font-weight: 500; }
.empty { color: var(--text-muted); text-align: center; padding: 24px; font-style: italic; }
.footer { text-align: center; color: var(--text-muted); padding: 24px; font-size: 12px; border-top: 1px solid var(--border-primary); margin-top: 8px; }
.footer a { color: var(--accent-cyan); text-decoration: none; }
.nav-bar { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 24px; justify-content: center; }
.nav-btn { background: var(--bg-card); color: var(--text-secondary); padding: 6px 14px; border-radius: 20px; font-size: 12px; border: 1px solid var(--border-primary); cursor: pointer; transition: all 0.2s; text-decoration: none; font-weight: 500; }
.nav-btn:hover { color: var(--accent-cyan); border-color: rgba(0,212,255,0.3); background: var(--accent-cyan-dim); }
@media (max-width: 768px) { .container { padding: 12px; } .header { padding: 24px 16px; } .header h1 { font-size: 24px; } .stats-bar { grid-template-columns: repeat(2, 1fr); } .info-grid { grid-template-columns: 1fr; } .section-body { padding: 14px 16px; } table { font-size: 12px; } th, td { padding: 7px 8px; } }
</style>
</head>
<body>
<div class="container">
`

	html += `<div class="header">
<h1>&#128270; LiteScan</h1>
<div class="subtitle">内网轻量级信息收集报告 | 仅限授权安全测试使用</div>
<div class="meta">
<span class="meta-item">&#9889; v` + r.Version + `</span>
<span class="meta-item">&#128336; ` + r.StartTime + `</span>
<span class="meta-item">&#9201; ` + r.Duration + `</span>
`
	if r.Target != "" {
		html += `<span class="meta-item">&#127919; ` + r.Target + `</span>`
	}
	html += `<span class="meta-item">&#128736; ` + fmt.Sprintf("%d", r.Threads) + ` threads</span>`
	if r.IsDomain {
		html += `<span class="meta-item">&#127968; 域环境</span>`
	} else {
		html += `<span class="meta-item">&#128101; 工作组</span>`
	}
	html += `</div></div>`

	html += buildStatsBar(r)

	html += buildLocalInfoHTML(r)
	html += buildAliveHostsHTML(r)
	html += buildARPHTML(r)
	html += buildNetBIOSHTML(r)
	html += buildSMBHTML(r)
	html += buildPortScanHTML(r)
	html += buildVulnHTML(r)
	html += buildServiceDetectHTML(r)
	html += buildWiFiHTML(r)
	html += buildLDAPHTML(r)
	if r.IsDomain {
		html += buildDomainHTML(r)
	}
	html += buildRiskHTML(r)

	html += `<div class="footer">LiteScan v` + r.Version + ` &middot; 本报告仅用于授权安全测试 &middot; ` + r.EndTime + `</div>`
	html += `</div></body></html>`

	return html
}

func buildStatsBar(r *ScanResult) string {
	aliveCount := len(r.AliveHosts)
	smbCount := 0
	for _, s := range r.SMBInfo {
		if s.SMBEnabled {
			smbCount++
		}
	}
	portCount := 0
	for _, pr := range r.PortScan {
		portCount += len(pr.Ports)
	}
	vulnHigh := 0
	for _, v := range r.VulnInfo {
		if v.Severity == "high" {
			vulnHigh++
		}
	}
	serviceCount := len(r.Services)
	wifiCount := len(r.WiFiInfo)

	html := `<div class="stats-bar">`
	html += `<div class="stat-card stat-cyan"><div class="stat-value">` + fmt.Sprintf("%d", aliveCount) + `</div><div class="stat-label">存活主机</div></div>`
	html += `<div class="stat-card stat-purple"><div class="stat-value">` + fmt.Sprintf("%d", smbCount) + `</div><div class="stat-label">SMB服务</div></div>`
	html += `<div class="stat-card stat-green"><div class="stat-value">` + fmt.Sprintf("%d", portCount) + `</div><div class="stat-label">开放端口</div></div>`
	html += `<div class="stat-card stat-red"><div class="stat-value">` + fmt.Sprintf("%d", vulnHigh) + `</div><div class="stat-label">高危漏洞</div></div>`
	html += `<div class="stat-card stat-yellow"><div class="stat-value">` + fmt.Sprintf("%d", serviceCount) + `</div><div class="stat-label">识别服务</div></div>`
	html += `<div class="stat-card stat-blue"><div class="stat-value">` + fmt.Sprintf("%d", wifiCount) + `</div><div class="stat-label">WiFi网络</div></div>`
	html += `</div>`
	return html
}

func buildLocalInfoHTML(r *ScanResult) string {
	if r.LocalInfo == nil {
		return ""
	}
	li := r.LocalInfo
	html := `<div class="section"><div class="section-title"><span class="icon">&#128187;</span> 本机内网基础信息</div><div class="section-body">`

	html += `<div class="info-grid">`
	html += infoCard("&#128433; 主机名", li.Hostname)
	html += infoCard("&#128187; 操作系统", li.OSVersion)
	html += infoCard("&#128100; 当前用户", li.CurrentUser)
	if li.IsDomainEnv {
		html += infoCard("域名称", li.DomainName)
		html += `<div class="info-card"><div class="label">环境类型</div><div class="value"><span class="badge badge-red">域环境</span></div></div>`
	} else {
		html += infoCard("工作组", li.Workgroup)
		html += `<div class="info-card"><div class="label">环境类型</div><div class="value"><span class="badge badge-green">工作组</span></div></div>`
	}
	html += `</div>`

	if len(li.Adapters) > 0 {
		html += `<div class="sub-title">网络适配器</div><table><tr><th>名称</th><th>IP地址</th><th>子网掩码</th><th>网关</th><th>DNS</th><th>MAC</th></tr>`
		for _, a := range li.Adapters {
			html += fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, a.Name, a.IPAddress, a.SubnetMask, a.Gateway, a.DNS, a.MACAddress)
		}
		html += `</table>`
	}

	if len(li.OpenPorts) > 0 {
		html += `<div class="sub-title">监听端口 (前50)</div><table><tr><th>协议</th><th>端口</th><th>状态</th></tr>`
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
		html += `<div class="sub-title">本地管理员</div><div class="info-grid">`
		for _, u := range li.AdminUsers {
			html += infoCard("", u)
		}
		html += `</div>`
	}

	if len(li.SystemPatches) > 0 {
		html += `<div class="sub-title">系统补丁</div><div class="patch-list">`
		for _, p := range li.SystemPatches {
			html += `<span class="patch-tag">` + p + `</span>`
		}
		html += `</div>`
	}

	if li.FirewallStatus != "" {
		html += `<div class="sub-title">防火墙状态</div>`
		if li.FirewallStatus == "已启用" {
			html += `<span class="badge badge-green">已启用</span>`
		} else if li.FirewallStatus == "已关闭" {
			html += `<span class="badge badge-red">已关闭</span>`
		} else {
			html += `<span class="badge badge-yellow">` + li.FirewallStatus + `</span>`
		}
	}

	if li.PasswordPolicy != nil {
		html += `<div class="sub-title">密码策略</div><div class="info-grid">`
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
		html += `<div class="sub-title">共享文件夹 (` + fmt.Sprintf("%d", len(li.SharedFolders)) + `)</div><div class="patch-list">`
		for _, s := range li.SharedFolders {
			html += `<span class="patch-tag">` + s + `</span>`
		}
		html += `</div>`
	}

	if len(li.UserSessions) > 0 {
		html += `<div class="sub-title">用户会话</div><table><tr><th>会话信息</th></tr>`
		for _, s := range li.UserSessions {
			html += fmt.Sprintf(`<tr><td>%s</td></tr>`, s)
		}
		html += `</table>`
	}

	if len(li.StartupItems) > 0 {
		html += `<div class="sub-title">启动项 (` + fmt.Sprintf("%d", len(li.StartupItems)) + `)</div><div class="patch-list">`
		for _, s := range li.StartupItems {
			html += `<span class="patch-tag">` + s + `</span>`
		}
		html += `</div>`
	}

	if len(li.ScheduledTasks) > 0 {
		html += `<div class="sub-title">计划任务 (` + fmt.Sprintf("%d", len(li.ScheduledTasks)) + `)</div><table><tr><th>任务名</th></tr>`
		for _, t := range li.ScheduledTasks {
			html += fmt.Sprintf(`<tr><td>%s</td></tr>`, t)
		}
		html += `</table>`
	}

	if len(li.ProcessList) > 0 {
		html += `<div class="sub-title">进程列表 (前50)</div><table><tr><th>PID</th><th>进程名</th><th>内存(MB)</th></tr>`
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
		html += `<div class="sub-title">域内主机 (` + fmt.Sprintf("%d", len(d.DomainHosts)) + `)</div><table><tr><th>主机名</th></tr>`
		for _, h := range d.DomainHosts {
			html += fmt.Sprintf(`<tr><td>%s</td></tr>`, h)
		}
		html += `</table>`
	}

	if len(d.DomainUsers) > 0 {
		html += `<div class="sub-title">域用户 (` + fmt.Sprintf("%d", len(d.DomainUsers)) + `)</div><table><tr><th>用户名</th></tr>`
		for _, u := range d.DomainUsers {
			html += fmt.Sprintf(`<tr><td>%s</td></tr>`, u)
		}
		html += `</table>`
	}

	if len(d.DomainGPO) > 0 {
		html += `<div class="sub-title">域组策略</div><div class="patch-list">`
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

func buildServiceDetectHTML(r *ScanResult) string {
	if len(r.Services) == 0 {
		return ""
	}
	html := `<div class="section"><div class="section-title"><span class="icon">&#128421;</span> 服务识别结果 (` + fmt.Sprintf("%d", len(r.Services)) + `)</div><div class="section-body">`
	html += `<table><tr><th>IP地址</th><th>服务类型</th><th>端口</th><th>信息</th></tr>`
	for _, s := range r.Services {
		serviceBadge := getServiceBadge(s.Type)
		html += fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>`, s.IP, serviceBadge, s.Port, s.Info)
	}
	html += `</table></div></div>`
	return html
}

func getServiceBadge(serviceType string) string {
	switch serviceType {
	case "ssh":
		return `<span class="badge badge-blue">SSH</span>`
	case "ftp":
		return `<span class="badge badge-purple">FTP</span>`
	case "telnet":
		return `<span class="badge badge-red">Telnet</span>`
	case "smtp", "smtps":
		return `<span class="badge badge-purple">SMTP</span>`
	case "dns":
		return `<span class="badge badge-blue">DNS</span>`
	case "http", "http-proxy", "https", "https-alt":
		return `<span class="badge badge-green">Web</span>`
	case "mssql":
		return `<span class="badge badge-red">MSSQL</span>`
	case "mysql":
		return `<span class="badge badge-blue">MySQL</span>`
	case "postgresql":
		return `<span class="badge badge-blue">PostgreSQL</span>`
	case "oracle":
		return `<span class="badge badge-red">Oracle</span>`
	case "redis":
		return `<span class="badge badge-red">Redis</span>`
	case "mongodb":
		return `<span class="badge badge-green">MongoDB</span>`
	case "rdp":
		return `<span class="badge badge-blue">RDP</span>`
	case "vnc":
		return `<span class="badge badge-purple">VNC</span>`
	case "netbios-ssn", "microsoft-ds":
		return `<span class="badge badge-yellow">SMB</span>`
	default:
		return `<span class="badge badge-blue">` + serviceType + `</span>`
	}
}

func buildWiFiHTML(r *ScanResult) string {
	if len(r.WiFiInfo) == 0 {
		return ""
	}
	html := `<div class="section"><div class="section-title"><span class="icon">&#128246;</span> 无线网络信息 (` + fmt.Sprintf("%d", len(r.WiFiInfo)) + `)</div><div class="section-body">`
	html += `<table><tr><th>SSID</th><th>认证方式</th><th>加密方式</th><th>信号强度</th><th>频道</th></tr>`
	for _, w := range r.WiFiInfo {
		signalLevel := getSignalLevel(w.Signal)
		html += fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s %d%%</td><td>%d</td></tr>`, w.SSID, w.Authentication, w.Encryption, signalLevel, w.Signal, w.Channel)
	}
	html += `</table></div></div>`
	return html
}

func getSignalLevel(signal int) string {
	if signal >= 80 {
		return `<span class="badge badge-green">强</span>`
	} else if signal >= 50 {
		return `<span class="badge badge-yellow">中</span>`
	} else {
		return `<span class="badge badge-red">弱</span>`
	}
}

func buildLDAPHTML(r *ScanResult) string {
	if r.LDAPInfo == nil {
		return ""
	}
	l := r.LDAPInfo
	html := `<div class="section"><div class="section-title"><span class="icon">&#128274;</span> LDAP服务信息</div><div class="section-body">`
	html += `<div class="info-grid">`
	html += infoCard("服务器名称", l.ServerName)
	html += infoCard("服务器IP", l.ServerIP)
	html += infoCard("Base DN", l.BaseDN)
	html += infoCard("域名称", l.DomainName)
	html += infoCard("Forest名称", l.ForestName)
	html += infoCard("LDAP版本", l.LDAPVersion)
	html += `</div></div></div>`
	return html
}