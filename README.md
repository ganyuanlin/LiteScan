<div align="center">

# 🔍 LiteScan

**内网轻量级信息收集工具**

[![Version](https://img.shields.io/badge/version-2.1.0-00d4ff.svg?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48dGV4dCB5PSI2MCIgZm9udC1zaXplPSI2MCIgZmlsbD0iIzAwZDRmZiI+8J+OrTwvdGV4dD48L3N2Zz4=)](https://github.com/ganyuanlin/LiteScan)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8.svg?style=flat-square&logo=go)](https://go.dev/)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D4.svg?style=flat-square&logo=windows)](https://github.com/ganyuanlin/LiteScan)
[![License](https://img.shields.io/badge/license-MIT-F7DF1E.svg?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/ganyuanlin/LiteScan?color=FFD700&style=flat-square&logo=github)](https://github.com/ganyuanlin/LiteScan/stargazers)

[功能特性](#-功能特性) • [快速开始](#-快速开始) • [使用方法](#-使用方法) • [报告展示](#-报告展示) • [项目结构](#-项目结构)

</div>

---

> ⚠️ **免责声明**：本工具仅用于**授权安全测试**，禁止用于任何非法用途。使用本工具即表示您同意遵守当地法律法规。

## ✨ 功能特性

<table>
<tr>
<td width="50%">

### 🌐 网络探测
- **存活探测** — ICMP Ping + TCP 135/445 双重探测
- **NetBIOS** — 主机名 / 工作组 / 域 / 设备类型
- **SMB 探测** — OS 版本 / 共享 / 匿名访问 / 签名状态 / SMB 版本
- **ARP 扫描** — ARP 缓存表解析，发现更多内网主机

</td>
<td width="50%">

### 🔒 安全检测
- **端口扫描** — 33 个常见端口 + 自定义范围 + Banner 抓取
- **服务识别** — 自动识别 SSH/FTP/MySQL/MSSQL/Redis 等 25+ 种服务
- **漏洞检测** — MS17-010 永恒之蓝深度检测
- **风险统计** — 自动汇总各类高危服务、漏洞风险

### 🌐 服务探测
- **服务识别** — 自动识别并获取 Banner 信息
- **WiFi 扫描** — 收集附近无线网络信息
- **LDAP 扫描** — 域环境 LDAP 服务器发现

</td>
</tr>
<tr>
<td width="50%">

### 💻 本机信息
- 主机 / 网络 / 端口 / 补丁 / 防火墙
- 密码策略 / 共享 / 计划任务 / 进程
- 自动检测域 / 工作组环境

</td>
<td width="50%">

### 📋 域信息
- 域控 IP / 主机名 / 域权限
- 域用户 / 域主机 / 组策略

</td>
</tr>
</table>

### 🎯 技术亮点

| 特性 | 说明 |
|:---:|:---|
| 🚀 **零依赖** | 纯 Go 标准库实现，无需任何第三方依赖 |
| 📦 **单文件** | 编译为单个 exe，即开即用无需安装 |
| ⚡ **高并发** | 可配置线程数（1-50），快速扫描 |
| 🔤 **GBK 解码** | 正确处理 Windows 中文命令输出 |
| 🪟 **隐藏窗口** | 所有子进程隐藏 CMD 窗口 |
| 📊 **双格式报告** | JSON 数据 + 暗色主题 HTML 可视化报告 |
| 🖥️ **交互模式** | 支持 REPL 交互式逐 IP / CIDR 探测 |

---

## 🚀 快速开始

### 编译

```bash
# 克隆仓库
git clone https://github.com/ganyuanlin/LiteScan.git
cd LiteScan

# 编译
go build -o LiteScan.exe main.go
```

### 直接使用

下载 [Release](https://github.com/ganyuanlin/LiteScan/releases) 中的预编译版本，直接运行即可。

---

## 📖 使用方法

### 基础扫描

```bash
# 默认模式：本机信息 + 自动网段探测
LiteScan.exe

# 扫描指定 C 段
LiteScan.exe -t 192.168.1.0/24

# 扫描多个目标
LiteScan.exe -t 192.168.1.1,192.168.2.0/24

# 仅采集本机信息
LiteScan.exe --local
```

### 扩展模块

```bash
# 启用端口扫描（常见端口）
LiteScan.exe -t 192.168.1.0/24 --ps

# 自定义端口扫描
LiteScan.exe -t 192.168.1.0/24 -p 80,443,445,3389,8080
LiteScan.exe -t 192.168.1.0/24 -p 1-1000

# 启用漏洞检测（MS17-010）
LiteScan.exe -t 192.168.1.0/24 --vuln

# 启用 ARP 表扫描
LiteScan.exe -t 192.168.1.0/24 --arp

# 强制采集域信息
LiteScan.exe --domain
```

### 交互式探测

```bash
LiteScan.exe --probe
```

进入交互模式后，支持以下命令：

| 命令 | 说明 |
|:---|:---|
| `192.168.1.1` | 探测单个 IP |
| `192.168.1.0/24` | 探测网段 |
| `192.168.1.1,192.168.1.2` | 逗号分隔多目标 |
| `ps` | 端口扫描存活主机（常见端口） |
| `ps 80,443,3389` | 端口扫描（自定义端口） |
| `ps 1-1000` | 端口扫描（端口范围） |
| `vuln` | 漏洞检测存活主机 |
| `arp` | 扫描 ARP 表 |
| `list` / `ls` | 查看已探测记录 |
| `report` | 生成报告 |
| `clear` / `reset` | 清空探测记录 |
| `q` / `quit` | 退出（自动生成报告） |

### 完整参数

| 参数 | 长格式 | 说明 | 默认值 |
|:---:|:---:|:---|:---:|
| `-t` | `--target` | 扫描目标网段 / IP | — |
| `-th` | `--thread` | 扫描线程数 | `20` |
| `-o` | `--out` | 报告输出路径 | 当前目录 |
| `-p` | `--ports` | 自定义扫描端口 | — |
| | `--local` | 仅采集本机信息 | `false` |
| | `--domain` | 强制采集域信息 | `false` |
| | `--probe` | 交互式探测模式 | `false` |
| | `--ps` / `--portscan` | 启用端口扫描 | `false` |
| | `--arp` | 启用 ARP 表扫描 | `false` |
| | `--vuln` | 启用漏洞检测 | `false` |
| | `--timeout` | 连接超时秒数 | `3` |
| | `--silent` | 静默模式 | `false` |
| `-h` | `--help` | 帮助文档 | — |

---

## 📊 报告展示

扫描完成后在输出目录生成：

- 📄 `scan_result.json` — JSON 格式完整数据
- 🌐 `scan_report.html` — 暗色主题可视化 HTML 报告

<details>
<summary>📋 HTML 报告包含内容</summary>

- **扫描概览** — 时间 / 目标 / 线程 / 环境
- **本机基础信息** — 主机 / 网络 / 端口 / 补丁 / 防火墙 / 密码策略 / 共享 / 计划任务 / 进程
- **存活主机资产总表**
- **ARP 表记录**
- **NetBIOS 信息汇总**
- **SMB 服务与共享资产**
- **端口扫描结果**
- **漏洞检测结果**
- **域环境信息**
- **风险简要统计**

</details>

### 风险检测项

| 风险项 | 检测方式 | 风险等级 |
|:---|:---|:---:|
| 445 端口开放 | 存活探测端口扫描 | 🔴 高 |
| 匿名 SMB 访问 | IPC$ 空连接测试 | 🔴 高 |
| MS17-010 漏洞 | SMBv1 协商 + IPC$ 连接深度检测 | 🔴 高 |
| 3389 端口开放 | 存活探测端口扫描 | 🟡 中 |
| SMB 签名未启用 | SMB 协商安全模式解析 | 🟡 中 |

---

## 📁 项目结构

```
LiteScan/
├── main.go                 # 主入口，命令行解析，流程控制
├── go.mod                  # Go 模块定义
│
├── scanner/                # 扫描模块
│   ├── alive.go            # 存活主机探测
│   ├── netbios.go          # NetBIOS 信息采集
│   ├── smb.go              # SMB 信息采集（含 SMBv2 协商）
│   ├── portscan.go         # 端口扫描 + 服务识别 + Banner 抓取
│   ├── arp.go              # ARP 表扫描
│   ├── vuln.go             # 漏洞检测（MS17-010）+ SMB 签名检测
│   ├── local.go            # 本机信息采集
│   ├── domain.go           # 域信息采集
│   └── probe.go            # 交互式探测
│
├── report/                 # 报告模块
│   ├── types.go            # 数据结构定义
│   └── report.go           # 报告生成（JSON + HTML）
│
└── utils/                  # 工具模块
    ├── cmd.go              # 命令执行 + GBK 解码
    └── network.go          # 网络工具函数
```

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 提交 Pull Request

---

## 📜 License

本项目基于 [MIT License](LICENSE) 开源。

<div align="center">

**如果这个项目对你有帮助，请给个 ⭐ Star 支持一下！**

</div>