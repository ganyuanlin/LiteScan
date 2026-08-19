package scanner

import (
	"LiteScan/report"
	"LiteScan/utils"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

func ScanSMB(targets []string, threadCount int) []report.SMBHostInfo {
	results := make(chan report.SMBHostInfo, len(targets))
	sem := make(chan struct{}, threadCount)

	var wg sync.WaitGroup

	for _, ip := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-sem }()

			info := querySMB(targetIP)
			results <- info
		}(ip)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var infos []report.SMBHostInfo
	for info := range results {
		infos = append(infos, info)
	}

	return infos
}

func querySMB(ip string) report.SMBHostInfo {
	info := report.SMBHostInfo{IP: ip}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", ip), 3*time.Second)
	if err != nil {
		info.SMBEnabled = false
		return info
	}
	conn.Close()
	info.SMBEnabled = true

	osVer := probeSMBOS(ip)
	info.OSVersion = osVer

	shares, anonymous := enumShares(ip)
	info.Shares = shares
	info.AnonymousAccess = anonymous

	info.SMBSigning = CheckSMBSigning(ip)
	info.SMBVersion = detectSMBVersion(ip)

	return info
}

func probeSMBOS(ip string) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", ip), 3*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	negotiateRequest := buildSMBNegotiateRequest()
	_, err = conn.Write(negotiateRequest)
	if err != nil {
		return ""
	}

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil || n < 40 {
		return ""
	}

	return parseSMBOSVersion(resp[:n])
}

func buildSMBNegotiateRequest() []byte {
	buf := make([]byte, 0)

	buf = append(buf, 0x00)
	buf = append(buf, 0x00, 0x00)

	smbHeader := []byte{
		0xFF, 0x53, 0x4D, 0x42, 0x72,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
	buf = append(buf, smbHeader...)

	dialects := []string{"NT LM 0.12"}
	paramBlock := make([]byte, 0)
	paramBlock = append(paramBlock, byte(len(dialects)))
	for _, d := range dialects {
		paramBlock = append(paramBlock, 0x02)
		paramBlock = append(paramBlock, []byte(d)...)
		paramBlock = append(paramBlock, 0x00)
	}

	buf = append(buf, 0x00, 0x00)
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(smbHeader)+len(paramBlock)+2))

	buf = append(buf, paramBlock...)

	return buf
}

func parseSMBOSVersion(resp []byte) string {
	if len(resp) < 40 {
		return ""
	}

	if resp[4] == 0xFF && resp[5] == 0x53 && resp[6] == 0x4D && resp[7] == 0x42 {
		if len(resp) > 70 {
			osStr := extractOSString(resp)
			if osStr != "" {
				return osStr
			}
		}

		if len(resp) > 73 {
			major := resp[72]
			minor := resp[73]
			return smbVersionToString(major, minor)
		}
	}

	return ""
}

func extractOSString(resp []byte) string {
	if len(resp) < 80 {
		return ""
	}

	str := string(resp[40:])
	idx := strings.Index(str, "Windows")
	if idx == -1 {
		idx = strings.Index(str, "windows")
	}
	if idx != -1 {
		end := idx
		for end < len(str) && str[end] != 0 && str[end] != '\n' && str[end] != '\r' {
			end++
		}
		result := strings.TrimSpace(str[idx:end])
		if len(result) > 0 && len(result) < 80 {
			return result
		}
	}

	return ""
}

func smbVersionToString(major, minor byte) string {
	switch major {
	case 6:
		switch minor {
		case 0:
			return "Windows Vista/Server 2008"
		case 1:
			return "Windows 7/Server 2008 R2"
		}
	case 10:
		switch minor {
		case 0:
			return "Windows 10/Server 2016/2019/2022"
		}
	case 5:
		switch minor {
		case 0:
			return "Windows 2000"
		case 1:
			return "Windows XP"
		case 2:
			return "Windows Server 2003"
		}
	}
	return fmt.Sprintf("Windows (SMB %d.%d)", major, minor)
}

func enumShares(ip string) ([]string, bool) {
	output, err := utils.RunCmd("net", "view", fmt.Sprintf("\\\\%s", ip))
	if err != nil {
		return nil, false
	}

	var shares []string
	shareRegex := regexp.MustCompile(`^\s*(\S+)\s+`)
	lines := strings.Split(output, "\n")
	inShareSection := false

	for _, line := range lines {
		if strings.Contains(line, "共享名") || strings.Contains(line, "Share name") {
			inShareSection = true
			continue
		}
		if inShareSection && strings.Contains(line, "---") {
			continue
		}
		if inShareSection && strings.TrimSpace(line) == "" {
			if len(shares) > 0 {
				break
			}
			continue
		}
		if inShareSection {
			matches := shareRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				name := matches[1]
				if name != "The" && name != "命令" && !strings.HasPrefix(name, "---") {
					shares = append(shares, name)
				}
			}
		}
	}

	anonymous := checkAnonymousAccess(ip)

	return shares, anonymous
}

func checkAnonymousAccess(ip string) bool {
	output, err := utils.RunCmd("net", "use", fmt.Sprintf("\\\\%s\\IPC$", ip), "/user:\"\"","\"")
	if err != nil {
		return false
	}

	if strings.Contains(output, "错误") || strings.Contains(output, "Error") ||
		strings.Contains(output, "拒绝") || strings.Contains(output, "denied") {
		return false
	}

	utils.RunCmd("net", "use", fmt.Sprintf("\\\\%s\\IPC$", ip), "/delete", "/y")

	return true
}

func detectSMBVersion(ip string) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", ip), 3*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	smb2Negotiate := buildSMB2NegotiateRequest()
	_, err = conn.Write(smb2Negotiate)
	if err != nil {
		return "SMBv1"
	}

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil || n < 64 {
		return "SMBv1"
	}

	if resp[4] == 0xFE && resp[5] == 0x53 && resp[6] == 0x4D && resp[7] == 0x42 {
		if n > 72 {
			dialectRev := binary.LittleEndian.Uint16(resp[68:70])
			switch dialectRev {
			case 0x0202:
				return "SMB 2.0.2"
			case 0x0210:
				return "SMB 2.1"
			case 0x0300:
				return "SMB 3.0"
			case 0x0302:
				return "SMB 3.0.2"
			case 0x0311:
				return "SMB 3.1.1"
			default:
				return fmt.Sprintf("SMB 2.x (dialect=0x%04x)", dialectRev)
			}
		}
		return "SMB 2.x"
	}

	return "SMBv1"
}

func buildSMB2NegotiateRequest() []byte {
	buf := make([]byte, 0, 128)

	buf = append(buf, 0x00)
	buf = append(buf, 0x00, 0x00)

	smb2Header := []byte{
		0xFE, 0x53, 0x4D, 0x42, 0x72,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	buf = append(buf, smb2Header...)

	creditCharge := []byte{0x01, 0x00}
	buf = append(buf, creditCharge...)

	status := []byte{0x00, 0x00, 0x00, 0x00}
	buf = append(buf, status...)

	command := []byte{0x00, 0x00}
	buf = append(buf, command...)

	creditReq := []byte{0x01, 0x00}
	buf = append(buf, creditReq...)

	creditResp := []byte{0x00, 0x00}
	buf = append(buf, creditResp...)

	flags := []byte{0x00, 0x00, 0x00, 0x00}
	buf = append(buf, flags...)

	nextCommand := []byte{0x00, 0x00, 0x00, 0x00}
	buf = append(buf, nextCommand...)

	messageId := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	buf = append(buf, messageId...)

	processId := []byte{0x00, 0x00, 0x00, 0x00}
	buf = append(buf, processId...)

	treeId := []byte{0x00, 0x00, 0x00, 0x00}
	buf = append(buf, treeId...)

	sessionId := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	buf = append(buf, sessionId...)

	signature := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	buf = append(buf, signature...)

	structSize := []byte{0x24, 0x00}
	buf = append(buf, structSize...)

	dialectCount := []byte{0x03, 0x00}
	buf = append(buf, dialectCount...)

	securityMode := []byte{0x01, 0x00}
	buf = append(buf, securityMode...)

	reserved := []byte{0x00, 0x00}
	buf = append(buf, reserved...)

	capabilities := []byte{0x00, 0x00, 0x00, 0x00}
	buf = append(buf, capabilities...)

	clientGuid := make([]byte, 16)
	buf = append(buf, clientGuid...)

	negotiateContextOffset := []byte{0x00, 0x00}
	buf = append(buf, negotiateContextOffset...)

	negotiateContextCount := []byte{0x00, 0x00}
	buf = append(buf, negotiateContextCount...)

	reserved2 := []byte{0x00, 0x00}
	buf = append(buf, reserved2...)

	dialect0202 := []byte{0x02, 0x02}
	buf = append(buf, dialect0202...)

	dialect0210 := []byte{0x10, 0x02}
	buf = append(buf, dialect0210...)

	dialect0300 := []byte{0x00, 0x03}
	buf = append(buf, dialect0300...)

	totalLen := uint16(len(buf) - 3)
	binary.BigEndian.PutUint16(buf[1:3], totalLen)

	return buf
}