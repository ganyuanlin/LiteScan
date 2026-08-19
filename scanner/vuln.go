package scanner

import (
	"LiteScan/report"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

func ScanMS17010(targets []string, threadCount int) []report.VulnResult {
	results := make(chan report.VulnResult, len(targets))
	sem := make(chan struct{}, threadCount)

	var wg sync.WaitGroup

	for _, ip := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-sem }()

			vuln := checkMS17010(targetIP)
			if vuln != nil {
				results <- *vuln
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var vulns []report.VulnResult
	for v := range results {
		vulns = append(vulns, v)
	}

	return vulns
}

func checkMS17010(ip string) *report.VulnResult {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", ip), 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	negotiateReq := buildSMB1NegotiateRequest()
	_, err = conn.Write(negotiateReq)
	if err != nil {
		return nil
	}

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil || n < 40 {
		return nil
	}

	if resp[4] != 0xFF || resp[5] != 0x53 || resp[6] != 0x4D || resp[7] != 0x42 {
		return nil
	}

	if resp[9] != 0x72 {
		return nil
	}

	dialectIndex := binary.LittleEndian.Uint16(resp[41:43])

	treeConnectReq := buildTreeConnectIPC(ip, dialectIndex)
	_, err = conn.Write(treeConnectReq)
	if err != nil {
		return &report.VulnResult{
			IP:       ip,
			VulnID:   "MS17-010",
			VulnName: "永恒之蓝(EternalBlue)",
			Severity: "unknown",
			Detail:   "SMB服务开放，无法完成深度检测（IPC$连接失败）",
		}
	}

	n, err = conn.Read(resp)
	if err != nil || n < 4 {
		return &report.VulnResult{
			IP:       ip,
			VulnID:   "MS17-010",
			VulnName: "永恒之蓝(EternalBlue)",
			Severity: "unknown",
			Detail:   "SMB服务开放，无法完成深度检测",
		}
	}

	if resp[4] == 0xFF && resp[5] == 0x53 && resp[6] == 0x4D && resp[7] == 0x42 {
		smbStatus := binary.LittleEndian.Uint32(resp[9:13])
		if smbStatus == 0 {
			return &report.VulnResult{
				IP:       ip,
				VulnID:   "MS17-010",
				VulnName: "永恒之蓝(EternalBlue)",
				Severity: "high",
				Detail:   "SMBv1服务开放且IPC$可连接，可能存在MS17-010漏洞",
			}
		}
	}

	return &report.VulnResult{
		IP:       ip,
		VulnID:   "MS17-010",
		VulnName: "永恒之蓝(EternalBlue)",
		Severity: "medium",
		Detail:   "SMBv1服务开放，需进一步验证MS17-010补丁状态",
	}
}

func buildSMB1NegotiateRequest() []byte {
	buf := make([]byte, 0, 128)

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

	dialects := [][]byte{
		[]byte{0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00},
	}

	paramBlock := []byte{0x00}
	for _, d := range dialects {
		paramBlock = append(paramBlock, d...)
	}

	buf = append(buf, paramBlock...)

	totalLen := uint16(len(buf) - 3)
	binary.BigEndian.PutUint16(buf[1:3], totalLen)

	return buf
}

func buildTreeConnectIPC(ip string, dialectIndex uint16) []byte {
	buf := make([]byte, 0, 256)

	buf = append(buf, 0x00)
	buf = append(buf, 0x00, 0x00)

	smbHeader := []byte{
		0xFF, 0x53, 0x4D, 0x42, 0x75,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	buf = append(buf, smbHeader...)

	buf = append(buf, byte(dialectIndex), 0x00)

	path := fmt.Sprintf("\\\\%s\\IPC$", ip)
	pathBytes := []byte(path)
	pathBytes = append(pathBytes, 0x00)

	service := "?????"
	serviceBytes := []byte(service)
	serviceBytes = append(serviceBytes, 0x00)

	buf = append(buf, 0x00, 0x00)
	buf = append(buf, 0x0A, 0x00)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, byte(len(pathBytes)), 0x00)
	buf = append(buf, byte(len(serviceBytes)), 0x00)
	buf = append(buf, pathBytes...)
	buf = append(buf, serviceBytes...)

	totalLen := uint16(len(buf) - 3)
	binary.BigEndian.PutUint16(buf[1:3], totalLen)

	return buf
}

func CheckSMBSigning(ip string) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", ip), 3*time.Second)
	if err != nil {
		return "N/A"
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	negotiateReq := buildSMB1NegotiateRequest()
	_, err = conn.Write(negotiateReq)
	if err != nil {
		return "N/A"
	}

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil || n < 73 {
		return "N/A"
	}

	if resp[4] == 0xFF && resp[5] == 0x53 && resp[6] == 0x4D && resp[7] == 0x42 {
		if n > 73 {
			securityMode := resp[73]
			if securityMode&0x02 != 0 {
				if securityMode&0x04 != 0 {
					return "required"
				}
				return "enabled"
			}
			return "disabled"
		}
	}

	return "unknown"
}