package utils

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"
)

func ParseTarget(target string) ([]string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("目标不能为空")
	}

	parts := strings.Split(target, ",")
	var allIPs []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "/") {
			ips, err := parseCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("解析CIDR %s 失败: %v", part, err)
			}
			allIPs = append(allIPs, ips...)
		} else {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("无效IP: %s", part)
			}
			if ip.To4() != nil {
				allIPs = append(allIPs, ip.To4().String())
			}
		}
	}

	return allIPs, nil
}

func parseCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("仅支持IPv4")
	}

	maskSize, _ := ipnet.Mask.Size()
	if maskSize < 16 {
		return nil, fmt.Errorf("网段过大（最小/16），请缩小范围")
	}

	networkIP := ip.Mask(ipnet.Mask)
	broadcastIP := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcastIP[i] = networkIP[i] | ^ipnet.Mask[i]
	}

	var ips []string
	start := ipToUint(networkIP) + 1
	end := ipToUint(broadcastIP) - 1
	count := end - start + 1

	if count > 1024 {
		return nil, fmt.Errorf("IP数量超过1024限制（当前%d），请缩小范围", count)
	}

	for i := start; i <= end; i++ {
		ips = append(ips, uintToIP(i).String())
	}

	return ips, nil
}

func ipToUint(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
}

func uintToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

func IPToCIDR(ipStr, maskStr string) string {
	ip := net.ParseIP(ipStr)
	mask := net.ParseIP(maskStr)
	if ip == nil || mask == nil {
		return ""
	}

	ip = ip.To4()
	mask = mask.To4()
	if ip == nil || mask == nil {
		return ""
	}

	ones := 0
	for _, b := range mask {
		for i := 7; i >= 0; i-- {
			if b&uint8(math.Pow(2, float64(i))) != 0 {
				ones++
			} else {
				break
			}
		}
	}

	network := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		network[i] = ip[i] & mask[i]
	}

	return fmt.Sprintf("%s/%d", network.String(), ones)
}

func DeduplicateStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}