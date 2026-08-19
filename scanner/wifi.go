package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"LiteScan/report"
	"LiteScan/utils"
)

func ScanWiFi() []report.WiFiInfo {
	var wifiList []report.WiFiInfo

	output, err := utils.RunCmd("netsh", "wlan show networks mode=bssid")
	if err != nil || output == "" {
		return wifiList
	}

	lines := strings.Split(output, "\n")
	var currentSSID string
	var currentAuth string
	var currentEncr string

	ssidRe := regexp.MustCompile(`^\s*SSID\s+\d+\s*:\s*(.+)$`)
	authRe := regexp.MustCompile(`^\s*Authentication\s*:\s*(.+)$`)
	encrRe := regexp.MustCompile(`^\s*Encryption\s*:\s*(.+)$`)
	signalRe := regexp.MustCompile(`^\s*Signal\s*:\s*(\d+)%`)
	channelRe := regexp.MustCompile(`^\s*Channel\s*:\s*(\d+)`)

	var signal, channel int

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := ssidRe.FindStringSubmatch(line); match != nil {
			if currentSSID != "" && currentSSID != "" {
				wifiList = append(wifiList, report.WiFiInfo{
					SSID:           currentSSID,
					Authentication: currentAuth,
					Encryption:     currentEncr,
					Signal:         signal,
					Channel:        channel,
				})
			}
			currentSSID = strings.TrimSpace(match[1])
			currentAuth = ""
			currentEncr = ""
			signal = 0
			channel = 0
			continue
		}

		if match := authRe.FindStringSubmatch(line); match != nil {
			currentAuth = strings.TrimSpace(match[1])
			continue
		}

		if match := encrRe.FindStringSubmatch(line); match != nil {
			currentEncr = strings.TrimSpace(match[1])
			continue
		}

		if match := signalRe.FindStringSubmatch(line); match != nil {
			fmt.Sscanf(match[1], "%d", &signal)
			continue
		}

		if match := channelRe.FindStringSubmatch(line); match != nil {
			fmt.Sscanf(match[1], "%d", &channel)
			continue
		}
	}

	if currentSSID != "" {
		wifiList = append(wifiList, report.WiFiInfo{
			SSID:           currentSSID,
			Authentication: currentAuth,
			Encryption:     currentEncr,
			Signal:         signal,
			Channel:        channel,
		})
	}

	return wifiList
}