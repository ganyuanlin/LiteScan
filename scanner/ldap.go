package scanner

import (
	"LiteScan/report"
	"fmt"
	"net"
	"strings"
	"time"
)

func ScanLDAP(domain string) *report.LDAPInfo {
	var ldapHost string
	var ldapPort int = 389

	if domain == "" {
		ips, _ := net.LookupIP("_ldap._tcp")
		for _, ip := range ips {
			ldapHost = ip.String()
			break
		}
	} else {
		ips, _ := net.LookupIP("_ldap._tcp." + domain)
		for _, ip := range ips {
			ldapHost = ip.String()
			break
		}
		if ldapHost == "" {
			ips, _ = net.LookupIP(domain)
			for _, ip := range ips {
				if ip.To4() != nil {
					ldapHost = ip.String()
					break
				}
			}
		}
	}

	if ldapHost == "" {
		return nil
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ldapHost, ldapPort), 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	return &report.LDAPInfo{
		ServerName: ldapHost,
		ServerIP:   ldapHost,
		BaseDN:     fmt.Sprintf("DC=%s", extractBaseDN(domain)),
		DomainName: domain,
		LDAPVersion: "3",
	}
}

func extractBaseDN(domain string) string {
	if domain == "" {
		return "domain"
	}
	parts := strings.Split(domain, ".")
	var dcParts []string
	for _, part := range parts {
		dcParts = append(dcParts, part)
	}
	return strings.Join(dcParts, ",DC=")
}