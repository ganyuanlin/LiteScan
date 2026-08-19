package report

type ScanResult struct {
	StartTime  string        `json:"start_time"`
	EndTime    string        `json:"end_time"`
	Duration   string        `json:"duration"`
	Target     string        `json:"target"`
	Threads    int           `json:"threads"`
	Version    string        `json:"version"`
	IsDomain   bool          `json:"is_domain"`
	LocalInfo  *LocalInfo    `json:"local_info,omitempty"`
	AliveHosts []AliveHost   `json:"alive_hosts,omitempty"`
	ARPHosts   []ARPHost     `json:"arp_hosts,omitempty"`
	NetBIOS    []NetBIOSInfo `json:"netbios_info,omitempty"`
	SMBInfo    []SMBHostInfo `json:"smb_info,omitempty"`
	PortScan   []PortScanResult `json:"port_scan,omitempty"`
	Services   []ServiceDetectResult `json:"services,omitempty"`
	WiFiInfo   []WiFiInfo    `json:"wifi_info,omitempty"`
	LDAPInfo   *LDAPInfo    `json:"ldap_info,omitempty"`
	VulnInfo   []VulnResult  `json:"vuln_info,omitempty"`
	DomainInfo *DomainInfo   `json:"domain_info,omitempty"`
	RiskStats  *RiskStats    `json:"risk_stats,omitempty"`
}

type LocalInfo struct {
	Hostname       string        `json:"hostname"`
	Workgroup      string        `json:"workgroup"`
	DomainName     string        `json:"domain_name"`
	IsDomainEnv    bool          `json:"is_domain_env"`
	OSVersion      string        `json:"os_version"`
	Adapters       []Adapter     `json:"adapters"`
	OpenPorts      []PortInfo    `json:"open_ports"`
	CurrentUser    string        `json:"current_user"`
	AdminUsers     []string      `json:"admin_users"`
	RouteTable     []string      `json:"route_table"`
	SystemPatches  []string      `json:"system_patches"`
	PasswordPolicy *PasswordPolicy `json:"password_policy,omitempty"`
	FirewallStatus string        `json:"firewall_status"`
	SharedFolders  []string      `json:"shared_folders"`
	UserSessions   []string      `json:"user_sessions"`
	StartupItems   []string      `json:"startup_items"`
	ScheduledTasks []string      `json:"scheduled_tasks"`
	ProcessList    []ProcessInfo `json:"process_list"`
}

type PasswordPolicy struct {
	MinPasswordLen     string `json:"min_password_len"`
	MaxPasswordAge     string `json:"max_password_age"`
	MinPasswordAge     string `json:"min_password_age"`
	PasswordHistory    string `json:"password_history"`
	LockoutThreshold   string `json:"lockout_threshold"`
	LockoutDuration    string `json:"lockout_duration"`
	ComplexityEnabled  string `json:"complexity_enabled"`
}

type ProcessInfo struct {
	PID   int    `json:"pid"`
	Name  string `json:"name"`
	User  string `json:"user"`
	MemMB int    `json:"mem_mb"`
}

type Adapter struct {
	Name       string `json:"name"`
	IPAddress  string `json:"ip_address"`
	SubnetMask string `json:"subnet_mask"`
	Gateway    string `json:"gateway"`
	DNS        string `json:"dns"`
	MACAddress string `json:"mac_address"`
}

type PortInfo struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	State    string `json:"state"`
	PID      int    `json:"pid,omitempty"`
	Process  string `json:"process,omitempty"`
}

type AliveHost struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Online    bool   `json:"online"`
	OpenPorts []int  `json:"open_ports"`
	Hostname  string `json:"hostname,omitempty"`
}

type ARPHost struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Type     string `json:"type"`
	Interface string `json:"interface,omitempty"`
}

type NetBIOSInfo struct {
	IP         string `json:"ip"`
	Hostname   string `json:"hostname"`
	Workgroup  string `json:"workgroup"`
	DeviceType string `json:"device_type"`
	Status     string `json:"status"`
}

type SMBHostInfo struct {
	IP              string   `json:"ip"`
	SMBEnabled      bool     `json:"smb_enabled"`
	OSVersion       string   `json:"os_version"`
	Shares          []string `json:"shares"`
	AnonymousAccess bool     `json:"anonymous_access"`
	SMBSigning      string   `json:"smb_signing,omitempty"`
	SMBVersion      string   `json:"smb_version,omitempty"`
}

type PortScanResult struct {
	IP     string        `json:"ip"`
	Ports  []ServicePort `json:"ports"`
}

type ServicePort struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
}

type VulnResult struct {
	IP        string `json:"ip"`
	VulnID    string `json:"vuln_id"`
	VulnName  string `json:"vuln_name"`
	Severity  string `json:"severity"`
	Detail    string `json:"detail"`
}

type DomainInfo struct {
	DomainName      string   `json:"domain_name"`
	DomainCtrlIP   string   `json:"domain_controller_ip"`
	DomainCtrlName string   `json:"domain_controller_name"`
	DomainHosts    []string `json:"domain_hosts"`
	DomainUsers    []string `json:"domain_users"`
	DomainGPO      []string `json:"domain_gpo"`
	DomainPriv     string   `json:"domain_priv"`
	DomainLogin    string   `json:"domain_login"`
}

type RiskStats struct {
	Open445Count      int `json:"open_445_count"`
	AnonymousSMBCount int `json:"anonymous_smb_count"`
	Open3389Count     int `json:"open_3389_count"`
	MS17010Count      int `json:"ms17010_count"`
	WeakPasswordCount int `json:"weak_password_count"`
	SMBNoSignCount    int `json:"smb_no_sign_count"`
	OpenRDPCount     int `json:"open_rdp_count"`
	OpenSSHCount     int `json:"open_ssh_count"`
	OpenFTPCount     int `json:"open_ftp_count"`
	OpenMySQLCount   int `json:"open_mysql_count"`
	OpenMSSQLCount   int `json:"open_mssql_count"`
	OpenRedisCount   int `json:"open_redis_count"`
	OpenHTTPCount    int `json:"open_http_count"`
	OpenLDAPCount    int `json:"open_ldap_count"`
}

type ServiceDetectResult struct {
	IP     string         `json:"ip"`
	Type   string         `json:"type"`
	Port   int            `json:"port"`
	Info   string         `json:"info"`
	Banner string         `json:"banner,omitempty"`
}

type WiFiInfo struct {
	SSID           string `json:"ssid"`
	Authentication string `json:"authentication"`
	Encryption     string `json:"encryption"`
	Signal         int    `json:"signal"`
	Channel        int    `json:"channel"`
}

type LDAPInfo struct {
	ServerName      string   `json:"server_name"`
	ServerIP       string   `json:"server_ip"`
	BaseDN         string   `json:"base_dn"`
	DomainName     string   `json:"domain_name"`
	ForestName     string   `json:"forest_name"`
	DomainSID      string   `json:"domain_sid"`
	LDAPVersion    string   `json:"ldap_version"`
	RootDomainNC   string   `json:"root_domain_nc"`
	ConfigNC       string   `json:"config_nc"`
	SchemaNC       string   `json:"schema_nc"`
}