package events

import "time"

type AuthRequest struct {
	NasIp           string             `json:"nas_ip" yaml:"nas_ip"`
	NasName         string             `json:"nas_name" yaml:"nas_name"`
	DeviceMac       string             `json:"device_mac"`
	DhcpServerName  string             `json:"dhcp_server_name"`
	DhcpServerId    string             `json:"dhcp_server_id"`
	AgentOption     *AuthRequestOption `json:"option"`
	FramedIpAddress string             `json:"ip_address"`
	Class           string             `json:"class_id"`
}

type AuthRequestOption struct {
	RemoteId     string `json:"remote_id"`
	RawCircuitId string `json:"circuit_id"`
}

type AuthResponse struct {
	Time            time.Time         `json:"-"`
	IpAddress       string            `json:"ip_address"`
	PoolName        string            `json:"pool_name"`
	LeaseTimeSec    int               `json:"lease_time_sec"`
	Status          string            `json:"status"`
	Error           string            `json:"error"`
	Class           string            `json:"class_id"`
	ExtraAttributes map[string]string `json:"extra_attributes"`
}
