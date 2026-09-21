package events

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

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

func (r *AuthRequest) GetHash() string {
	arrBytes := []byte{}
	r.Class = ""
	jsonBytes, _ := json.Marshal(r)
	arrBytes = append(arrBytes, jsonBytes...)
	return fmt.Sprintf("%x", md5.Sum(arrBytes))
}

type AuthResponse struct {
	Time         time.Time `json:"-"`
	IpAddress    string    `json:"ip_address"`
	PoolName     string    `json:"pool_name"`
	LeaseTimeSec int       `json:"lease_time_sec"`
	Status       string    `json:"status"`
	Error        string    `json:"error"`
	Class        string    `json:"class_id"`
	// ExtraAttributes - дополнительные RADIUS-атрибуты в ответ, полное имя
	// (например "Mikrotik-Address-List") -> значение. Список поддерживаемых
	// имён см. attrTypes.
	ExtraAttributes map[string]string `json:"extra_attributes"`
}

type RadiusResponseType int

const SetPool RadiusResponseType = 1
const SetIpAddress RadiusResponseType = 2

func (r *AuthResponse) GetRadiusResponseType() RadiusResponseType {
	if r.IpAddress != "" {
		return SetIpAddress
	} else {
		return SetPool
	}
}
func (r *AuthResponse) GetIp() net.IP {
	return net.ParseIP(r.IpAddress)
}
