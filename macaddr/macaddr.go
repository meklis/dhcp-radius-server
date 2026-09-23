// Package macaddr keeps one MAC format across the project: AA:BB:CC:DD:EE:FF,
// so MACs from NAS, clientdb and option 82 compare as plain strings.
package macaddr

import (
	"encoding/hex"
	"strings"
)

// Normalize returns AA:BB:CC:DD:EE:FF. Input that does not hold exactly 12 hex
// digits is returned as bare upper-case hex, so broken data stays visible in logs.
func Normalize(mac string) string {
	var digits strings.Builder
	digits.Grow(len(mac))
	for _, r := range strings.ToUpper(mac) {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') {
			digits.WriteRune(r)
		}
	}
	hexStr := digits.String()
	if len(hexStr) != 12 {
		return hexStr
	}
	var b strings.Builder
	b.Grow(17)
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexStr[i : i+2])
	}
	return b.String()
}

// FromRemoteID extracts the switch MAC from the DHCP option 82 remote-id.
// Ported from remoteReader() in the legacy abills.pl with offsets shifted by one
// byte (FreeRADIUS passed hex there, we get raw bytes). Some NAS send the MAC
// as text; the 18-byte form carries trailing garbage after the MAC.
func FromRemoteID(remoteID []byte) string {
	switch len(remoteID) {
	case 17:
		if mac := Normalize(string(remoteID)); mac == strings.ToUpper(string(remoteID)) {
			return mac
		}
	case 8:
		return Normalize(hex.EncodeToString(remoteID[2:8]))
	case 6, 18:
		return Normalize(hex.EncodeToString(remoteID[0:6]))
	}
	return ""
}
