package radius

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// attrNames covers the attributes NASes actually send us; others print as numbers.
var attrNames = map[radius.Type]string{
	1: "User-Name", 4: "NAS-IP-Address", 5: "NAS-Port", 6: "Service-Type",
	8: "Framed-IP-Address", 25: "Class", 30: "Called-Station-Id", 31: "Calling-Station-Id",
	32: "NAS-Identifier", 40: "Acct-Status-Type", 44: "Acct-Session-Id", 55: "Event-Timestamp",
	61: "NAS-Port-Type", 80: "Message-Authenticator", 87: "NAS-Port-Id", 88: "Framed-Pool",
}

var ipAttrs = map[radius.Type]bool{4: true, 8: true}

var vendorNames = map[uint32]string{2352: "Redback", 14988: "Mikrotik", 9: "Cisco"}

var vsaNames = map[uint32]map[byte]string{
	2352: {96: "Agent-Remote-Id", 97: "Agent-Circuit-Id"},
}

// packetDump prints every attribute of a packet. It implements fmt.Stringer
// so the work is only done when the log line is actually written.
type packetDump struct{ p *radius.Packet }

func (d packetDump) String() string {
	types := make([]int, 0, len(d.p.Attributes))
	for t := range d.p.Attributes {
		types = append(types, int(t))
	}
	sort.Ints(types)

	var parts []string
	for _, ti := range types {
		t := radius.Type(ti)
		for _, a := range d.p.Attributes[t] {
			if t == rfc2865.VendorSpecific_Type {
				parts = append(parts, dumpVSA(a)...)
				continue
			}
			name, ok := attrNames[t]
			if !ok {
				name = fmt.Sprintf("Attr-%d", t)
			}
			val := dumpValue(a)
			if ipAttrs[t] && len(a) == 4 {
				val = net.IP(a).String()
			}
			parts = append(parts, name+"="+val)
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func dumpVSA(a radius.Attribute) []string {
	vendorID, vsa, err := radius.VendorSpecific(a)
	if err != nil {
		return []string{"Vendor-Specific=" + dumpValue(a)}
	}
	vendor, ok := vendorNames[vendorID]
	if !ok {
		vendor = fmt.Sprintf("Vendor-%d", vendorID)
	}
	var parts []string
	for len(vsa) >= 3 {
		typ, l := vsa[0], int(vsa[1])
		if l < 3 || l > len(vsa) {
			break
		}
		name, ok := vsaNames[vendorID][typ]
		if !ok {
			name = fmt.Sprintf("%d", typ)
		}
		parts = append(parts, vendor+"."+name+"="+dumpValue(vsa[2:l]))
		vsa = vsa[l:]
	}
	if len(vsa) > 0 {
		parts = append(parts, vendor+".raw="+dumpValue(vsa))
	}
	return parts
}

// dumpValue quotes printable values and hex-encodes the rest.
func dumpValue(b []byte) string {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return fmt.Sprintf("0x%X", b)
		}
	}
	return fmt.Sprintf("%q", b)
}
