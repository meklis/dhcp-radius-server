package radius

import (
	"fmt"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const (
	vendorMikrotik uint32 = 14988
	vendorRedback  uint32 = 2352
)

// attrInfo with VendorID 0 is a standard attribute, otherwise a vendor-specific one.
type attrInfo struct {
	VendorID uint32
	Type     byte
}

// attrTypes lists string attributes only. MikroTik types match dictionary.mikrotik
// from FreeRADIUS, Redback types match the generated radius/redback package.
var attrTypes = map[string]attrInfo{
	"Reply-Message": {0, byte(rfc2865.ReplyMessage_Type)},

	"Mikrotik-Group":                  {vendorMikrotik, 3},
	"Mikrotik-Wireless-Enc-Key":       {vendorMikrotik, 7},
	"Mikrotik-Rate-Limit":             {vendorMikrotik, 8},
	"Mikrotik-Realm":                  {vendorMikrotik, 9},
	"Mikrotik-Mark-Id":                {vendorMikrotik, 11},
	"Mikrotik-Advertise-URL":          {vendorMikrotik, 12},
	"Mikrotik-Wireless-PSK":           {vendorMikrotik, 16},
	"Mikrotik-Address-List":           {vendorMikrotik, 19},
	"Mikrotik-Wireless-MPKey":         {vendorMikrotik, 20},
	"Mikrotik-Wireless-Comment":       {vendorMikrotik, 21},
	"Mikrotik-Delegated-IPv6-Pool":    {vendorMikrotik, 22},
	"Mikrotik-DHCP-Option-Set":        {vendorMikrotik, 23},
	"Mikrotik-DHCP-Option-Param-STR1": {vendorMikrotik, 24},
	"Mikrotik-DHCP-Option-ParamSTR2":  {vendorMikrotik, 25},
	"Mikrotik-Wireless-Minsignal":     {vendorMikrotik, 28},
	"Mikrotik-Wireless-Maxsignal":     {vendorMikrotik, 29},
	"Mikrotik-Switching-Filter":       {vendorMikrotik, 30},

	"Redback-Context-Name": {vendorRedback, 4},
}

// setExtraAttribute sets a string attribute by name, see attrTypes.
func setExtraAttribute(p *radius.Packet, name, value string) error {
	info, ok := attrTypes[name]
	if !ok {
		return fmt.Errorf("unknown attribute %q", name)
	}
	attr, err := radius.NewString(value)
	if err != nil {
		return err
	}
	if info.VendorID == 0 {
		p.Set(radius.Type(info.Type), attr)
		return nil
	}
	vendorAttr := make(radius.Attribute, 2+len(attr))
	vendorAttr[0] = info.Type
	vendorAttr[1] = byte(len(vendorAttr))
	copy(vendorAttr[2:], attr)
	vsa, err := radius.NewVendorSpecific(info.VendorID, vendorAttr)
	if err != nil {
		return err
	}
	p.Add(rfc2865.VendorSpecific_Type, vsa)
	return nil
}
