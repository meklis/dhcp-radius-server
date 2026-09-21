package extraAttributes

import (
	"testing"

	"layeh.com/radius"
)

func TestSetStringAddressList(t *testing.T) {
	p := radius.New(radius.CodeAccessAccept, []byte("secret"))
	if err := SetString(p, "Mikrotik-Address-List", "Triolan.IPTV"); err != nil {
		t.Fatalf("SetString: %v", err)
	}

	attrs := p.Attributes[26] // rfc2865.VendorSpecific_Type
	if len(attrs) != 1 {
		t.Fatalf("expected exactly one Vendor-Specific attribute, got %v", len(attrs))
	}

	gotVendorID, vsa, err := radius.VendorSpecific(attrs[0])
	if err != nil {
		t.Fatalf("VendorSpecific: %v", err)
	}
	if gotVendorID != vendorMikrotik {
		t.Errorf("expected vendor id %v, got %v", vendorMikrotik, gotVendorID)
	}
	if len(vsa) < 3 || vsa[0] != attrTypes["Mikrotik-Address-List"].Type {
		t.Fatalf("unexpected vsa bytes: %v", vsa)
	}
	if got := string(vsa[2:]); got != "Triolan.IPTV" {
		t.Errorf("expected value=Triolan.IPTV, got %q", got)
	}
}

func TestSetStringDifferentVendors(t *testing.T) {
	p := radius.New(radius.CodeAccessAccept, []byte("secret"))
	if err := SetString(p, "Mikrotik-Address-List", "Triolan.IPTV"); err != nil {
		t.Fatalf("SetString (mikrotik): %v", err)
	}
	if err := SetString(p, "Redback-Context-Name", "vlan101"); err != nil {
		t.Fatalf("SetString (redback): %v", err)
	}

	attrs := p.Attributes[26] // rfc2865.VendorSpecific_Type
	if len(attrs) != 2 {
		t.Fatalf("expected two Vendor-Specific attributes, got %v", len(attrs))
	}

	gotVendorID, vsa, err := radius.VendorSpecific(attrs[1])
	if err != nil {
		t.Fatalf("VendorSpecific: %v", err)
	}
	if gotVendorID != vendorRedback {
		t.Errorf("expected vendor id %v, got %v", vendorRedback, gotVendorID)
	}
	if len(vsa) < 3 || vsa[0] != attrTypes["Redback-Context-Name"].Type {
		t.Fatalf("unexpected vsa bytes: %v", vsa)
	}
	if got := string(vsa[2:]); got != "vlan101" {
		t.Errorf("expected value=vlan101, got %q", got)
	}
}

func TestSetStringUnknownAttribute(t *testing.T) {
	p := radius.New(radius.CodeAccessAccept, []byte("secret"))
	if err := SetString(p, "Not-A-Real-Attribute", "x"); err == nil {
		t.Fatal("expected error for unregistered attribute name")
	}
}
