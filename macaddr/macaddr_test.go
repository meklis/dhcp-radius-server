package macaddr

import "testing"

func TestNormalize(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF"},
		{"aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF"},
		{"AABBCCDDEEFF", "AA:BB:CC:DD:EE:FF"},
		{"aabbccddeeff", "AA:BB:CC:DD:EE:FF"},
		{"AA-BB-CC-DD-EE-FF", "AA:BB:CC:DD:EE:FF"},
		{"aabb.ccdd.eeff", "AA:BB:CC:DD:EE:FF"}, // cisco dot-notation
		{"  AA:BB:CC:DD:EE:FF  ", "AA:BB:CC:DD:EE:FF"},
		{"short", ""},        // no hex digits (A-F only, no G-Z) survive stripping
		{"AABBCC", "AABBCC"}, // too short (6 hex chars) - returned verbatim, no colons
	}
	for _, c := range cases {
		got := Normalize(c.in)
		if got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
