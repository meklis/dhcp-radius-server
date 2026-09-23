package macaddr

import "testing"

func TestFromRemoteID(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "dlink - 2 байта заголовка + 6 байт мака",
			input: []byte{0x00, 0x06, 0x78, 0x98, 0xE8, 0xE9, 0x4F, 0xE0},
			want:  "78:98:E8:E9:4F:E0",
		},
		{
			name:  "bdcom - без заголовка, чистый мак",
			input: []byte{0xE0, 0x67, 0xB3, 0x7B, 0x6D, 0x49},
			want:  "E0:67:B3:7B:6D:49",
		},
		{
			name:  "текстовый мак вместо сырых байт",
			input: []byte("d8:0a:e6:af:73:3b"),
			want:  "D8:0A:E6:AF:73:3B",
		},
		{
			name: "18 байт - мак сразу (без заголовка), хвостовой мусор после мака игнорируется",
			input: []byte{
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // мак
				0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // мусор
			},
			want: "11:22:33:44:55:66",
		},
		{
			name:  "слишком короткое значение",
			input: []byte{0x01, 0x02},
			want:  "",
		},
		{
			name:  "пусто",
			input: nil,
			want:  "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FromRemoteID(c.input); got != c.want {
				t.Errorf("FromRemoteID(%v) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}
