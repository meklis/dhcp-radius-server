package redback_agent_parsers

import (
	"fmt"
	"strings"
)

// isMacText - значение уже текстовый мак "aa:bb:cc:dd:ee:ff" (17 ascii-байт),
// встречается у некоторых NAS вместо сырых 6 байт
func isMacText(b []byte) bool {
	if len(b) != 17 {
		return false
	}
	for i, c := range b {
		if i%3 == 2 {
			if c != ':' {
				return false
			}
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// ParseRemoteId - порт логики remoteReader() из abills.pl (freeradius), со сдвигом
// на 1 байт: там смещения считаны относительно hex-строки, которую отдавал
// FreeRADIUS, а у нас на 1 байт короче сырые данные (подтверждено на дублирующих
// вычислениях для circuit_id и remote_id по реальным пакетам dlink/bdcom).
//
// Мак читается фиксированной позицией сразу после заголовка, а не "с конца" -
// это важно для 18-байтного случая, где после мака идёт ~12 байт мусора, который
// нужно просто игнорировать, а не пытаться найти мак с хвоста
func ParseRemoteId(remoteIdBytes []byte) string {
	if isMacText(remoteIdBytes) {
		return strings.ToUpper(string(remoteIdBytes))
	}

	var mac []byte
	switch len(remoteIdBytes) {
	case 8: // perl: length==18 (hex), заголовок 3 байта -> у нас 2
		mac = remoteIdBytes[2:8]
	case 6, 18: // perl: length==14 или 38 (hex), заголовок 1 байт -> у нас 0
		mac = remoteIdBytes[0:6]
	default:
		return ""
	}

	var remoteId string
	for _, h_block := range mac {
		h := fmt.Sprintf("%X", h_block)
		if len(h) == 1 {
			h = "0" + h
		}
		remoteId += h + ":"
	}
	remoteId = strings.Trim(remoteId, ":")
	return remoteId
}
