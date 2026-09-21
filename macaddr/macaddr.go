// Package macaddr - единый формат представления мак-адреса для всего проекта:
// 12 hex-цифр в верхнем регистре через двоеточие (AA:BB:CC:DD:EE:FF). Мак-адреса
// приходят в разных видах в зависимости от источника (сырой User-Name от NAS,
// client_mac из внешней clientdb, remote_id из option82) - вендоры свитчей и
// внешние системы форматируют их по-разному (с разделителями/без, "-"/":", регистр).
// Normalize приводит любой из этих видов к одному каноническому - это позволяет
// сравнивать мак-адреса как обычные строки (в т.ч. в lua-скриптах) без отдельной
// нормализации на месте сравнения.
package macaddr

import "strings"

// Normalize приводит мак-адрес к каноническому виду AA:BB:CC:DD:EE:FF. Пустая
// строка остаётся пустой. Если после отбрасывания разделителей осталось не ровно
// 12 hex-символов (не похоже на 6-байтный мак) - возвращается verbatim hex без
// двоеточий: битые данные остаются видимыми в логах, а не пропадают и не роняют
// обработку.
func Normalize(mac string) string {
	hex := stripNonHex(mac)
	if len(hex) != 12 {
		return hex
	}
	var b strings.Builder
	b.Grow(17)
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex[i : i+2])
	}
	return b.String()
}

func stripNonHex(s string) string {
	s = strings.ToUpper(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') {
			b.WriteRune(r)
		}
	}
	return b.String()
}
