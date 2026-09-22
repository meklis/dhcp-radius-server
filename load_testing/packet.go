package main

import (
	"crypto/md5"
	"fmt"
	"math/rand"
	"net"
	"strings"

	"github.com/meklis/dhcp-radius-server/radius/redback"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

// randMAC генерирует случайный мак клиента - основной источник "разнообразия"
// в нагрузочном тесте, чтобы каждый запрос выглядел как новое устройство.
func randMAC(rnd *rand.Rand) [6]byte {
	var b [6]byte
	rnd.Read(b[:])
	return b
}

// pickClientMAC - мак абонентского устройства для запроса. Если задан
// -mac-pool, каждый раз выбирается один из заранее сгенерированных N маков
// (ограниченная кардинальность - как у реальных постоянных абонентов); иначе
// каждый запрос получает совершенно новый случайный мак.
func pickClientMAC(rnd *rand.Rand, pool [][6]byte) [6]byte {
	if len(pool) > 0 {
		return pool[rnd.Intn(len(pool))]
	}
	return randMAC(rnd)
}

func macString(b [6]byte) string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
}

// addVendorSub добавляет одну vendor-specific под-запись произвольного вендора -
// используется, чтобы продублировать option-82 под "неизвестным" вендором 3561,
// как это делают реальные dlink/bdcom свитчи в примерах из задачи.
func addVendorSub(p *radius.Packet, vendorID uint32, subType byte, value []byte) error {
	sub := make([]byte, 2+len(value))
	sub[0] = subType
	sub[1] = byte(len(sub))
	copy(sub[2:], value)
	vsa, err := radius.NewVendorSpecific(vendorID, radius.Attribute(sub))
	if err != nil {
		return err
	}
	p.Add(rfc2865.VendorSpecific_Type, vsa)
	return nil
}

const unknownVendorID = 3561

// setEmptyUserPassword кодирует пустой User-Password как один блок из 16 нулевых
// байт (RFC 2865 5.2). Обходит rfc2865.UserPassword_SetString(p, "") -
// в заопиненной версии layeh.com/radius она паникует на пустой строке
// (slice bounds out of range при попытке взять plaintext[:16] от 0-длинного
// слайса), поэтому блок собирается вручную.
func setEmptyUserPassword(p *radius.Packet) {
	hash := md5.New()
	hash.Write(p.Secret)
	hash.Write(p.Authenticator[:])
	block := hash.Sum(nil) // XOR с 16 нулевыми байтами plaintext - тождество
	p.Set(rfc2865.UserPassword_Type, radius.Attribute(block))
}

// buildRealisticPacket собирает Access-Request, максимально похожий по набору
// атрибутов на реальные пакеты DHCP-relay/CCR из задачи: мак клиента, NAS-*,
// vendor-specific option-82 (Redback 2352 attrs 96/97 + дубль под вендором
// 3561), пустой Password, иногда Message-Authenticator.
func buildRealisticPacket(secret string, site Site, opts Options, rnd *rand.Rand) *radius.Packet {
	packet := radius.New(radius.CodeAccessRequest, []byte(secret))

	macBytes := pickClientMAC(rnd, opts.ClientMacPool)
	mac := macString(macBytes)
	rfc2865.UserName_SetString(packet, mac)
	rfc2865.NASPortType_Set(packet, rfc2865.NASPortType_Value_Ethernet)
	rfc2865.ServiceType_Set(packet, rfc2865.ServiceType_Value_FramedUser)
	rfc2865.CalledStationID_SetString(packet, site.CalledStationID)
	rfc2865.CallingStationID_SetString(packet, "1:"+strings.ToLower(mac))

	framedIP := net.IPv4(10, byte(rnd.Intn(250)+2), byte(rnd.Intn(254)+1), byte(rnd.Intn(254)+1))
	rfc2865.FramedIPAddress_Set(packet, framedIP)

	if site.LocalPort {
		rfc2865.NASPort_Set(packet, rfc2865.NASPort(uint32(site.PortNumber)))
		rfc2869.NASPortID_SetString(packet, site.PortID)
	} else {
		neg := int32(-(2080000000 + rnd.Int31n(20000000)))
		rfc2865.NASPort_Set(packet, rfc2865.NASPort(uint32(neg)))
	}

	// option-82. По умолчанию remote-id (мак свитча) не отправляем: сервер
	// (см. script/examples/auth.lua) без remote-id теперь отвечает явным
	// Access-Reject, не ходя во внешнюю clientdb вовсе - для прогона полного
	// пути с обращением в clientdb/binds нужен -switch-macs (реальные маки
	// свитчей из внешней clientdb), часть запросов (см. -known-device-percent)
	// тогда идёт с remote-id одного из них.
	vlan := rnd.Intn(4094) + 1
	stack := byte(rnd.Intn(4))
	port := byte(rnd.Intn(48) + 1)
	circuitVal := []byte{byte(rnd.Intn(256)), byte(rnd.Intn(256)), byte(vlan >> 8), byte(vlan), stack, port}
	redback.AgentCircuitID_Set(packet, circuitVal)

	var remoteVal []byte
	if len(opts.SwitchMacs) > 0 && rnd.Intn(100) < opts.KnownDevicePercent {
		switchMac := opts.SwitchMacs[rnd.Intn(len(opts.SwitchMacs))]
		remoteVal = append([]byte{0x00, 0x06}, switchMac[:]...)
		redback.AgentRemoteID_Set(packet, remoteVal)
	}

	if opts.DupVendor {
		if remoteVal != nil {
			addVendorSub(packet, unknownVendorID, 2, remoteVal)
		}
		addVendorSub(packet, unknownVendorID, 1, circuitVal)
	}

	setEmptyUserPassword(packet)
	rfc2865.NASIdentifier_SetString(packet, site.NasID)
	rfc2865.NASIPAddress_Set(packet, net.ParseIP(site.NasIP))

	if opts.MsgAuthPercent > 0 && rnd.Intn(100) < opts.MsgAuthPercent {
		authBytes := make([]byte, 16)
		rnd.Read(authBytes)
		rfc2869.MessageAuthenticator_Set(packet, authBytes)
	}

	return packet
}

// buildSimplePacket - минимальный пакет (старое поведение инструмента):
// только мак, Called-Station-Id и пустой пароль. Полезен, чтобы сравнить
// стоимость обработки "тяжёлого" реалистичного пакета с "лёгким".
func buildSimplePacket(secret, calledStationID string, pool [][6]byte, rnd *rand.Rand) *radius.Packet {
	packet := radius.New(radius.CodeAccessRequest, []byte(secret))
	mac := macString(pickClientMAC(rnd, pool))
	rfc2865.UserName_SetString(packet, mac)
	rfc2865.CalledStationID_SetString(packet, calledStationID)
	setEmptyUserPassword(packet)
	return packet
}
