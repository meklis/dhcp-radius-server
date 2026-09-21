package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// udpPacket - один UDP-пакет, извлечённый из pcap-файла, с адресами и временем
// захвата. Payload - тело UDP-датаграммы (то, что видит radius.Parse).
type udpPacket struct {
	Time    time.Time
	SrcIP   net.IP
	SrcPort int
	DstIP   net.IP
	DstPort int
	Payload []byte
}

// Значения поля Network в глобальном заголовке pcap (LINKTYPE_*) - какие
// заголовки канального уровня нужно снять перед IP.
const (
	linktypeEthernet = 1
	linktypeRaw      = 101
	linktypeLinuxSLL = 113
)

// readUDPPackets читает classic pcap-файл (не pcapng - см. README рядом),
// снимает заголовки Ethernet/Linux-cooked/Raw -> IPv4 -> UDP и возвращает все
// UDP-пакеты, у которых src или dst порт равен port. Не-IPv4, не-UDP,
// повреждённые/укороченные (snaplen) пакеты молча пропускаются - это офлайн-анализ
// трафика, а не production-парсер, падать из-за одного битого пакета в
// десятиминутном дампе незачем.
func readUDPPackets(path string, port int) ([]udpPacket, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)

	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, fmt.Errorf("read pcap magic: %w", err)
	}
	var bo binary.ByteOrder
	switch magic {
	case [4]byte{0xd4, 0xc3, 0xb2, 0xa1}:
		bo = binary.LittleEndian
	case [4]byte{0xa1, 0xb2, 0xc3, 0xd4}:
		bo = binary.BigEndian
	default:
		return nil, fmt.Errorf("unsupported pcap magic %x - expected classic pcap (tcpdump -w), not pcapng", magic)
	}

	rest := make([]byte, 20)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, fmt.Errorf("read pcap global header: %w", err)
	}
	network := bo.Uint32(rest[16:20])

	var out []udpPacket
	pktHdr := make([]byte, 16)
	skipped := map[string]int{}
	for {
		if _, err := io.ReadFull(r, pktHdr); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("read packet header: %w", err)
		}
		tsSec := bo.Uint32(pktHdr[0:4])
		tsUsec := bo.Uint32(pktHdr[4:8])
		inclLen := bo.Uint32(pktHdr[8:12])

		data := make([]byte, inclLen)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, fmt.Errorf("read packet data: %w", err)
		}

		u, reason := decodeUDP(data, uint32(network))
		if reason != "" {
			skipped[reason]++
			continue
		}
		if u.SrcPort != port && u.DstPort != port {
			continue
		}
		u.Time = time.Unix(int64(tsSec), int64(tsUsec)*1000)
		out = append(out, u)
	}

	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "pcap: skipped packets by reason: %v\n", skipped)
	}
	return out, nil
}

// decodeUDP снимает заголовки канального/сетевого уровня и возвращает UDP-пакет.
// reason непустой, если пакет пропущен (с человекочитаемой причиной для сводки).
func decodeUDP(data []byte, network uint32) (udpPacket, string) {
	switch network {
	case linktypeEthernet:
		if len(data) < 14 {
			return udpPacket{}, "short-ethernet"
		}
		ethertype := binary.BigEndian.Uint16(data[12:14])
		off := 14
		// снимаем до 2 VLAN-тегов (802.1Q/802.1ad) перед IP
		for i := 0; i < 2 && ethertype == 0x8100 || ethertype == 0x88a8; i++ {
			if len(data) < off+4 {
				return udpPacket{}, "short-vlan"
			}
			ethertype = binary.BigEndian.Uint16(data[off+2 : off+4])
			off += 4
		}
		if ethertype != 0x0800 {
			return udpPacket{}, "non-ipv4-ethertype"
		}
		return decodeIPv4(data[off:])
	case linktypeLinuxSLL:
		if len(data) < 16 {
			return udpPacket{}, "short-sll"
		}
		protocol := binary.BigEndian.Uint16(data[14:16])
		if protocol != 0x0800 {
			return udpPacket{}, "non-ipv4-sll"
		}
		return decodeIPv4(data[16:])
	case linktypeRaw:
		return decodeIPv4(data)
	default:
		return udpPacket{}, fmt.Sprintf("unsupported-linktype-%d", network)
	}
}

func decodeIPv4(data []byte) (udpPacket, string) {
	if len(data) < 20 {
		return udpPacket{}, "short-ip"
	}
	version := data[0] >> 4
	if version != 4 {
		return udpPacket{}, "non-ipv4"
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl {
		return udpPacket{}, "bad-ip-ihl"
	}
	if data[9] != 17 { // UDP
		return udpPacket{}, "non-udp"
	}
	totalLen := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLen > len(data) {
		totalLen = len(data) // snaplen обрезал хвост - берём что есть
	}
	srcIP := net.IP(append([]byte(nil), data[12:16]...))
	dstIP := net.IP(append([]byte(nil), data[16:20]...))

	udp := data[ihl:totalLen]
	if len(udp) < 8 {
		return udpPacket{}, "short-udp"
	}
	srcPort := int(binary.BigEndian.Uint16(udp[0:2]))
	dstPort := int(binary.BigEndian.Uint16(udp[2:4]))
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 {
		return udpPacket{}, "bad-udp-length"
	}
	payloadEnd := udpLen
	if payloadEnd > len(udp) {
		payloadEnd = len(udp) // snaplen обрезал хвост
	}

	return udpPacket{
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstIP:   dstIP,
		DstPort: dstPort,
		Payload: append([]byte(nil), udp[8:payloadEnd]...),
	}, ""
}
