package main

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// buildEthIPUDP собирает Ethernet+IPv4+UDP кадр вокруг payload - ровно то, что
// пишет tcpdump при захвате на обычном сетевом интерфейсе (LINKTYPE_ETHERNET).
func buildEthIPUDP(t *testing.T, srcMAC, dstMAC [6]byte, srcIP, dstIP net.IP, srcPort, dstPort int, payload []byte) []byte {
	t.Helper()
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)

	ip := make([]byte, 20+len(udp))
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64   // TTL
	ip[9] = 17   // UDP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	copy(ip[20:], udp)

	eth := make([]byte, 14+len(ip))
	copy(eth[0:6], dstMAC[:])
	copy(eth[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	copy(eth[14:], ip)
	return eth
}

func writePcap(t *testing.T, path string, network uint32, frames [][]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 262144)
	binary.LittleEndian.PutUint32(hdr[20:24], network)
	if _, err := f.Write(hdr); err != nil {
		t.Fatal(err)
	}

	for _, fr := range frames {
		ph := make([]byte, 16)
		binary.LittleEndian.PutUint32(ph[8:12], uint32(len(fr)))
		binary.LittleEndian.PutUint32(ph[12:16], uint32(len(fr)))
		if _, err := f.Write(ph); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(fr); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadUDPPacketsAndMatchPairs(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.pcap"

	nasMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	srvMAC := [6]byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	nasIP := net.ParseIP("10.0.0.5")
	srvIP := net.ParseIP("10.0.0.1")

	req := radius.New(radius.CodeAccessRequest, []byte("secret"))
	req.Identifier = 42
	if err := rfc2865.UserName_SetString(req, "AA:BB:CC:DD:EE:FF"); err != nil {
		t.Fatal(err)
	}
	reqWire, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}

	accept := req.Response(radius.CodeAccessAccept)
	if err := rfc2865.FramedIPAddress_Set(accept, net.ParseIP("1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	acceptWire, err := accept.Encode()
	if err != nil {
		t.Fatal(err)
	}

	reqFrame := buildEthIPUDP(t, nasMAC, srvMAC, nasIP, srvIP, 33000, 1812, reqWire)
	respFrame := buildEthIPUDP(t, srvMAC, nasMAC, srvIP, nasIP, 1812, 33000, acceptWire)

	writePcap(t, path, linktypeEthernet, [][]byte{reqFrame, respFrame})

	pkts, err := readUDPPackets(path, 1812)
	if err != nil {
		t.Fatalf("readUDPPackets: %v", err)
	}
	if len(pkts) != 2 {
		t.Fatalf("expected 2 udp packets, got %d", len(pkts))
	}
	if pkts[0].SrcIP.String() != "10.0.0.5" || pkts[0].DstIP.String() != "10.0.0.1" || pkts[0].SrcPort != 33000 || pkts[0].DstPort != 1812 {
		t.Errorf("unexpected request addressing: %+v", pkts[0])
	}
	if pkts[1].SrcIP.String() != "10.0.0.1" || pkts[1].DstPort != 33000 {
		t.Errorf("unexpected response addressing: %+v", pkts[1])
	}

	pairs, unmatched := matchPairs(pkts)
	if unmatched != 0 {
		t.Errorf("expected 0 unmatched, got %d", unmatched)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected 1 matched pair, got %d", len(pairs))
	}

	gotUser := rfc2865.UserName_GetString(&radius.Packet{Attributes: pairs[0].req})
	if gotUser != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("expected recovered User-Name=AA:BB:CC:DD:EE:FF, got %q", gotUser)
	}
	sum := summarize(pairs[0].real, nil)
	if sum.code != "Accept" || sum.ip != "1.2.3.4" {
		t.Errorf("unexpected summary: %+v", sum)
	}
}
