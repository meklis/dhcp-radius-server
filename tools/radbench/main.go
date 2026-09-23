// Command radbench шлёт на радиус-сервер случайные Access-Request с заданным
// постоянным темпом (pps) и считает ответы по типам.
//
// Темп открытый: запросы уходят по расписанию независимо от того, ответил ли
// сервер на предыдущие, поэтому медленный сервер проявляется таймаутами, а не
// падением pps. Ошибки (таймауты, реджекты) печатаются по ходу, итоговая
// статистика - по Ctrl+C или по окончании -duration.
//
// Использование:
//
//	radbench -server 127.0.0.1:1812 -secret secret -pps 500 -timeout 1000 -duration 60s
package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/meklis/dhcp-radius-server/radius/redback"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type stats struct {
	sent, sendErr, timeout, noFreeID, badResp atomic.Int64

	mu     sync.Mutex
	codes  map[radius.Code]int64
	latSum time.Duration
	latMin time.Duration
	latMax time.Duration
	latN   int64
}

func (s *stats) answer(code radius.Code, lat time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code]++
	s.latSum += lat
	s.latN++
	if s.latMin == 0 || lat < s.latMin {
		s.latMin = lat
	}
	if lat > s.latMax {
		s.latMax = lat
	}
}

type inflight struct {
	req    []byte // закодированный запрос, нужен для проверки Response Authenticator
	mac    string
	sentAt time.Time
	timer  *time.Timer
}

// conn - один UDP-сокет с 256 слотами под RADIUS Identifier; ответ
// сопоставляется с запросом по Identifier внутри своего сокета.
type conn struct {
	c       *net.UDPConn
	secret  []byte
	st      *stats
	timeout time.Duration

	mu      sync.Mutex
	pending [256]*inflight
	nextID  byte
}

func (c *conn) send(p *radius.Packet, mac string) bool {
	c.mu.Lock()
	id, ok := c.freeID()
	if !ok {
		c.mu.Unlock()
		return false
	}
	p.Identifier = id
	raw, err := p.Encode()
	if err != nil {
		c.mu.Unlock()
		c.st.sendErr.Add(1)
		fmt.Fprintf(os.Stderr, "ERROR encode: %v\n", err)
		return true
	}
	f := &inflight{req: raw, mac: mac, sentAt: time.Now()}
	f.timer = time.AfterFunc(c.timeout, func() { c.expire(id, f) })
	c.pending[id] = f
	c.mu.Unlock()

	c.st.sent.Add(1)
	if _, err := c.c.Write(raw); err != nil {
		c.mu.Lock()
		if c.pending[id] == f {
			c.pending[id] = nil
			f.timer.Stop()
		}
		c.mu.Unlock()
		c.st.sendErr.Add(1)
		fmt.Fprintf(os.Stderr, "ERROR send: mac=%s %v\n", mac, err)
	}
	return true
}

func (c *conn) freeID() (byte, bool) {
	for i := 0; i < 256; i++ {
		id := c.nextID
		c.nextID++
		if c.pending[id] == nil {
			return id, true
		}
	}
	return 0, false
}

func (c *conn) expire(id byte, f *inflight) {
	c.mu.Lock()
	if c.pending[id] != f {
		c.mu.Unlock()
		return
	}
	c.pending[id] = nil
	c.mu.Unlock()
	c.st.timeout.Add(1)
	fmt.Fprintf(os.Stderr, "TIMEOUT: id=%d mac=%s after %v\n", id, f.mac, c.timeout)
}

func (c *conn) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, err := c.c.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// ICMP port unreachable и т.п. - запрос всё равно досчитается как таймаут
			continue
		}
		now := time.Now()
		raw := buf[:n]
		if n < 20 {
			c.st.badResp.Add(1)
			continue
		}
		id := raw[1]
		c.mu.Lock()
		f := c.pending[id]
		if f == nil {
			c.mu.Unlock()
			// опоздавший ответ на уже истёкший по таймауту запрос
			continue
		}
		if !radius.IsAuthenticResponse(raw, f.req, c.secret) {
			c.mu.Unlock()
			c.st.badResp.Add(1)
			fmt.Fprintf(os.Stderr, "BAD RESPONSE: id=%d mac=%s wrong authenticator (secret?)\n", id, f.mac)
			continue
		}
		c.pending[id] = nil
		f.timer.Stop()
		c.mu.Unlock()

		code := radius.Code(raw[0])
		lat := now.Sub(f.sentAt)
		c.st.answer(code, lat)
		if code != radius.CodeAccessAccept {
			fmt.Fprintf(os.Stderr, "%s: id=%d mac=%s in %v\n", code, id, f.mac, lat.Round(time.Microsecond))
		}
	}
}

func randMAC() string {
	var b [6]byte
	rand.Read(b[:])
	b[0] &^= 1 // unicast
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
}

func newRequest(secret []byte, nasIP net.IP, nasID, mac string) *radius.Packet {
	p := radius.New(radius.CodeAccessRequest, secret)
	rfc2865.UserName_SetString(p, mac)
	rfc2865.NASIPAddress_Set(p, nasIP)
	if nasID != "" {
		rfc2865.NASIdentifier_SetString(p, nasID)
	}
	// option-82: случайный remote-id (мак свитча) и circuit-id (vlan/порт)
	var remote [8]byte
	remote[1] = 6
	rand.Read(remote[2:])
	redback.AgentRemoteID_Set(p, remote[:])
	var circuit [6]byte
	circuit[1] = 4
	rand.Read(circuit[2:])
	redback.AgentCircuitID_Set(p, circuit[:])
	return p
}

func main() {
	server := flag.String("server", "", "адрес радиус-сервера host:port (обязательно)")
	secret := flag.String("secret", "", "RADIUS-секрет (обязательно)")
	pps := flag.Int("pps", 0, "запросов в секунду (обязательно)")
	timeoutMs := flag.Int("timeout", 1000, "таймаут ответа, мс")
	duration := flag.Duration("duration", 0, "длительность теста, например 30s, 5m (0 = до Ctrl+C)")
	nasIP := flag.String("nas-ip", "127.0.0.1", "NAS-IP-Address в запросах (сервер ищет NAS по нему)")
	nasID := flag.String("nas-id", "radbench", "NAS-Identifier в запросах (пусто = не слать)")
	flag.Parse()

	if *server == "" || *secret == "" || *pps <= 0 || *timeoutMs <= 0 {
		fmt.Fprintln(os.Stderr, "usage: radbench -server host:port -secret S -pps N [-timeout ms] [-duration 60s] [-nas-ip IP] [-nas-id ID]")
		flag.PrintDefaults()
		os.Exit(2)
	}
	nas := net.ParseIP(*nasIP).To4()
	if nas == nil {
		fmt.Fprintf(os.Stderr, "invalid -nas-ip %q\n", *nasIP)
		os.Exit(2)
	}
	addr, err := net.ResolveUDPAddr("udp", *server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve %s: %v\n", *server, err)
		os.Exit(2)
	}
	timeout := time.Duration(*timeoutMs) * time.Millisecond

	// в полёте одновременно до pps*timeout запросов, на сокет - 256 Identifier;
	// берём с двойным запасом
	inflightMax := int64(*pps) * int64(*timeoutMs) / 1000
	nConns := int(inflightMax*2/256) + 1

	st := &stats{codes: map[radius.Code]int64{}}
	conns := make([]*conn, nConns)
	for i := range conns {
		uc, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dial %s: %v\n", *server, err)
			os.Exit(1)
		}
		conns[i] = &conn{c: uc, secret: []byte(*secret), st: st, timeout: timeout}
		go conns[i].readLoop()
	}

	fmt.Printf("radbench: %s, %d pps, timeout %v, duration %v, %d sockets\n",
		*server, *pps, timeout, *duration, nConns)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	var deadline <-chan time.Time
	if *duration > 0 {
		deadline = time.After(*duration)
	}

	start := time.Now()
	interval := time.Second / time.Duration(*pps)
	tick := time.NewTicker(time.Millisecond)
	var planned int64
	next := 0
loop:
	for {
		select {
		case <-sig:
			fmt.Println("\ninterrupted")
			break loop
		case <-deadline:
			break loop
		case <-tick.C:
			// догоняем расписание: сколько запросов уже должно было уйти к этому моменту
			due := int64(time.Since(start) / interval)
			for ; planned < due; planned++ {
				mac := randMAC()
				p := newRequest([]byte(*secret), nas, *nasID, mac)
				sent := false
				for try := 0; try < nConns && !sent; try++ {
					sent = conns[next].send(p, mac)
					next = (next + 1) % nConns
				}
				if !sent {
					st.noFreeID.Add(1)
				}
			}
		}
	}
	tick.Stop()
	elapsed := time.Since(start)

	// ждём ответы на уже отправленные запросы, но не дольше таймаута
	waitUntil := time.Now().Add(timeout)
	for time.Now().Before(waitUntil) {
		busy := false
		for _, c := range conns {
			c.mu.Lock()
			for _, f := range c.pending {
				if f != nil {
					busy = true
					break
				}
			}
			c.mu.Unlock()
			if busy {
				break
			}
		}
		if !busy {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, c := range conns {
		c.c.Close()
	}
	printStats(st, elapsed)
}

func printStats(st *stats, elapsed time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()

	var answered int64
	codes := make([]radius.Code, 0, len(st.codes))
	for c, n := range st.codes {
		codes = append(codes, c)
		answered += n
	}
	sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })

	sent := st.sent.Load()
	fmt.Println()
	fmt.Println("===== radbench statistics =====")
	fmt.Printf("duration:        %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("requests sent:   %d (%.1f pps actual)\n", sent, float64(sent)/elapsed.Seconds())
	fmt.Printf("responses:       %d\n", answered)
	for _, c := range codes {
		fmt.Printf("  %-16s %d (%.2f%%)\n", c.String()+":", st.codes[c], pct(st.codes[c], sent))
	}
	fmt.Printf("timeouts:        %d (%.2f%%)\n", st.timeout.Load(), pct(st.timeout.Load(), sent))
	if n := st.badResp.Load(); n > 0 {
		fmt.Printf("bad responses:   %d\n", n)
	}
	if n := st.sendErr.Load(); n > 0 {
		fmt.Printf("send errors:     %d\n", n)
	}
	if n := st.noFreeID.Load(); n > 0 {
		fmt.Printf("not sent (no free id): %d\n", n)
	}
	if st.latN > 0 {
		fmt.Printf("latency:         min %v / avg %v / max %v\n",
			st.latMin.Round(time.Microsecond),
			(st.latSum / time.Duration(st.latN)).Round(time.Microsecond),
			st.latMax.Round(time.Microsecond))
	}
}

func pct(n, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) * 100 / float64(total)
}
