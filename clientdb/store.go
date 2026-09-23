package clientdb

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/meklis/dhcp-radius-server/logger"
	"github.com/meklis/dhcp-radius-server/macaddr"
	"github.com/meklis/dhcp-radius-server/prom"
)

// Config describes where to load devices and named bind sources (e.g. clients,
// smart) from. Redis is optional and delivers per-record updates between reloads.
type Config struct {
	DevicesURL      string            `yaml:"devices_url"`
	Binds           map[string]string `yaml:"binds"`
	RefreshInterval time.Duration     `yaml:"refresh_interval"`
	Timeout         time.Duration     `yaml:"timeout"`
	Redis           RedisConfig       `yaml:"redis"`
}

// json tags name the fields as scripts see them.
type Device struct {
	IP        net.IP `json:"ip"`
	Mac       string `json:"mac"`
	ParseType string `json:"parse_type"`
}

// Bind links a client to a device port, or just to an IP/MAC for sources
// without devices (e.g. smart). ID is the record key in the external source.
type Bind struct {
	ID        string `json:"-"`
	IP        net.IP `json:"ip"`
	ClientMac string `json:"client_mac"`
	DeviceMac string `json:"device_mac"`
	Port      int    `json:"port"`
}

type snapshot struct {
	devices map[string]Device
	binds   map[string]*bindIndex
}

// Store serves lookups from an immutable snapshot that is swapped atomically on
// each full reload. Bind indexes are additionally patched in place by live
// updates (see ApplyBindEvent).
type Store struct {
	conf   Config
	lg     *logger.Logger
	client *http.Client
	snap   atomic.Pointer[snapshot]
	stop   chan struct{}

	// Live updates that arrive during a reload are queued and applied after
	// the new snapshot is published, otherwise they would be lost with the old one.
	pendingMu sync.Mutex
	reloading bool
	pending   []BindEvent
}

// New loads the database synchronously, so a broken source fails startup.
func New(conf Config, lg *logger.Logger) (*Store, error) {
	if conf.DevicesURL == "" {
		return nil, fmt.Errorf("clientdb: devices_url not set")
	}
	if conf.RefreshInterval <= 0 {
		conf.RefreshInterval = 5 * time.Minute
	}
	if conf.Timeout <= 0 {
		conf.Timeout = 30 * time.Second
	}

	s := &Store{
		conf:   conf,
		lg:     lg,
		client: &http.Client{Timeout: conf.Timeout},
		stop:   make(chan struct{}),
	}
	if err := s.reload(); err != nil {
		return nil, err
	}
	if err := s.subscribeRedis(); err != nil {
		return nil, fmt.Errorf("clientdb: redis: %w", err)
	}
	go func() {
		ticker := time.NewTicker(conf.RefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := s.reload(); err != nil {
					lg.ErrorF("clientdb: database update failed, keeping old data: %v", err)
				}
			case <-s.stop:
				return
			}
		}
	}()
	return s, nil
}

func (s *Store) Close() { close(s.stop) }

// reload replaces the whole snapshot. An empty source is treated as an error:
// a 200 response with a truncated body must not wipe a healthy snapshot.
func (s *Store) reload() error {
	s.lg.NoticeF("clientdb: start loading database")

	s.pendingMu.Lock()
	s.reloading = true
	s.pendingMu.Unlock()
	// replay live updates queued during the reload, in arrival order, on
	// whichever snapshot is current (new or, on failure, old)
	defer func() {
		s.pendingMu.Lock()
		pending := s.pending
		s.pending = nil
		s.reloading = false
		s.pendingMu.Unlock()
		for _, ev := range pending {
			if err := s.applyBindEvent(ev); err != nil {
				s.lg.ErrorF("clientdb: live-update (deferred during reload): %v", err)
			}
		}
	}()

	devices, err := s.loadDevices(s.conf.DevicesURL)
	if err != nil {
		return fmt.Errorf("devices: %w", err)
	}
	if len(devices) == 0 {
		return fmt.Errorf("devices: got 0 devices from %v - refusing to replace a possibly-healthy snapshot with an empty one", s.conf.DevicesURL)
	}

	binds := make(map[string]*bindIndex, len(s.conf.Binds))
	for name, url := range s.conf.Binds {
		idx, err := s.loadBinds(url)
		if err != nil {
			return fmt.Errorf("binds.%v: %w", name, err)
		}
		if idx.Count() == 0 {
			return fmt.Errorf("binds.%v: got 0 binds from %v - refusing to replace a possibly-healthy snapshot with an empty one", name, url)
		}
		binds[name] = idx
	}

	s.snap.Store(&snapshot{devices: devices, binds: binds})

	s.lg.NoticeF("clientdb: database updated: devices=%v", len(devices))
	prom.SetClientDBDevices(len(devices))
	for name, idx := range binds {
		count := idx.Count()
		s.lg.NoticeF("clientdb: binds.%v=%v", name, count)
		prom.SetClientDBBinds(name, count)
	}
	prom.SetClientDBLastReload(time.Now().Unix())
	return nil
}

func (s *Store) fetch(url string) (io.ReadCloser, error) {
	resp, err := s.client.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status: %v", resp.Status)
	}
	return resp.Body, nil
}

// loadDevices parses lines "ip_int;device_mac;parse_type".
func (s *Store) loadDevices(url string) (map[string]Device, error) {
	body, err := s.fetch(url)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	devices := make(map[string]Device)
	scanner := newScanner(body)
	for scanner.Scan() {
		fields := strings.Split(strings.TrimSpace(scanner.Text()), ";")
		if len(fields) < 3 {
			continue
		}
		mac := macaddr.Normalize(fields[1])
		if mac == "" {
			continue
		}
		devices[mac] = Device{
			IP:        intToIP(fields[0]),
			Mac:       mac,
			ParseType: strings.TrimSpace(fields[2]),
		}
	}
	return devices, scanner.Err()
}

// loadBinds parses lines "id;ip;client_mac" or "id;ip;client_mac;device_mac;port".
// A duplicate id replaces the earlier line.
func (s *Store) loadBinds(url string) (*bindIndex, error) {
	body, err := s.fetch(url)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	idx := newBindIndex()
	scanner := newScanner(body)
	for scanner.Scan() {
		fields := strings.Split(strings.TrimSpace(scanner.Text()), ";")
		if len(fields) < 3 {
			continue
		}
		id := strings.TrimSpace(fields[0])
		clientMac := macaddr.Normalize(fields[2])
		if id == "" || clientMac == "" {
			continue
		}
		b := &Bind{ID: id, IP: intToIP(fields[1]), ClientMac: clientMac}
		if len(fields) >= 5 {
			b.DeviceMac = macaddr.Normalize(fields[3])
			b.Port, _ = strconv.Atoi(strings.TrimSpace(fields[4]))
		}
		idx.put(b)
	}
	return idx, scanner.Err()
}

func newScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return scanner
}

// current never returns nil: New fails unless the first reload succeeded.
func (s *Store) current() *snapshot {
	return s.snap.Load()
}

func (s *Store) GetDeviceByMac(mac string) (Device, bool) {
	d, ok := s.current().devices[macaddr.Normalize(mac)]
	return d, ok
}

// FindBinds returns all binds of source dbName matching the client mac,
// optionally narrowed by deviceMac and port. With an empty mac, deviceMac and
// port select every bind on that device port (ports given to a shared pool).
func (s *Store) FindBinds(dbName, mac, deviceMac, port string) []Bind {
	idx, ok := s.current().binds[dbName]
	if !ok {
		return nil
	}
	mac = macaddr.Normalize(mac)
	deviceMac = macaddr.Normalize(deviceMac)
	port = strings.TrimSpace(port)
	if n, err := strconv.Atoi(port); err == nil {
		port = strconv.Itoa(n)
	}

	idx.mu.RLock()
	defer idx.mu.RUnlock()
	var found []*Bind
	switch {
	case mac != "" && deviceMac != "" && port != "":
		found = idx.byMacDevicePort[mac+"|"+deviceMac+"|"+port]
	case mac != "" && deviceMac != "":
		found = idx.byMacDevice[mac+"|"+deviceMac]
	case mac != "":
		found = idx.byMac[mac]
	case deviceMac != "" && port != "":
		found = idx.byDevicePort[deviceMac+"|"+port]
	}
	if len(found) == 0 {
		return nil
	}
	result := make([]Bind, len(found))
	for i, b := range found {
		result[i] = *b
	}
	return result
}

func (s *Store) GetBindByID(dbName, id string) (Bind, bool) {
	idx, ok := s.current().binds[dbName]
	if !ok {
		return Bind{}, false
	}
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	if b, ok := idx.byID[id]; ok {
		return *b, true
	}
	return Bind{}, false
}

func intToIP(s string) net.IP {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return nil
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, uint32(n))
	return ip
}
