package script

import (
	"os"
	"testing"
	"time"

	"github.com/meklis/dhcp-radius-server/clientdb"
	"github.com/meklis/dhcp-radius-server/logger"
	"github.com/meklis/dhcp-radius-server/prom"
	"github.com/meklis/dhcp-radius-server/radius/events"
	"github.com/prometheus/client_golang/prometheus"
)

func testLogger(t *testing.T) *logger.Logger {
	t.Helper()
	return logger.New(os.Stdout, logger.Options{Level: logger.InfoLevel})
}

func TestNewProcessorAuthOnly(t *testing.T) {
	srv := testDBServer(t)
	defer srv.Close()

	p, err := NewProcessor(Config{
		Auth:     "examples/auth.lua",
		PoolSize: 2,
		Timeout:  time.Second,
		Database: clientdb.Config{
			DevicesURL:      srv.URL + "?type=devices",
			Binds:           map[string]string{"clients": srv.URL + "?type=clients"},
			RefreshInterval: time.Hour,
		},
	}, nil, testLogger(t))
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}
	if p.acct != nil || p.postAuth != nil {
		t.Fatal("acct/post_auth не заданы в конфиге, но движки созданы")
	}

	resp, err := p.Get(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "999999999999",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "08:5A:11:94:65:E0",
			RawCircuitId: "000000650009", // vlan=101, port=9 - не в binds, "серый" пул
		},
	})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.PoolName != "INET-101-FAKE" {
		t.Errorf("expected pool_name=INET-101-FAKE, got %q", resp.PoolName)
	}

	// без сконфигурированных acct/post_auth вызовы должны быть no-op, без паники
	p.SendAcct(&events.AcctRequest{DeviceMac: "AA:BB:CC:DD:EE:FF"})
	p.SendPostAuth(events.AuthRequest{DeviceMac: "AA:BB:CC:DD:EE:FF"}, events.AuthResponse{PoolName: "default"})
}

func TestFullQueueDropsEventsAndCountsThem(t *testing.T) {
	prom.Enabled = true
	t.Cleanup(func() { prom.Enabled = false })
	before := map[string]float64{"post_auth": droppedEvents(t, "post_auth"), "acct": droppedEvents(t, "acct")}

	// nobody reads the queues, so the second event of each kind does not fit
	p := &Processor{
		lg:            testLogger(t),
		acct:          &Engine{},
		postAuth:      &Engine{},
		acctQueue:     make(chan *events.AcctRequest, 1),
		postAuthQueue: make(chan postAuthEvent, 1),
	}
	for range 2 {
		p.SendAcct(&events.AcctRequest{})
		p.SendPostAuth(events.AuthRequest{}, events.AuthResponse{})
	}

	for phase, count := range before {
		if got := droppedEvents(t, phase) - count; got != 1 {
			t.Errorf("%v: dropped %v events, expected 1", phase, got)
		}
	}
}

func droppedEvents(t *testing.T, phase string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "rad_script_dropped_events_count" {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metric.GetLabel()[0].GetValue() == phase {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func TestDefaultQueueSize(t *testing.T) {
	srv := testDBServer(t)
	defer srv.Close()

	p, err := NewProcessor(Config{
		Auth:     "examples/auth.lua",
		Acct:     "examples/acct.lua",
		PostAuth: "examples/post_auth.lua",
		PoolSize: 1,
		Database: clientdb.Config{
			DevicesURL:      srv.URL + "?type=devices",
			Binds:           map[string]string{"clients": srv.URL + "?type=clients"},
			RefreshInterval: time.Hour,
		},
	}, unreachableRedis(), testLogger(t))
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}
	if cap(p.acctQueue) != defaultQueueSize || cap(p.postAuthQueue) != defaultQueueSize {
		t.Fatalf("unexpected queue sizes: acct=%v post_auth=%v", cap(p.acctQueue), cap(p.postAuthQueue))
	}
}

func TestNewProcessorRequiresAuth(t *testing.T) {
	_, err := NewProcessor(Config{}, nil, testLogger(t))
	if err == nil {
		t.Fatal("expected error when script.auth is empty")
	}
}

func TestNewProcessorRequiresDatabase(t *testing.T) {
	// при processor: script database.devices_url обязателен, даже если auth задан
	_, err := NewProcessor(Config{
		Auth:     "examples/auth.lua",
		PoolSize: 2,
		Timeout:  time.Second,
	}, nil, testLogger(t))
	if err == nil {
		t.Fatal("expected error when script.database.devices_url is empty")
	}
}

func TestNewProcessorAllPhases(t *testing.T) {
	srv := testDBServer(t)
	defer srv.Close()

	p, err := NewProcessor(Config{
		Auth:     "examples/auth.lua",
		Acct:     "examples/acct.lua",
		PostAuth: "examples/post_auth.lua",
		PoolSize: 2,
		Timeout:  time.Second,
		Database: clientdb.Config{
			DevicesURL:      srv.URL + "?type=devices",
			Binds:           map[string]string{"clients": srv.URL + "?type=clients"},
			RefreshInterval: time.Hour,
		},
	}, unreachableRedis(), testLogger(t))
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}

	p.SendAcct(&events.AcctRequest{DeviceMac: "AA:BB:CC:DD:EE:FF", StatusType: "Start"})
	p.SendPostAuth(events.AuthRequest{DeviceMac: "AA:BB:CC:DD:EE:FF"}, events.AuthResponse{PoolName: "default"})
	time.Sleep(50 * time.Millisecond)
}
