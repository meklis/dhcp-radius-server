package script

import (
	"os"
	"testing"
	"time"

	"github.com/meklis/dhcp-radius-server/clientdb"
	"github.com/meklis/dhcp-radius-server/logger"
	"github.com/meklis/dhcp-radius-server/radius/events"
)

func testLogger(t *testing.T) *logger.Logger {
	t.Helper()
	lg, err := logger.New("test", 0, os.Stdout)
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}
	return lg
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
	}, testLogger(t))
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}
	if p.acctEngine != nil || p.postAuthEngine != nil {
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

func TestNewProcessorRequiresAuth(t *testing.T) {
	_, err := NewProcessor(Config{}, testLogger(t))
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
	}, testLogger(t))
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
	}, testLogger(t))
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}

	p.SendAcct(&events.AcctRequest{DeviceMac: "AA:BB:CC:DD:EE:FF", StatusType: "Start"})
	p.SendPostAuth(events.AuthRequest{DeviceMac: "AA:BB:CC:DD:EE:FF"}, events.AuthResponse{PoolName: "default"})
	time.Sleep(50 * time.Millisecond)
}
