package script

import (
	"os"
	"testing"
	"time"

	"github.com/meklis/dhcp-radius-server/logger"
	"github.com/meklis/dhcp-radius-server/radius/events"
)

func testEngine(t *testing.T, path string) *Engine {
	t.Helper()
	lg, err := logger.New("test", 0, os.Stdout)
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}
	e, err := New(path, 2, time.Second, lg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// dlinkCircuitID - vlan=101 (0x0065), stack=0, port=3 - см. смещения в examples/auth.lua
const dlinkCircuitID = "000000650003"

func TestCallAuthorizeError(t *testing.T) {
	e := testEngine(t, "examples/auth.lua")

	// без db тип оборудования неизвестен -> circuit_id не распознан -> отказ
	// (позитивные сценарии - в db_test.go, т.к. теперь требуют db.devices)
	_, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "AA:BB:CC:DD:EE:FF",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "08:5A:11:94:65:E0",
			RawCircuitId: dlinkCircuitID,
		},
	})
	if err == nil {
		t.Fatal("expected error without configured db, got nil")
	}
	// без store глобальная переменная db не создаётся вовсе (см. db.go:registerDB) -
	// authorize() падает на индексации nil, это Lua-паника (инфраструктурная
	// проблема, KindError), а не бизнес-решение скрипта (KindInvalid) - для
	// последнего см. TestTableToAuthResponse в convert_test.go
	if kind := events.ClassifyAuthError(err); kind != events.KindError {
		t.Errorf("expected KindError (db not configured -> lua panic), got %v", kind)
	}
}

func TestCallAccounting(t *testing.T) {
	e := testEngine(t, "examples/acct.lua")

	err := e.CallAccounting(&events.AcctRequest{
		NasIp:      "10.0.0.1",
		DeviceMac:  "AA:BB:CC:DD:EE:FF",
		StatusType: "Start",
	})
	if err != nil {
		t.Fatalf("CallAccounting: %v", err)
	}
}

func TestCallPostAuth(t *testing.T) {
	e := testEngine(t, "examples/post_auth.lua")

	err := e.CallPostAuth(&events.AuthRequest{
		DeviceMac: "AA:BB:CC:DD:EE:FF",
	}, &events.AuthResponse{
		PoolName: "default",
	})
	if err != nil {
		t.Fatalf("CallPostAuth: %v", err)
	}
}
