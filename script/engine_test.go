package script

import (
	"testing"
	"time"

	"github.com/meklis/dhcp-radius-server/radius/events"
)

func testEngine(t *testing.T, path string) *Engine {
	t.Helper()
	e, err := NewEngine(path, 2, time.Second, testLogger(t), nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// dlinkCircuitID - vlan=101 (0x0065), stack=0, port=3 - см. смещения в examples/auth.lua
const dlinkCircuitID = "000000650003"

func TestAuthorizeError(t *testing.T) {
	e := testEngine(t, "examples/auth.lua")

	// без db тип оборудования неизвестен -> circuit_id не распознан -> отказ
	// (позитивные сценарии - в db_test.go, т.к. теперь требуют db.devices)
	_, err := e.Authorize(&events.AuthRequest{
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
	// без store глобальная переменная db не создаётся вовсе (см. engine.go:NewEngine) -
	// authorize() падает на индексации nil, это Lua-паника (инфраструктурная
	// проблема, KindError), а не бизнес-решение скрипта (KindInvalid) - для
	// последнего см. TestTableToAuthResponse в convert_test.go
	if kind := events.ClassifyAuthError(err); kind != events.KindError {
		t.Errorf("expected KindError (db not configured -> lua panic), got %v", kind)
	}
}

func TestAccounting(t *testing.T) {
	e := testEngine(t, "examples/acct.lua")

	err := e.Accounting(&events.AcctRequest{
		NasIp:      "10.0.0.1",
		DeviceMac:  "AA:BB:CC:DD:EE:FF",
		StatusType: "Start",
	})
	if err != nil {
		t.Fatalf("Accounting: %v", err)
	}
}

func TestPostAuth(t *testing.T) {
	e := testEngine(t, "examples/post_auth.lua")

	err := e.PostAuth(&events.AuthRequest{
		DeviceMac: "AA:BB:CC:DD:EE:FF",
	}, &events.AuthResponse{
		PoolName: "default",
	})
	if err != nil {
		t.Fatalf("PostAuth: %v", err)
	}
}
