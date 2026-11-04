package script

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/meklis/dhcp-radius-server/radius/events"
	"github.com/meklis/dhcp-radius-server/redisconn"
	redis "github.com/redis/go-redis/v9"
)

// startRedis runs a throwaway redis-server and returns its address.
func startRedis(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("redis-server")
	if err != nil {
		t.Skip("redis-server not installed")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cmd := exec.Command(bin, "--port", fmt.Sprint(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no")
	cmd.Dir = t.TempDir()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for range 100 {
		if conn, err := net.Dial("tcp", addr); err == nil {
			conn.Close()
			return addr
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("redis-server did not start on %v", addr)
	return ""
}

// unreachableRedis lets the example scripts run without a server: publishing
// fails fast and the scripts only log it.
func unreachableRedis() redisconn.Clients {
	return redisconn.Clients{"main": redis.NewClient(&redis.Options{
		Addr:          "127.0.0.1:1",
		MaxRetries:    -1,
		DialerRetries: 1,
	})}
}

func luaEngine(t *testing.T, source string, clients redisconn.Clients) *Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acct.lua")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(path, 1, 2*time.Second, testLogger(t), nil, clients)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestRedisMethods(t *testing.T) {
	clients, err := redisconn.New(redisconn.Config{"main": {Addr: startRedis(t)}})
	if err != nil {
		t.Fatal(err)
	}
	client, _ := clients.Get("main")
	ctx := context.Background()
	sub := client.Subscribe(ctx, "events")
	defer sub.Close()
	if _, err := sub.Receive(ctx); err != nil {
		t.Fatal(err)
	}

	e := luaEngine(t, `
function accounting(request)
    assert(redis.main:set("plain", "value") == true)
    assert(redis.main:get("plain") == "value")
    assert(redis.main:set("expiring", 42, 100) == true)
    assert(redis.main:get("expiring") == "42")

    local missing, err = redis.main:get("missing")
    assert(missing == nil and err == nil)

    assert(redis.main:incr("counter") == 1)
    assert(redis.main:incr("counter", 5) == 6)

    assert(redis.main:del("plain") == 1)
    assert(redis.main:del("plain") == 0)

    assert(redis.main:publish("events", "hello") == 1)
end`, clients)
	if err := e.Accounting(&events.AcctRequest{}); err != nil {
		t.Fatalf("Accounting: %v", err)
	}

	if ttl := client.TTL(ctx, "expiring").Val(); ttl <= 0 || ttl > 100*time.Second {
		t.Fatalf("unexpected ttl: %v", ttl)
	}
	msg, err := sub.ReceiveMessage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Payload != "hello" {
		t.Fatalf("unexpected message: %q", msg.Payload)
	}
}

func TestRedisEncodesValues(t *testing.T) {
	clients, err := redisconn.New(redisconn.Config{"main": {Addr: startRedis(t)}})
	if err != nil {
		t.Fatal(err)
	}
	client, _ := clients.Get("main")
	ctx := context.Background()
	sub := client.Subscribe(ctx, "events")
	defer sub.Close()
	if _, err := sub.Receive(ctx); err != nil {
		t.Fatal(err)
	}

	e := luaEngine(t, `
function accounting(request)
    assert(redis.main:set("table", {id = 1, name = "x"}))
    assert(redis.main:set("array", {1, 2}))
    assert(redis.main:set("string", '{"raw"'))
    assert(redis.main:set("number", 1.5))
    assert(redis.main:set("bool", true))
    assert(redis.main:publish("events", {id = 1}) == 1)
    assert(json.decode(redis.main:get("table")).name == "x")

    local ok, err = redis.main:set("function", print)
    assert(ok == nil and err ~= nil)
    local receivers, err = redis.main:publish("events", {f = print})
    assert(receivers == nil and err ~= nil)
end`, clients)
	if err := e.Accounting(&events.AcctRequest{}); err != nil {
		t.Fatalf("Accounting: %v", err)
	}

	for key, expected := range map[string]string{
		"table":  `{"id":1,"name":"x"}`,
		"array":  `[1,2]`,
		"string": `{"raw"`,
		"number": `1.5`,
		"bool":   `true`,
	} {
		if got := client.Get(ctx, key).Val(); got != expected {
			t.Fatalf("%v: got %q, expected %q", key, got, expected)
		}
	}
	msg, err := sub.ReceiveMessage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Payload != `{"id":1}` {
		t.Fatalf("unexpected message: %q", msg.Payload)
	}
}

func TestExampleScriptsPublishEvents(t *testing.T) {
	clients, err := redisconn.New(redisconn.Config{"main": {Addr: startRedis(t)}})
	if err != nil {
		t.Fatal(err)
	}
	client, _ := clients.Get("main")
	ctx := context.Background()
	sub := client.Subscribe(ctx, "radius-post-auth-events", "radius-acct-events")
	defer sub.Close()
	for range 2 {
		if _, err := sub.Receive(ctx); err != nil {
			t.Fatal(err)
		}
	}
	engine := func(path string) *Engine {
		e, err := NewEngine(path, 1, 2*time.Second, testLogger(t), nil, clients)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		return e
	}
	receive := func(channel string, event any) {
		t.Helper()
		msg, err := sub.ReceiveMessage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Channel != channel {
			t.Fatalf("message in channel %q, expected %q", msg.Channel, channel)
		}
		if err := json.Unmarshal([]byte(msg.Payload), event); err != nil {
			t.Fatalf("invalid json %q: %v", msg.Payload, err)
		}
	}
	type postAuthEvent struct {
		Time     int64               `json:"time"`
		Request  events.AuthRequest  `json:"request"`
		Response events.AuthResponse `json:"response"`
	}

	postAuth := engine("examples/post_auth.lua")
	req := &events.AuthRequest{
		DeviceMac:   "AA:BB:CC:DD:EE:FF",
		AgentOption: &events.AuthRequestOption{RemoteId: "08:5A:11:94:65:E0", RawCircuitId: "00"},
	}
	err = postAuth.PostAuth(req, &events.AuthResponse{
		Status:          "REJECT",
		Error:           "denied",
		ExtraAttributes: map[string]string{"Reply-Message": "vlan=101;port=9"},
	})
	if err != nil {
		t.Fatalf("PostAuth: %v", err)
	}
	var rejected postAuthEvent
	receive("radius-post-auth-events", &rejected)
	if rejected.Time == 0 || rejected.Request.DeviceMac != req.DeviceMac || rejected.Request.AgentOption.RemoteId != "08:5A:11:94:65:E0" {
		t.Fatalf("unexpected event: %+v", rejected)
	}
	if rejected.Response.Status != "REJECT" || rejected.Response.Error != "denied" ||
		rejected.Response.ExtraAttributes["Reply-Message"] != "vlan=101;port=9" {
		t.Fatalf("unexpected response: %+v", rejected.Response)
	}

	if err := postAuth.PostAuth(req, &events.AuthResponse{PoolName: "pool"}); err != nil {
		t.Fatalf("PostAuth: %v", err)
	}
	var accepted postAuthEvent
	receive("radius-post-auth-events", &accepted)
	if accepted.Response.Status != "ACCEPT" || accepted.Response.PoolName != "pool" {
		t.Fatalf("unexpected response: %+v", accepted.Response)
	}

	acct := &events.AcctRequest{DeviceMac: "AA:BB:CC:DD:EE:FF", StatusType: "Stop", SessionTime: 60, InputOctets: 5}
	if err := engine("examples/acct.lua").Accounting(acct); err != nil {
		t.Fatalf("Accounting: %v", err)
	}
	var acctEvent struct {
		Time    int64              `json:"time"`
		Request events.AcctRequest `json:"request"`
	}
	receive("radius-acct-events", &acctEvent)
	if acctEvent.Time == 0 || acctEvent.Request != *acct {
		t.Fatalf("unexpected event: %+v", acctEvent)
	}
}

func TestRedisNilValueAbortsScript(t *testing.T) {
	clients, err := redisconn.New(redisconn.Config{"main": {Addr: "127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	e := luaEngine(t, `
function accounting(request)
    redis.main:set("key", nil)
end`, clients)
	if err := e.Accounting(&events.AcctRequest{}); err == nil {
		t.Fatal("expected an error for a nil value")
	}
}

func TestRedisErrorIsReturnedToScript(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()

	clients, err := redisconn.New(redisconn.Config{"main": {Addr: addr}})
	if err != nil {
		t.Fatal(err)
	}
	e := luaEngine(t, `
function accounting(request)
    local ok, err = redis.main:set("key", "value")
    assert(ok == nil and err ~= nil)
end`, clients)
	if err := e.Accounting(&events.AcctRequest{}); err != nil {
		t.Fatalf("Accounting: %v", err)
	}
}

func TestRedisGlobalUndefinedWithoutServers(t *testing.T) {
	e := luaEngine(t, `
function accounting(request)
    assert(redis == nil)
end`, nil)
	if err := e.Accounting(&events.AcctRequest{}); err != nil {
		t.Fatalf("Accounting: %v", err)
	}
}
