package redisconn

import "testing"

func TestNewAndGet(t *testing.T) {
	clients, err := New(Config{
		"main":  {Addr: "localhost:6379"},
		"state": {Addr: "redis-state:6380", Password: "secret", DB: 2},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	client, err := clients.Get("state")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	opts := client.Options()
	if opts.Addr != "redis-state:6380" || opts.Password != "secret" || opts.DB != 2 {
		t.Fatalf("unexpected options: %+v", opts)
	}
}

func TestNewRequiresAddr(t *testing.T) {
	if _, err := New(Config{"main": {}}); err == nil {
		t.Fatal("expected error for empty addr")
	}
}

func TestGetUnknownServer(t *testing.T) {
	var clients Clients
	if _, err := clients.Get("main"); err == nil {
		t.Fatal("expected error for unknown server")
	}
}
