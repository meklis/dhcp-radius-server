package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRedisServers(t *testing.T) {
	t.Setenv("REDIS_ADDR", "")
	t.Setenv("REDIS_PASSWORD", "secret")
	path := filepath.Join(t.TempDir(), "conf.yml")
	err := os.WriteFile(path, []byte(`
redis:
  main:
    addr: ${REDIS_ADDR:-localhost:6379}
    password: ${REDIS_PASSWORD:-}
    db: 0
  sessions:
    addr: redis-sessions:6380
    db: 2
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	conf, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(conf.Redis) != 2 {
		t.Fatalf("expected 2 servers, got %+v", conf.Redis)
	}
	if got := conf.Redis["main"]; got.Addr != "localhost:6379" || got.Password != "secret" || got.DB != 0 {
		t.Fatalf("unexpected redis.main: %+v", got)
	}
	if got := conf.Redis["sessions"]; got.Addr != "redis-sessions:6380" || got.Password != "" || got.DB != 2 {
		t.Fatalf("unexpected redis.sessions: %+v", got)
	}
}
