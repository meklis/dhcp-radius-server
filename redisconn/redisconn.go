// Package redisconn holds the global named Redis servers (the root "redis"
// config section). It is unrelated to the clientdb live-update connection.
package redisconn

import (
	"fmt"

	redis "github.com/redis/go-redis/v9"
)

// ServerConfig describes the connection to one Redis server.
type ServerConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

// Config maps a server key to its connection settings.
type Config map[string]ServerConfig

// Clients maps a server key to its shared client.
type Clients map[string]*redis.Client

// New creates a client per server. Clients connect lazily, so an unreachable
// server is reported on first use, not here.
func New(conf Config) (Clients, error) {
	clients := make(Clients, len(conf))
	for key, server := range conf {
		if server.Addr == "" {
			return nil, fmt.Errorf("redis.%v.addr not set", key)
		}
		clients[key] = redis.NewClient(&redis.Options{
			Addr:     server.Addr,
			Password: server.Password,
			DB:       server.DB,
		})
	}
	return clients, nil
}

// Get returns the client configured under key.
func (c Clients) Get(key string) (*redis.Client, error) {
	client, ok := c[key]
	if !ok {
		return nil, fmt.Errorf("redis server %q is not defined in the redis section", key)
	}
	return client, nil
}
