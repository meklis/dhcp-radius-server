package cache

import (
	"github.com/meklis/dhcp-radius-server/prom"
	"github.com/meklis/dhcp-radius-server/radius/events"
	"github.com/meklis/go-cache"
	"time"
)

type CacheApi struct {
	responses *cache.Cache
}

func Init(expireTimeout time.Duration) *CacheApi {
	c := new(CacheApi)
	c.responses = cache.New(expireTimeout, 10*time.Minute)
	go func() {
		for {
			prom.SetCacheSize(c.responses.ItemCount())
			time.Sleep(time.Second * 3)
		}
	}()
	return c
}

func (c *CacheApi) Get(hash string) (*events.AuthResponse, bool) {
	if resp, exist := c.responses.Get(hash); exist {
		ret := resp.(events.AuthResponse)
		return &ret, true
	} else {
		return nil, false
	}
}

func (c *CacheApi) Set(hash string, resp events.AuthResponse) *CacheApi {
	c.responses.SetDefault(hash, resp)
	return c
}
