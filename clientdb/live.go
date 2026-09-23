package clientdb

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/meklis/dhcp-radius-server/macaddr"
	"github.com/meklis/dhcp-radius-server/prom"
	redis "github.com/redis/go-redis/v9"
)

// RedisConfig enables live bind updates (see BindEvent). Empty Addr disables them.
type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	Channel  string `yaml:"channel"`
}

// BindEvent is a single-record change published to Redis by the external system:
//
//	{"db_type":"clients","action":"delete","object":{"id":123}}
//	{"db_type":"clients","action":"add","object":{"id":123,"ip":16909060,"mac":"AABBCCDDEEFF","device_mac":"AABBCCDDEEFF","port":44}}
//
// db_type is a key of Config.Binds. "add" and "update" both upsert by id;
// device_mac and port are optional.
type BindEvent struct {
	DBType string          `json:"db_type"`
	Action string          `json:"action"`
	Object BindEventObject `json:"object"`
}

type BindEventObject struct {
	ID        json.Number `json:"id"`
	IP        json.Number `json:"ip"`
	Mac       string      `json:"mac"`
	DeviceMac string      `json:"device_mac"`
	Port      json.Number `json:"port"`
}

func (s *Store) subscribeRedis() error {
	conf := s.conf.Redis
	if conf.Addr == "" {
		return nil
	}
	if conf.Channel == "" {
		return fmt.Errorf("redis.channel not set")
	}

	client := redis.NewClient(&redis.Options{
		Addr:     conf.Addr,
		Password: conf.Password,
		DB:       conf.DB,
	})
	ctx := context.Background()
	sub := client.Subscribe(ctx, conf.Channel)
	if _, err := sub.Receive(ctx); err != nil {
		sub.Close()
		client.Close()
		prom.SetClientDBRedisConnected(false)
		return fmt.Errorf("subscribe %q: %w", conf.Channel, err)
	}
	prom.SetClientDBRedisConnected(true)

	go func() {
		defer client.Close()
		defer sub.Close()
		defer prom.SetClientDBRedisConnected(false)
		messages := sub.Channel()
		for {
			select {
			case <-s.stop:
				return
			case msg, ok := <-messages:
				if !ok {
					return
				}
				s.lg.DebugF("clientdb: live-update: received message from redis: %v", msg.Payload)
				prom.SetClientDBLastLiveUpdate(time.Now().Unix())
				var ev BindEvent
				if err := json.Unmarshal([]byte(msg.Payload), &ev); err != nil {
					s.lg.ErrorF("clientdb: live-update: invalid json from redis: %v", err)
					prom.IncClientDBLiveUpdateError("")
					continue
				}
				prom.IncClientDBLiveUpdate(ev.DBType)
				if err := s.ApplyBindEvent(ev); err != nil {
					s.lg.ErrorF("clientdb: live-update: %v", err)
					prom.IncClientDBLiveUpdateError(ev.DBType)
				}
			}
		}
	}()

	// go-redis silently reconnects the subscription and does not expose its
	// state, so connection health is tracked with pings
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				err := client.Ping(ctx).Err()
				cancel()
				prom.SetClientDBRedisConnected(err == nil)
				if err != nil {
					s.lg.WarningF("clientdb: redis ping failed: %v", err)
				}
			}
		}
	}()

	s.lg.NoticeF("clientdb: subscribed to point binds updates via redis %v channel %q", conf.Addr, conf.Channel)
	return nil
}

// ApplyBindEvent patches a single bind. During a reload the event is queued
// and applied once the new snapshot is published.
func (s *Store) ApplyBindEvent(ev BindEvent) error {
	s.pendingMu.Lock()
	if s.reloading {
		s.pending = append(s.pending, ev)
		s.pendingMu.Unlock()
		return nil
	}
	s.pendingMu.Unlock()
	return s.applyBindEvent(ev)
}

func (s *Store) applyBindEvent(ev BindEvent) error {
	idx, ok := s.current().binds[ev.DBType]
	if !ok {
		return fmt.Errorf("live-update for non-existent source binds.%v", ev.DBType)
	}
	id := string(ev.Object.ID)
	if id == "" {
		return fmt.Errorf("live-update: object.id not set (binds.%v)", ev.DBType)
	}

	switch ev.Action {
	case "delete":
		idx.mu.Lock()
		existed := idx.remove(id)
		count := len(idx.byID)
		idx.mu.Unlock()
		prom.SetClientDBBinds(ev.DBType, count)
		s.lg.NoticeF("clientdb: live-update: binds.%v id=%v deleted (existed=%v)", ev.DBType, id, existed)
		return nil
	case "add", "update":
		mac := macaddr.Normalize(ev.Object.Mac)
		if mac == "" {
			return fmt.Errorf("live-update: object.mac not set (binds.%v id=%v)", ev.DBType, id)
		}
		ip := intToIP(string(ev.Object.IP))
		if ip == nil {
			return fmt.Errorf("live-update: object.ip not recognized (binds.%v id=%v): %q", ev.DBType, id, ev.Object.IP)
		}
		b := &Bind{ID: id, IP: ip, ClientMac: mac}
		if deviceMac := macaddr.Normalize(ev.Object.DeviceMac); deviceMac != "" {
			b.DeviceMac = deviceMac
			b.Port, _ = strconv.Atoi(string(ev.Object.Port))
		}
		idx.mu.Lock()
		existed := idx.put(b)
		count := len(idx.byID)
		idx.mu.Unlock()
		prom.SetClientDBBinds(ev.DBType, count)
		s.lg.NoticeF("clientdb: live-update: binds.%v id=%v %v (existed=%v): ip=%v mac=%v device_mac=%v port=%v",
			ev.DBType, id, ev.Action, existed, b.IP, b.ClientMac, b.DeviceMac, b.Port)
		return nil
	default:
		return fmt.Errorf("live-update: unknown action %q (binds.%v id=%v)", ev.Action, ev.DBType, id)
	}
}
