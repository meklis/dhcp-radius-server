package clientdb

import (
	"context"
	"fmt"
	"time"

	"github.com/meklis/all-ok-radius-server/prom"
	redis "github.com/redis/go-redis/v9"
)

// RedisConfig - подписка на точечные обновления binds через Redis pub/sub (см.
// BindEvent), в дополнение к периодическому полному reload по HTTP. Полностью
// опциональна: если Addr не задан, подписка не запускается и Store работает как
// раньше, только на периодическом reload.
type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	Channel  string `yaml:"channel"` // канал pub/sub, в который внешняя система публикует BindEvent (JSON)
}

// subscribeRedis поднимает фоновую подписку на канал с точечными изменениями binds.
// Останавливается при закрытии s.stop (см. Store.Close). Вызывается синхронно из
// New() до старта фонового reload-цикла - ошибка подписки (misconfiguration, сеть)
// является fail-fast, как и остальная обязательная конфигурация в New().
func (s *Store) subscribeRedis(conf RedisConfig) error {
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
		ch := sub.Channel()
		for {
			select {
			case <-s.stop:
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				s.handleRedisMessage(msg.Payload)
			}
		}
	}()

	go s.watchRedisConnection(client)

	s.lg.NoticeF("clientdb: subscribed to point binds updates via redis %v channel %q", conf.Addr, conf.Channel)
	return nil
}

// watchRedisConnection periodically pings redis to track connection status
// (rad_clientdb_redis_connected) independently of the pub/sub subscription itself -
// go-redis reconnects the subscription internally on transient network errors and
// does not expose that disconnect/reconnect state, so a separate health check is
// the only reliable way to observe it.
func (s *Store) watchRedisConnection(client *redis.Client) {
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
}
