package clientdb

import (
	"context"
	"fmt"

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
		return fmt.Errorf("subscribe %q: %w", conf.Channel, err)
	}

	go func() {
		defer client.Close()
		defer sub.Close()
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

	s.lg.NoticeF("clientdb: subscribed to point binds updates via redis %v channel %q", conf.Addr, conf.Channel)
	return nil
}
