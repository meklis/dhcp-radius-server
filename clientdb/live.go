package clientdb

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// BindEvent - точечное изменение одной записи в bind-источнике (см. Config.Binds),
// приходит через Redis pub/sub в дополнение к периодическому полному reload по HTTP.
// В отличие от reload, применяется без перезагрузки всего источника - патчит по
// месту только запись с данным id, остальные записи не затрагиваются.
//
// Формат сообщения (JSON) задан внешней системой:
//
//	{"db_type":"binds","action":"delete","object":{"id":123}}
//	{"db_type":"binds","action":"add","object":{"id":123,"ip":16909060,"mac":"AABBCCDDEEFF","device_mac":"AABBCCDDEEFF","port":44}}
//	{"db_type":"binds","action":"update","object":{"id":123,"ip":16909060,"mac":"AABBCCDDEEFF","device_mac":"AABBCCDDEEFF","port":44}}
//
// db_type должен совпадать с одним из ключей Config.Binds (например "clients"/"smart",
// или один ключ "binds", если у источника только одно имя). device_mac/port опциональны -
// их отсутствие/пустое значение означает запись без привязки к устройству/порту (как у
// "smart" в HTTP-источнике). "add" и "update" оба означают upsert по object.id: если
// запись с таким id уже есть - заменяется целиком, если нет - создаётся.
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

// handleRedisMessage - точка входа для сообщений из Redis pub/sub (см. subscribeRedis).
func (s *Store) handleRedisMessage(payload string) {
	var ev BindEvent
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		s.lg.ErrorF("clientdb: live-update: невалидный json от redis: %v", err)
		return
	}
	if err := s.ApplyBindEvent(ev); err != nil {
		s.lg.ErrorF("clientdb: live-update: %v", err)
	}
}

// ApplyBindEvent применяет точечное изменение (см. BindEvent), не затрагивая
// остальные записи и не запуская полный reload. Если в этот момент выполняется
// reload() (от начала HTTP-запроса к источнику до фактической подмены снапшота) -
// событие не применяется сразу, а откладывается (см. Store.pendingLive) и
// накатывается на актуальный снапшот сразу после reload (см. finishReload) - иначе
// оно применилось бы к снапшоту, который через мгновение целиком заменят, и было
// бы потеряно. Вне окна reload применяется немедленно, как и раньше.
func (s *Store) ApplyBindEvent(ev BindEvent) error {
	s.liveMu.Lock()
	if s.reloading {
		s.pendingLive = append(s.pendingLive, ev)
		s.liveMu.Unlock()
		return nil
	}
	s.liveMu.Unlock()
	return s.applyBindEventNow(ev)
}

// applyBindEventNow - собственно применение события к текущему снапшоту (см.
// ApplyBindEvent про откладывание на время reload).
func (s *Store) applyBindEventNow(ev BindEvent) error {
	idx, ok := s.currentSnapshot().binds[ev.DBType]
	if !ok {
		return fmt.Errorf("live-update для несуществующего источника binds.%v", ev.DBType)
	}

	id := string(ev.Object.ID)
	if id == "" {
		return fmt.Errorf("live-update: object.id не задан (binds.%v)", ev.DBType)
	}

	switch ev.Action {
	case "delete":
		existed := idx.deleteByID(id)
		s.lg.NoticeF("clientdb: live-update: binds.%v id=%v удалена (была=%v)", ev.DBType, id, existed)
		return nil
	case "add", "update":
		mac := normalizeMac(ev.Object.Mac)
		if mac == "" {
			return fmt.Errorf("live-update: object.mac не задан (binds.%v id=%v)", ev.DBType, id)
		}
		ip := intToIP(string(ev.Object.IP))
		if ip == nil {
			return fmt.Errorf("live-update: object.ip не распознан (binds.%v id=%v): %q", ev.DBType, id, ev.Object.IP)
		}
		b := &Bind{ID: id, IP: ip, ClientMac: mac}
		if deviceMac := normalizeMac(ev.Object.DeviceMac); deviceMac != "" {
			b.DeviceMac = deviceMac
			b.Port, _ = strconv.Atoi(string(ev.Object.Port))
		}
		existed := idx.upsert(b)
		s.lg.NoticeF("clientdb: live-update: binds.%v id=%v %v (была=%v): ip=%v mac=%v device_mac=%v port=%v",
			ev.DBType, id, ev.Action, existed, b.IP, b.ClientMac, b.DeviceMac, b.Port)
		return nil
	default:
		return fmt.Errorf("live-update: неизвестный action %q (binds.%v id=%v)", ev.Action, ev.DBType, id)
	}
}
