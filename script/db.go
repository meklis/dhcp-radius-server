package script

import (
	"github.com/meklis/dhcp-radius-server/clientdb"
	lua "github.com/yuin/gopher-lua"
)

// registerDB - глобальный объект db с методами доступа к внешней базе
// устройств/смартов/привязок. Если store не задан (script.database не
// сконфигурирован) - глобальная переменная db не создаётся
func registerDB(ls *lua.LState, store *clientdb.Store) {
	if store == nil {
		return
	}

	tbl := ls.NewTable()
	ls.SetFuncs(tbl, map[string]lua.LGFunction{
		"getDeviceByMac": func(l *lua.LState) int {
			d, ok := store.GetDeviceByMac(l.CheckString(2))
			if !ok {
				l.Push(lua.LNil)
				return 1
			}
			t := l.NewTable()
			t.RawSetString("ip", lua.LString(d.IP.String()))
			t.RawSetString("mac", lua.LString(d.Mac))
			t.RawSetString("parse_type", lua.LString(d.ParseType))
			l.Push(t)
			return 1
		},
		"getBind": func(l *lua.LState) int {
			dbName := l.CheckString(2)
			mac := optString(l, 3)
			deviceMac := optString(l, 4)
			port := optString(l, 5)

			binds := store.GetBind(dbName, mac, deviceMac, port)
			t := l.NewTable()
			for i, b := range binds {
				row := l.NewTable()
				row.RawSetString("ip", lua.LString(b.IP.String()))
				row.RawSetString("port", lua.LNumber(b.Port))
				row.RawSetString("client_mac", lua.LString(b.ClientMac))
				row.RawSetString("device_mac", lua.LString(b.DeviceMac))
				t.RawSetInt(i+1, row)
			}
			l.Push(t)
			return 1
		},
	})
	ls.SetGlobal("db", tbl)
}

// optString - необязательный строковый аргумент getBind (mac/device_mac/port)
func optString(l *lua.LState, idx int) string {
	v := l.Get(idx)
	if v == lua.LNil {
		return ""
	}
	return v.String()
}
