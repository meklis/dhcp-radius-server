package script

import (
	"errors"

	"github.com/meklis/all-ok-radius-server/logger"
	"github.com/meklis/all-ok-radius-server/radius/events"
	lua "github.com/yuin/gopher-lua"
)

func registerHelpers(ls *lua.LState, lg *logger.Logger) {
	logTbl := ls.NewTable()
	ls.SetFuncs(logTbl, map[string]lua.LGFunction{
		"debug": func(l *lua.LState) int {
			lg.DebugF("%v", l.CheckString(1))
			return 0
		},
		"info": func(l *lua.LState) int {
			lg.InfoF("%v", l.CheckString(1))
			return 0
		},
		"notice": func(l *lua.LState) int {
			lg.NoticeF("%v", l.CheckString(1))
			return 0
		},
		"warning": func(l *lua.LState) int {
			lg.WarningF("%v", l.CheckString(1))
			return 0
		},
		"error": func(l *lua.LState) int {
			lg.ErrorF("%v", l.CheckString(1))
			return 0
		},
	})
	ls.SetGlobal("log", logTbl)
}

func authRequestToTable(L *lua.LState, r *events.AuthRequest) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("nas_ip", lua.LString(r.NasIp))
	t.RawSetString("nas_name", lua.LString(r.NasName))
	t.RawSetString("device_mac", lua.LString(r.DeviceMac))
	t.RawSetString("dhcp_server_name", lua.LString(r.DhcpServerName))
	t.RawSetString("dhcp_server_id", lua.LString(r.DhcpServerId))
	t.RawSetString("ip_address", lua.LString(r.FramedIpAddress))
	t.RawSetString("class_id", lua.LString(r.Class))

	opt := L.NewTable()
	if r.AgentOption != nil {
		opt.RawSetString("remote_id", lua.LString(r.AgentOption.RemoteId))
		opt.RawSetString("circuit_id", lua.LString(r.AgentOption.RawCircuitId))
	}
	t.RawSetString("option", opt)
	return t
}

func authResponseToTable(L *lua.LState, r *events.AuthResponse) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("ip_address", lua.LString(r.IpAddress))
	t.RawSetString("pool_name", lua.LString(r.PoolName))
	t.RawSetString("lease_time_sec", lua.LNumber(r.LeaseTimeSec))
	t.RawSetString("status", lua.LString(r.Status))
	t.RawSetString("error", lua.LString(r.Error))
	t.RawSetString("class_id", lua.LString(r.Class))
	t.RawSetString("extra_attributes", stringMapToTable(L, r.ExtraAttributes))
	return t
}

func acctRequestToTable(L *lua.LState, r *events.AcctRequest) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("nas_ip", lua.LString(r.NasIp))
	t.RawSetString("nas_name", lua.LString(r.NasName))
	t.RawSetString("device_mac", lua.LString(r.DeviceMac))
	t.RawSetString("dhcp_server_name", lua.LString(r.DhcpServerName))
	t.RawSetString("dhcp_server_id", lua.LString(r.DhcpServerId))
	t.RawSetString("ip_address", lua.LString(r.FramedIpAddress))
	t.RawSetString("auth_type", lua.LString(r.AuthType))
	t.RawSetString("class_id", lua.LString(r.Class))
	t.RawSetString("status_type", lua.LString(r.StatusType))
	t.RawSetString("session_time", lua.LNumber(r.SessionTime))
	t.RawSetString("terminate_cause", lua.LString(r.TerminateCause))
	t.RawSetString("input_octets", lua.LNumber(r.InputOctets))
	t.RawSetString("output_octets", lua.LNumber(r.OutputOctets))
	t.RawSetString("pool_name", lua.LString(r.PoolName))
	t.RawSetString("session_id", lua.LString(r.SessionId))
	return t
}

func tableToAuthResponse(ret lua.LValue) (*events.AuthResponse, error) {
	tbl, ok := ret.(*lua.LTable)
	if !ok {
		return nil, errors.New("authorize() must return a table")
	}

	extraAttrs := getTableStringMap(tbl, "extra_attributes")
	resp := &events.AuthResponse{
		IpAddress:       getTableString(tbl, "ip_address"),
		PoolName:        getTableString(tbl, "pool_name"),
		LeaseTimeSec:    getTableInt(tbl, "lease_time_sec"),
		Status:          getTableString(tbl, "status"),
		Error:           getTableString(tbl, "error"),
		ExtraAttributes: extraAttrs,
	}

	// reject - явное бизнес-решение скрипта отказать этому устройству (аналог
	// RLM_MODULE_REJECT в legacy Perl-скрипте, см. script.pl). Проверяется раньше
	// error - если скрипт зачем-то заполнил оба поля, явный отказ приоритетнее
	if reject := getTableString(tbl, "reject"); reject != "" {
		return nil, events.NewRejectErrorWithAttrs(errors.New(reject), extraAttrs)
	}
	// error - скрипт определил, что не может разобрать/обслужить этот конкретный
	// запрос (например не распарсился circuit_id) - аналог RLM_MODULE_INVALID
	if resp.Error != "" {
		return nil, events.NewInvalidErrorWithAttrs(errors.New(resp.Error), extraAttrs)
	}
	if resp.IpAddress == "" && resp.PoolName == "" {
		return nil, events.NewInvalidErrorWithAttrs(errors.New("authorize() returned empty ip_address and pool_name"), extraAttrs)
	}
	return resp, nil
}

func getTableString(t *lua.LTable, key string) string {
	v := t.RawGetString(key)
	if v == lua.LNil {
		return ""
	}
	return v.String()
}

func getTableInt(t *lua.LTable, key string) int {
	v := t.RawGetString(key)
	if n, ok := v.(lua.LNumber); ok {
		return int(n)
	}
	return 0
}

// getTableStringMap читает t[key] как таблицу вида {[string]=string, ...} (не массив).
// Отсутствующее поле или не-таблица - nil, без ошибки (поле опционально).
func getTableStringMap(t *lua.LTable, key string) map[string]string {
	sub, ok := t.RawGetString(key).(*lua.LTable)
	if !ok {
		return nil
	}
	var out map[string]string
	sub.ForEach(func(k, v lua.LValue) {
		if out == nil {
			out = make(map[string]string)
		}
		out[k.String()] = v.String()
	})
	return out
}

func stringMapToTable(L *lua.LState, m map[string]string) *lua.LTable {
	t := L.NewTable()
	for k, v := range m {
		t.RawSetString(k, lua.LString(v))
	}
	return t
}
