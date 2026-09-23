package script

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/meklis/dhcp-radius-server/clientdb"
	"github.com/meklis/dhcp-radius-server/logger"
	"github.com/meklis/dhcp-radius-server/radius/events"
	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

const (
	funcAuthorize  = "authorize"
	funcAccounting = "accounting"
	funcPostAuth   = "post_auth"
)

// Engine runs one compiled script on a pool of Lua states.
type Engine struct {
	timeout   time.Duration
	pool      chan *lua.LState
	functions map[string]bool
}

// NewEngine compiles the script once and prepares poolSize Lua states.
// A nil store leaves the global db undefined in the script.
func NewEngine(path string, poolSize int, timeout time.Duration, lg *logger.Logger, store *clientdb.Store) (*Engine, error) {
	if poolSize <= 0 {
		poolSize = 5
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("compile script %v: %w", path, err)
	}
	chunk, err := parse.Parse(bufio.NewReader(file), path)
	file.Close()
	if err != nil {
		return nil, fmt.Errorf("compile script %v: parse: %w", path, err)
	}
	proto, err := lua.Compile(chunk, path)
	if err != nil {
		return nil, fmt.Errorf("compile script %v: compile: %w", path, err)
	}

	logFuncs := map[string]lua.LGFunction{}
	for name, logf := range map[string]func(string, ...any){
		"debug":   lg.DebugF,
		"info":    lg.InfoF,
		"notice":  lg.NoticeF,
		"warning": lg.WarningF,
		"error":   lg.ErrorF,
	} {
		logFuncs[name] = func(l *lua.LState) int {
			logf("%v", l.CheckString(1))
			return 0
		}
	}
	dbFuncs := map[string]lua.LGFunction{
		"getDeviceByMac": func(l *lua.LState) int {
			d, ok := store.GetDeviceByMac(l.CheckString(2))
			if !ok {
				l.Push(lua.LNil)
				return 1
			}
			l.Push(toTable(l, d))
			return 1
		},
		"getBind": func(l *lua.LState) int {
			binds := store.FindBinds(l.CheckString(2), optString(l, 3), optString(l, 4), optString(l, 5))
			t := l.NewTable()
			for i, b := range binds {
				t.RawSetInt(i+1, toTable(l, b))
			}
			l.Push(t)
			return 1
		},
	}

	e := &Engine{
		timeout:   timeout,
		pool:      make(chan *lua.LState, poolSize),
		functions: make(map[string]bool),
	}
	for i := 0; i < poolSize; i++ {
		ls := lua.NewState()
		ls.SetGlobal("log", ls.SetFuncs(ls.NewTable(), logFuncs))
		if store != nil {
			ls.SetGlobal("db", ls.SetFuncs(ls.NewTable(), dbFuncs))
		}
		ls.Push(ls.NewFunctionFromProto(proto))
		if err := ls.PCall(0, lua.MultRet, nil); err != nil {
			ls.Close()
			return nil, fmt.Errorf("init lua state #%d: %w", i, err)
		}
		if i == 0 {
			for _, name := range []string{funcAuthorize, funcAccounting, funcPostAuth} {
				_, e.functions[name] = ls.GetGlobal(name).(*lua.LFunction)
			}
		}
		e.pool <- ls
	}

	lg.NoticeF("script engine initialized: path=%v pool_size=%v authorize=%v accounting=%v post_auth=%v",
		path, poolSize, e.functions[funcAuthorize], e.functions[funcAccounting], e.functions[funcPostAuth])
	return e, nil
}

func (e *Engine) Authorize(req *events.AuthRequest) (*events.AuthResponse, error) {
	ret, err := e.call(funcAuthorize, 1, func(ls *lua.LState) []lua.LValue {
		return []lua.LValue{toTable(ls, req)}
	})
	if err != nil {
		return nil, err
	}
	return tableToAuthResponse(ret)
}

func (e *Engine) Accounting(req *events.AcctRequest) error {
	_, err := e.call(funcAccounting, 0, func(ls *lua.LState) []lua.LValue {
		return []lua.LValue{toTable(ls, req)}
	})
	return err
}

func (e *Engine) PostAuth(req *events.AuthRequest, resp *events.AuthResponse) error {
	_, err := e.call(funcPostAuth, 0, func(ls *lua.LState) []lua.LValue {
		return []lua.LValue{toTable(ls, req), toTable(ls, resp)}
	})
	return err
}

// call runs a global script function on a pooled state; the timeout covers
// both waiting for a free state and the execution itself.
func (e *Engine) call(function string, nret int, args func(*lua.LState) []lua.LValue) (lua.LValue, error) {
	if !e.functions[function] {
		return nil, fmt.Errorf("script does not define function %v()", function)
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	var ls *lua.LState
	select {
	case ls = <-e.pool:
	case <-ctx.Done():
		return nil, fmt.Errorf("timed out waiting for a free script worker: %w", ctx.Err())
	}
	defer func() {
		ls.RemoveContext()
		e.pool <- ls
	}()
	ls.SetContext(ctx)

	err := ls.CallByParam(lua.P{Fn: ls.GetGlobal(function), NRet: nret, Protect: true}, args(ls)...)
	if err != nil {
		return nil, fmt.Errorf("%v(): %w", function, err)
	}
	if nret == 0 {
		return lua.LNil, nil
	}
	ret := ls.Get(-1)
	ls.Pop(1)
	return ret, nil
}

// toTable converts a struct (or a pointer to one) into a Lua table keyed by
// json tags. A nil pointer or map becomes an empty table, a fmt.Stringer
// such as net.IP becomes its string.
func toTable(ls *lua.LState, v any) *lua.LTable {
	t := ls.NewTable()
	rv := reflect.Indirect(reflect.ValueOf(v))
	if !rv.IsValid() {
		return t
	}
	for i := 0; i < rv.NumField(); i++ {
		key, _, _ := strings.Cut(rv.Type().Field(i).Tag.Get("json"), ",")
		if key == "" || key == "-" {
			continue
		}
		field := rv.Field(i)
		if s, ok := field.Interface().(fmt.Stringer); ok {
			t.RawSetString(key, lua.LString(s.String()))
			continue
		}
		switch field.Kind() {
		case reflect.String:
			t.RawSetString(key, lua.LString(field.String()))
		case reflect.Int, reflect.Int64:
			t.RawSetString(key, lua.LNumber(field.Int()))
		case reflect.Map:
			m := ls.NewTable()
			for _, k := range field.MapKeys() {
				m.RawSetString(k.String(), lua.LString(field.MapIndex(k).String()))
			}
			t.RawSetString(key, m)
		case reflect.Pointer, reflect.Struct:
			t.RawSetString(key, toTable(ls, field.Interface()))
		}
	}
	return t
}

// fromTable fills struct fields pointed to by v from a Lua table keyed by
// json tags; missing keys and values of the wrong type are left unset.
func fromTable(t *lua.LTable, v any) {
	rv := reflect.ValueOf(v).Elem()
	for i := 0; i < rv.NumField(); i++ {
		key, _, _ := strings.Cut(rv.Type().Field(i).Tag.Get("json"), ",")
		value := t.RawGetString(key)
		if key == "" || key == "-" || value == lua.LNil {
			continue
		}
		field := rv.Field(i)
		switch field.Kind() {
		case reflect.String:
			field.SetString(value.String())
		case reflect.Int, reflect.Int64:
			if n, ok := value.(lua.LNumber); ok {
				field.SetInt(int64(n))
			}
		case reflect.Map:
			if sub, ok := value.(*lua.LTable); ok {
				m := make(map[string]string)
				sub.ForEach(func(k, v lua.LValue) { m[k.String()] = v.String() })
				if len(m) > 0 {
					field.Set(reflect.ValueOf(m))
				}
			}
		}
	}
}

func tableToAuthResponse(ret lua.LValue) (*events.AuthResponse, error) {
	tbl, ok := ret.(*lua.LTable)
	if !ok {
		return nil, errors.New("authorize() must return a table")
	}
	resp := &events.AuthResponse{}
	fromTable(tbl, resp)
	// Class is assigned by the server, not by the script
	resp.Class = ""

	// an explicit reject wins over error if the script set both
	if reject := lua.LVAsString(tbl.RawGetString("reject")); reject != "" {
		return nil, &events.AuthError{Kind: events.KindReject, Err: errors.New(reject), ExtraAttributes: resp.ExtraAttributes}
	}
	if resp.Error != "" {
		return nil, &events.AuthError{Kind: events.KindInvalid, Err: errors.New(resp.Error), ExtraAttributes: resp.ExtraAttributes}
	}
	if resp.IpAddress == "" && resp.PoolName == "" {
		return nil, &events.AuthError{Kind: events.KindInvalid, Err: errors.New("authorize() returned empty ip_address and pool_name"), ExtraAttributes: resp.ExtraAttributes}
	}
	return resp, nil
}

func optString(l *lua.LState, idx int) string {
	if v := l.Get(idx); v != lua.LNil {
		return v.String()
	}
	return ""
}
