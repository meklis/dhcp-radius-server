package script

import (
	"bufio"
	"context"
	"fmt"
	"os"
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

type Engine struct {
	path      string
	timeout   time.Duration
	lg        *logger.Logger
	proto     *lua.FunctionProto
	functions map[string]bool
	pool      chan *lua.LState
	store     *clientdb.Store
}

// New компилирует скрипт path один раз и прогревает пул из poolSize Lua-состояний.
// store может быть nil - тогда глобальная переменная db в скрипте не создаётся
func New(path string, poolSize int, timeout time.Duration, lg *logger.Logger, store *clientdb.Store) (*Engine, error) {
	if poolSize <= 0 {
		poolSize = 5
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	proto, err := compileFile(path)
	if err != nil {
		return nil, fmt.Errorf("compile script %v: %w", path, err)
	}

	e := &Engine{
		path:      path,
		timeout:   timeout,
		lg:        lg,
		proto:     proto,
		functions: make(map[string]bool),
		pool:      make(chan *lua.LState, poolSize),
		store:     store,
	}

	for i := 0; i < poolSize; i++ {
		ls, err := e.newState()
		if err != nil {
			return nil, fmt.Errorf("init lua state #%d: %w", i, err)
		}
		if i == 0 {
			for _, name := range []string{funcAuthorize, funcAccounting, funcPostAuth} {
				if fn, ok := ls.GetGlobal(name).(*lua.LFunction); ok && fn != nil {
					e.functions[name] = true
				}
			}
		}
		e.pool <- ls
	}

	lg.NoticeF("script engine initialized: path=%v pool_size=%v authorize=%v accounting=%v post_auth=%v",
		path, poolSize, e.functions[funcAuthorize], e.functions[funcAccounting], e.functions[funcPostAuth])
	return e, nil
}

func compileFile(path string) (*lua.FunctionProto, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	chunk, err := parse.Parse(bufio.NewReader(file), path)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	proto, err := lua.Compile(chunk, path)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	return proto, nil
}

func (e *Engine) newState() (*lua.LState, error) {
	ls := lua.NewState()
	registerHelpers(ls, e.lg)
	registerDB(ls, e.store)
	lfunc := ls.NewFunctionFromProto(e.proto)
	ls.Push(lfunc)
	if err := ls.PCall(0, lua.MultRet, nil); err != nil {
		ls.Close()
		return nil, err
	}
	return ls, nil
}

func (e *Engine) HasAuthorize() bool  { return e.functions[funcAuthorize] }
func (e *Engine) HasAccounting() bool { return e.functions[funcAccounting] }
func (e *Engine) HasPostAuth() bool   { return e.functions[funcPostAuth] }
func (e *Engine) PoolSize() int       { return cap(e.pool) }

func (e *Engine) acquire(ctx context.Context) (*lua.LState, error) {
	select {
	case ls := <-e.pool:
		return ls, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("timed out waiting for a free script worker: %w", ctx.Err())
	}
}

func (e *Engine) release(ls *lua.LState) {
	ls.RemoveContext()
	select {
	case e.pool <- ls:
	default:
		ls.Close()
	}
}

func (e *Engine) CallAuthorize(req *events.AuthRequest) (*events.AuthResponse, error) {
	if !e.HasAuthorize() {
		return nil, fmt.Errorf("script does not define an '%v' function", funcAuthorize)
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	ls, err := e.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer e.release(ls)
	ls.SetContext(ctx)

	reqTable := authRequestToTable(ls, req)
	if err := ls.CallByParam(lua.P{
		Fn:      ls.GetGlobal(funcAuthorize),
		NRet:    1,
		Protect: true,
	}, reqTable); err != nil {
		return nil, fmt.Errorf("%v(): %w", funcAuthorize, err)
	}
	ret := ls.Get(-1)
	ls.Pop(1)

	return tableToAuthResponse(ret)
}

func (e *Engine) CallAccounting(req *events.AcctRequest) error {
	if !e.HasAccounting() {
		return fmt.Errorf("script does not define an '%v' function", funcAccounting)
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	ls, err := e.acquire(ctx)
	if err != nil {
		return err
	}
	defer e.release(ls)
	ls.SetContext(ctx)

	reqTable := acctRequestToTable(ls, req)
	if err := ls.CallByParam(lua.P{
		Fn:      ls.GetGlobal(funcAccounting),
		NRet:    0,
		Protect: true,
	}, reqTable); err != nil {
		return fmt.Errorf("%v(): %w", funcAccounting, err)
	}
	return nil
}

func (e *Engine) CallPostAuth(req *events.AuthRequest, resp *events.AuthResponse) error {
	if !e.HasPostAuth() {
		return fmt.Errorf("script does not define a '%v' function", funcPostAuth)
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	ls, err := e.acquire(ctx)
	if err != nil {
		return err
	}
	defer e.release(ls)
	ls.SetContext(ctx)

	reqTable := authRequestToTable(ls, req)
	respTable := authResponseToTable(ls, resp)
	if err := ls.CallByParam(lua.P{
		Fn:      ls.GetGlobal(funcPostAuth),
		NRet:    0,
		Protect: true,
	}, reqTable, respTable); err != nil {
		return fmt.Errorf("%v(): %w", funcPostAuth, err)
	}
	return nil
}
