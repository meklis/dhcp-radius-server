package script

import (
	"fmt"
	"time"

	"github.com/meklis/dhcp-radius-server/clientdb"
	"github.com/meklis/dhcp-radius-server/logger"
	"github.com/meklis/dhcp-radius-server/prom"
	"github.com/meklis/dhcp-radius-server/radius/events"
)

// Config sets one script per phase: auth is required, acct and post_auth are optional.
type Config struct {
	PoolSize int             `yaml:"pool_size"`
	Timeout  time.Duration   `yaml:"timeout"`
	Auth     string          `yaml:"auth"`
	Acct     string          `yaml:"acct"`
	PostAuth string          `yaml:"post_auth"`
	Database clientdb.Config `yaml:"database"`
}

const queueSize = 100

type postAuthEvent struct {
	req  events.AuthRequest
	resp events.AuthResponse
}

// Processor implements radius.Processor with embedded Lua scripts.
type Processor struct {
	lg            *logger.Logger
	auth          *Engine
	acct          *Engine
	postAuth      *Engine
	acctQueue     chan *events.AcctRequest
	postAuthQueue chan postAuthEvent
}

func NewProcessor(conf Config, lg *logger.Logger) (*Processor, error) {
	if conf.Auth == "" {
		return nil, fmt.Errorf("script.auth not set")
	}
	// scripts need db.devices to pick the circuit_id parser
	db, err := clientdb.New(conf.Database, lg)
	if err != nil {
		return nil, fmt.Errorf("script.database: %w", err)
	}
	newEngine := func(key, path, function string) (*Engine, error) {
		e, err := NewEngine(path, conf.PoolSize, conf.Timeout, lg, db)
		if err != nil {
			return nil, fmt.Errorf("script.%v (%v): %w", key, path, err)
		}
		if !e.functions[function] {
			return nil, fmt.Errorf("script.%v (%v) does not contain function %v()", key, path, function)
		}
		return e, nil
	}

	p := &Processor{lg: lg}
	if p.auth, err = newEngine("auth", conf.Auth, funcAuthorize); err != nil {
		return nil, err
	}
	if conf.Acct != "" {
		if p.acct, err = newEngine("acct", conf.Acct, funcAccounting); err != nil {
			return nil, err
		}
		p.acctQueue = make(chan *events.AcctRequest, queueSize)
		for range cap(p.acct.pool) {
			go func() {
				for acct := range p.acctQueue {
					if err := p.acct.Accounting(acct); err != nil {
						prom.IncError(acct.NasIp, prom.Error, "accounting_script_error")
						lg.ErrorF("script accounting returned err: %v", err)
					}
				}
			}()
		}
	}
	if conf.PostAuth != "" {
		if p.postAuth, err = newEngine("post_auth", conf.PostAuth, funcPostAuth); err != nil {
			return nil, err
		}
		p.postAuthQueue = make(chan postAuthEvent, queueSize)
		for range cap(p.postAuth.pool) {
			go func() {
				for ev := range p.postAuthQueue {
					if err := p.postAuth.PostAuth(&ev.req, &ev.resp); err != nil {
						prom.IncError(ev.req.NasIp, prom.Error, "post_auth_script_error")
						lg.ErrorF("script post_auth returned err: %v", err)
					}
				}
			}()
		}
	}
	return p, nil
}

func (p *Processor) Get(req *events.AuthRequest) (*events.AuthResponse, error) {
	return p.auth.Authorize(req)
}

func (p *Processor) SendPostAuth(req events.AuthRequest, resp events.AuthResponse) {
	if p.postAuth == nil {
		return
	}
	select {
	case p.postAuthQueue <- postAuthEvent{req: req, resp: resp}:
	default:
		p.lg.WarningF("post auth channel is full! Try to increase script.pool_size")
	}
}

func (p *Processor) SendAcct(acct *events.AcctRequest) {
	if p.acct == nil {
		return
	}
	select {
	case p.acctQueue <- acct:
	default:
		p.lg.WarningF("acct channel is full! Try to increase script.pool_size")
	}
}
