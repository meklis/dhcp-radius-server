package script

import (
	"fmt"
	"time"

	"github.com/meklis/all-ok-radius-server/clientdb"
	"github.com/meklis/all-ok-radius-server/logger"
	"github.com/meklis/all-ok-radius-server/prom"
	"github.com/meklis/all-ok-radius-server/radius/events"
)

// Config - путь к своему lua-скрипту на каждый метод (auth обязателен, acct/post_auth опциональны).
// pool_size/timeout общие для всех сконфигурированных скриптов.
type Config struct {
	PoolSize int             `yaml:"pool_size"`
	Timeout  time.Duration   `yaml:"timeout"`
	Auth     string          `yaml:"auth"`
	Acct     string          `yaml:"acct"`
	PostAuth string          `yaml:"post_auth"`
	Database clientdb.Config `yaml:"database"`
}

type postAuthEvent struct {
	req  events.AuthRequest
	resp events.AuthResponse
}

// Processor реализует radius.Processor поверх встроенных Lua-скриптов
type Processor struct {
	lg              *logger.Logger
	db              *clientdb.Store
	authEngine      *Engine
	acctEngine      *Engine
	postAuthEngine  *Engine
	acctChannel     chan *events.AcctRequest
	postAuthChannel chan postAuthEvent
}

func NewProcessor(conf Config, lg *logger.Logger) (*Processor, error) {
	if conf.Auth == "" {
		return nil, fmt.Errorf("script.auth not set")
	}

	p := &Processor{lg: lg}

	// при processor: script база обязательна - без неё скрипты не могут
	// определить тип оборудования (db.devices.parse_type) для парсинга circuit_id
	db, err := clientdb.New(conf.Database, lg)
	if err != nil {
		return nil, fmt.Errorf("script.database: %w", err)
	}
	p.db = db

	authEngine, err := New(conf.Auth, conf.PoolSize, conf.Timeout, lg, p.db)
	if err != nil {
		return nil, fmt.Errorf("script.auth (%v): %w", conf.Auth, err)
	}
	if !authEngine.HasAuthorize() {
		return nil, fmt.Errorf("script.auth (%v) does not contain function authorize()", conf.Auth)
	}
	p.authEngine = authEngine

	if conf.Acct != "" {
		acctEngine, err := New(conf.Acct, conf.PoolSize, conf.Timeout, lg, p.db)
		if err != nil {
			return nil, fmt.Errorf("script.acct (%v): %w", conf.Acct, err)
		}
		if !acctEngine.HasAccounting() {
			return nil, fmt.Errorf("script.acct (%v) does not contain function accounting()", conf.Acct)
		}
		p.acctEngine = acctEngine
		p.acctChannel = make(chan *events.AcctRequest, 100)
		for i := 0; i < acctEngine.PoolSize(); i++ {
			go p.acctWorker()
		}
	}

	if conf.PostAuth != "" {
		postAuthEngine, err := New(conf.PostAuth, conf.PoolSize, conf.Timeout, lg, p.db)
		if err != nil {
			return nil, fmt.Errorf("script.post_auth (%v): %w", conf.PostAuth, err)
		}
		if !postAuthEngine.HasPostAuth() {
			return nil, fmt.Errorf("script.post_auth (%v) does not contain function post_auth()", conf.PostAuth)
		}
		p.postAuthEngine = postAuthEngine
		p.postAuthChannel = make(chan postAuthEvent, 100)
		for i := 0; i < postAuthEngine.PoolSize(); i++ {
			go p.postAuthWorker()
		}
	}

	return p, nil
}

func (p *Processor) Get(req *events.AuthRequest) (*events.AuthResponse, error) {
	return p.authEngine.CallAuthorize(req)
}

func (p *Processor) SendPostAuth(req events.AuthRequest, resp events.AuthResponse) {
	if p.postAuthEngine == nil {
		return
	}
	select {
	case p.postAuthChannel <- postAuthEvent{req: req, resp: resp}:
	default:
		p.lg.WarningF("post auth channel is full! Try to increase script.pool_size")
	}
}

func (p *Processor) SendAcct(acct *events.AcctRequest) {
	if p.acctEngine == nil {
		return
	}
	select {
	case p.acctChannel <- acct:
	default:
		p.lg.WarningF("acct channel is full! Try to increase script.pool_size")
	}
}

func (p *Processor) acctWorker() {
	for acct := range p.acctChannel {
		if err := p.acctEngine.CallAccounting(acct); err != nil {
			prom.ErrorsInc(prom.Error, "script")
			p.lg.ErrorF("script accounting returned err: %v", err)
		}
	}
}

func (p *Processor) postAuthWorker() {
	for ev := range p.postAuthChannel {
		if err := p.postAuthEngine.CallPostAuth(&ev.req, &ev.resp); err != nil {
			prom.ErrorsInc(prom.Error, "script")
			p.lg.ErrorF("script post_auth returned err: %v", err)
		}
	}
}
