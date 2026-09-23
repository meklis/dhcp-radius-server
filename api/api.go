package api

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"

	"github.com/meklis/dhcp-radius-server/logger"
	"github.com/meklis/dhcp-radius-server/prom"
	"github.com/meklis/dhcp-radius-server/radius/events"
	gocache "github.com/meklis/go-cache"
)

type Config struct {
	Auth struct {
		Addresses     []string `yaml:"addresses"`
		AliveChecking struct {
			DisableTimeout time.Duration `yaml:"disable_timeout"`
		} `yaml:"alive_checking"`
		Caching struct {
			Enabled          bool          `yaml:"enabled"`
			ActualizeTimeout time.Duration `yaml:"actualize_timeout"`
			TimeoutExpires   time.Duration `yaml:"expire_timeout"`
		} `yaml:"caching"`
	} `yaml:"auth"`
	PostAuth SenderConfig  `yaml:"postauth"`
	Acct     SenderConfig  `yaml:"acct"`
	Timeout  time.Duration `yaml:"timeout"`
}

type SenderConfig struct {
	Enabled      bool     `yaml:"enabled"`
	CountReaders int      `yaml:"count_readers"`
	Addresses    []string `yaml:"addresses"`
}

const queueSize = 100

type postAuthEvent struct {
	Request  events.AuthRequest  `json:"request"`
	Response events.AuthResponse `json:"response"`
}

type source struct {
	alive      bool
	requests   int
	disabledAt time.Time
}

// API implements radius.Processor over an HTTP backend. Auth requests go to the
// least loaded alive address; a failing address is disabled for DisableTimeout.
type API struct {
	conf          Config
	lg            *logger.Logger
	client        *http.Client
	cache         *gocache.Cache
	mu            sync.Mutex
	sources       map[string]*source
	postAuthQueue chan postAuthEvent
	acctQueue     chan *events.AcctRequest
}

func New(conf Config, lg *logger.Logger) *API {
	jar, _ := cookiejar.New(nil)
	a := &API{
		conf: conf,
		lg:   lg,
		client: &http.Client{
			Jar:     jar,
			Timeout: conf.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				TLSHandshakeTimeout: 5 * time.Second,
				DisableKeepAlives:   true,
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			},
		},
		cache:   gocache.New(conf.Auth.Caching.TimeoutExpires, 10*time.Minute),
		sources: make(map[string]*source),
	}
	for _, addr := range conf.Auth.Addresses {
		a.sources[addr] = &source{alive: true}
	}

	if conf.PostAuth.Enabled {
		a.postAuthQueue = make(chan postAuthEvent, queueSize)
		lg.NoticeF("start postAuth readers")
		for range conf.PostAuth.CountReaders {
			go func() {
				for ev := range a.postAuthQueue {
					a.sendAll(conf.PostAuth.Addresses, ev, ev.Request.NasIp, "post_auth")
				}
			}()
		}
	} else {
		lg.NoticeF("postAuth disabled")
	}
	if conf.Acct.Enabled {
		a.acctQueue = make(chan *events.AcctRequest, queueSize)
		lg.NoticeF("start acct readers")
		for range conf.Acct.CountReaders {
			go func() {
				for acct := range a.acctQueue {
					a.sendAll(conf.Acct.Addresses, acct, acct.NasIp, "acct")
				}
			}()
		}
	} else {
		lg.NoticeF("acct request disabled")
	}

	go func() {
		for range time.Tick(time.Second) {
			prom.SetCacheSize(a.cache.ItemCount())
			prom.SetPostAuthQueueLen(len(a.postAuthQueue))
			prom.SetAcctQueueLen(len(a.acctQueue))

			a.mu.Lock()
			for addr, src := range a.sources {
				if !src.alive && time.Since(src.disabledAt) > conf.Auth.AliveChecking.DisableTimeout {
					src.alive = true
					prom.SetAPIAlive(addr, true)
					lg.NoticeF("change source %v state to alive", addr)
				}
			}
			a.mu.Unlock()
		}
	}()
	return a
}

// Get answers from cache while the entry is fresh; a stale entry is still used
// when the backend fails.
func (a *API) Get(req *events.AuthRequest) (*events.AuthResponse, error) {
	cacheReq := *req
	cacheReq.Class = ""
	data, _ := json.Marshal(cacheReq)
	key := fmt.Sprintf("%x", md5.Sum(data))

	var cached *events.AuthResponse
	if a.conf.Auth.Caching.Enabled {
		if v, ok := a.cache.Get(key); ok {
			resp := v.(events.AuthResponse)
			if resp.Time.After(time.Now()) {
				a.lg.DebugF("%v found in cache, actual until %v", key, resp.Time)
				return &resp, nil
			}
			cached = &resp
		}
	}

	resp, err := a.fetch(req)
	if err != nil {
		if cached != nil {
			prom.IncError(req.NasIp, prom.Error, "api_get_failed_using_stale_cache")
			a.lg.ErrorF("error get data from api: %v", err)
			return cached, nil
		}
		return nil, err
	}

	if a.conf.Auth.Caching.Enabled {
		lease := time.Duration(resp.LeaseTimeSec) * time.Second
		if a.conf.Auth.Caching.ActualizeTimeout > lease {
			a.lg.WarningF("detected lease_time_sec has a small time. Actualize time will be set as lease time")
			resp.Time = time.Now().Add(lease)
		} else {
			resp.Time = time.Now().Add(a.conf.Auth.Caching.ActualizeTimeout)
		}
		a.cache.SetDefault(key, *resp)
	}
	return resp, nil
}

// fetch asks the least loaded alive source; a failing source is disabled.
func (a *API) fetch(req *events.AuthRequest) (*events.AuthResponse, error) {
	a.mu.Lock()
	var addr string
	var src *source
	for candidate, s := range a.sources {
		if s.alive && (src == nil || s.requests < src.requests) {
			addr, src = candidate, s
		}
	}
	if src == nil {
		a.mu.Unlock()
		return nil, fmt.Errorf("not found alive sources for send request")
	}
	src.requests++
	a.mu.Unlock()

	var body struct {
		Data       events.AuthResponse `json:"data"`
		StatusCode int                 `json:"statusCode"`
	}
	err := a.post(addr, req, &body)
	if err != nil {
		prom.IncError(req.NasIp, prom.Error, "api_request_failed")
		a.lg.ErrorF("source %v returned err: %v", addr, err)
		a.mu.Lock()
		src.alive = false
		src.disabledAt = time.Now()
		a.mu.Unlock()
		prom.SetAPIAlive(addr, false)
		a.lg.NoticeF("change source %v state to dead", addr)
		return nil, err
	}
	if body.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api returned status code - %v. must be 200", body.StatusCode)
	}
	return &body.Data, nil
}

func (a *API) SendPostAuth(req events.AuthRequest, resp events.AuthResponse) {
	if !a.conf.PostAuth.Enabled {
		return
	}
	req.AgentOption = nil
	resp.ExtraAttributes = nil
	select {
	case a.postAuthQueue <- postAuthEvent{Request: req, Response: resp}:
	default:
		a.lg.WarningF("post auth channel is full! Try to increase reader count")
	}
}

func (a *API) SendAcct(acct *events.AcctRequest) {
	if !a.conf.Acct.Enabled {
		return
	}
	select {
	case a.acctQueue <- acct:
	default:
		a.lg.WarningF("acct channel is full! Try to increase reader count")
	}
}

func (a *API) sendAll(addresses []string, payload any, nasIP, name string) {
	for _, addr := range addresses {
		if err := a.post(addr, payload, nil); err != nil {
			prom.IncError(nasIP, prom.Error, name+"_send_failed")
			a.lg.ErrorF("%v report to %v failed: %v", name, addr, err)
		}
	}
}

// post sends payload as JSON and decodes the response into out, if not nil.
func (a *API) post(url string, payload, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := a.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status %v", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
