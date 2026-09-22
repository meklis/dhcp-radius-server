package api

import (
	"crypto/tls"
	"fmt"
	"github.com/imroc/req"
	"github.com/meklis/dhcp-radius-server/api/cache"
	"github.com/meklis/dhcp-radius-server/api/sources"
	"github.com/meklis/dhcp-radius-server/logger"
	"github.com/meklis/dhcp-radius-server/prom"
	"github.com/meklis/dhcp-radius-server/radius/events"
	"github.com/ztrue/tracerr"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"
)

type Api struct {
	sync.Mutex
	Conf            ApiConfig
	cache           *cache.CacheApi
	sources         *sources.Sources
	lg              *logger.Logger
	postAuthChannel chan *PostAuth
	acctChannel     chan *events.AcctRequest
}

func Init(conf ApiConfig, lg *logger.Logger) *Api {
	req.Client().Jar, _ = cookiejar.New(nil)

	trans, _ := req.Client().Transport.(*http.Transport)
	trans.MaxIdleConns = 20
	trans.TLSHandshakeTimeout = 5 * time.Second
	trans.DisableKeepAlives = true
	trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	cl := req.Client()
	cl.Transport = trans
	req.SetClient(cl)

	api := new(Api)
	api.Conf = conf
	api.cache = cache.Init(conf.Auth.Caching.TimeoutExpires)
	api.sources = sources.New(conf.Auth.Addresses, lg, conf.Auth.AliveChecking.DisableTimeout)
	api.lg = lg

	//Post auth reader
	if conf.PostAuth.Enabled {
		api.postAuthChannel = make(chan *PostAuth, 100)
		lg.NoticeF("start postAuth readers")
		for i := 0; i < conf.PostAuth.CountReaders; i++ {
			go func() {
				htReq := req.New()
				for {
					auth := <-api.postAuthChannel
					for _, addr := range conf.PostAuth.Addresses {
						response, err := htReq.Post(addr, req.BodyJSON(auth))
						if err != nil {
							prom.ErrorsInc(auth.Request.NasIp, prom.Error, "post_auth_send_failed")
							lg.ErrorF("post auth report returned err from addr %v: %v", addr, tracerr.Sprint(err))
							continue
						}
						if response.Response().StatusCode != 200 {
							prom.ErrorsInc(auth.Request.NasIp, prom.Error, "post_auth_bad_status")
							lg.ErrorF("post auth report returned err from addr %v: %v", addr, tracerr.Sprint(err))
							continue
						}
					}
				}
			}()
		}
		go func() {
			for {
				time.Sleep(time.Second)
				prom.SetPostAuthQueueSize(len(api.postAuthChannel))
			}
		}()
	} else {
		lg.NoticeF("postAuth disabled")
	}

	//Init acct readers
	if conf.Acct.Enabled {
		api.acctChannel = make(chan *events.AcctRequest, 100)
		lg.NoticeF("start acct readers")
		for i := 0; i < conf.Acct.CountReaders; i++ {
			go func() {
				htReq := req.New()
				for {
					acct := <-api.acctChannel
					for _, addr := range conf.Acct.Addresses {
						response, err := htReq.Post(addr, req.BodyJSON(acct))
						if err != nil {
							prom.ErrorsInc(acct.NasIp, prom.Error, "acct_send_failed")
							lg.ErrorF("acct report returned err from addr %v: %v", addr, tracerr.Sprint(err))
							continue
						}
						if response.Response().StatusCode != 200 {
							prom.ErrorsInc(acct.NasIp, prom.Error, "acct_bad_status")
							lg.ErrorF("acct report returned err from addr %v: %v", addr, tracerr.Sprint(err))
							continue
						}
					}
				}
			}()
		}
		go func() {
			for {
				time.Sleep(time.Second)
				prom.SetAcctQueueSize(len(api.acctChannel))
			}
		}()
	} else {
		lg.NoticeF("acct request disabled")
	}

	return api
}

func (a *Api) Get(req *events.AuthRequest) (*events.AuthResponse, error) {
	hash := req.GetHash()
	response := new(events.AuthResponse)
	exist := false
	if a.Conf.Auth.Caching.Enabled {
		response, exist = a.cache.Get(hash)
		if exist {
			a.lg.DebugF("%v found in cache, check actual time", hash)
			if response.Time.After(time.Now()) {
				a.lg.DebugF("%v has actual time - %v, returning from cache", hash, response.Time.String())
				return response, nil
			} else {
				a.lg.DebugF("%v must be actualized from api", hash)
			}
		}
	} else {
		a.lg.DebugF("caching disabled, not checking")
	}
	a.lg.DebugF("%v try get data over API", hash)

	apiResp, err := a._getFromApi(req)
	if err != nil && exist {
		prom.ErrorsInc(req.NasIp, prom.Error, "api_get_failed_using_stale_cache")
		a.lg.ErrorF("error get data from api: %v", tracerr.Sprint(err))
		return response, nil
	} else if err != nil {
		return nil, tracerr.Wrap(err)
	}

	if a.Conf.Auth.Caching.Enabled {
		actualizeTime := time.Now().Add(a.Conf.Auth.Caching.ActualizeTimeout)
		if actualizeTime.After(time.Now().Add(time.Second * time.Duration(apiResp.LeaseTimeSec))) {
			a.lg.Warningf("detected lease_time_sec has a small time. Actualize time will be set as lease time")
			actualizeTime = time.Now().Add(time.Second * time.Duration(apiResp.LeaseTimeSec))
		}
		apiResp.Time = actualizeTime
		a.cache.Set(hash, *apiResp)
	}
	return apiResp, nil
}

func (a *Api) SendPostAuth(req events.AuthRequest, resp events.AuthResponse) {
	if !a.Conf.PostAuth.Enabled {
		return
	}
	auth := newPostAuth(req, resp)
	select {
	case a.postAuthChannel <- auth:
	default:
		a.lg.WarningF("post auth channel is full! Try to increase reader count")
		a.lg.DebugF("request %v-%v-%v will be dropped", auth.Request.NasIp, auth.Request.DeviceMac, auth.Request.DhcpServerName)
	}
}

func (a *Api) SendAcct(acct *events.AcctRequest) {
	if !a.Conf.Acct.Enabled {
		return
	}
	select {
	case a.acctChannel <- acct:
	default:
		a.lg.WarningF("acct channel is full! Try to increase reader count")
		a.lg.DebugF("acct %v-%v-%v with ip %v will be dropped ", acct.NasIp, acct.DeviceMac, acct.DhcpServerName, acct.FramedIpAddress)
	}
}

func (a *Api) _getFromApi(request *events.AuthRequest) (*events.AuthResponse, error) {
	source, err := a.sources.GetSource()
	if err != nil {
		a.lg.DebugF("not found sources - %v", err.Error())
		return nil, tracerr.Wrap(err)
	}
	a.lg.DebugF("defined source from rr = %v", source)
	a.sources.IncRequests(source.Address)
	req.SetTimeout(a.Conf.Timeout)
	response, err := req.Post(source.Address, req.BodyJSON(request))
	if err != nil {
		prom.ErrorsInc(request.NasIp, prom.Error, "api_request_failed")
		a.lg.ErrorF("source returned err: %v", tracerr.Sprint(err))
		a.sources.Disable(source.Address)
		return nil, tracerr.Wrap(err)
	}
	if response.Response().StatusCode != 200 {
		prom.ErrorsInc(request.NasIp, prom.Error, "api_bad_status")
		a.lg.ErrorF("source returned http != 200: %v %v", response.Response().StatusCode, response.Response().Status)
		a.sources.Disable(source.Address)
		return nil, tracerr.New(fmt.Sprintf("http err: %v - %v", response.Response().StatusCode, response.Response().Status))
	}
	apiResp := ApiResponse{}
	if err := response.ToJSON(&apiResp); err != nil {
		a.sources.Disable(source.Address)
		return nil, tracerr.Wrap(err)
	}

	if apiResp.StatusCode != 200 {
		return nil, tracerr.New(fmt.Sprintf("api returned status code - %v. must be 200", apiResp.StatusCode))
	}
	return &apiResp.Data, nil
}
