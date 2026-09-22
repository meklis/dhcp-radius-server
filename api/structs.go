package api

import (
	"github.com/meklis/dhcp-radius-server/radius/events"
	"time"
)

type ApiConfig struct {
	Auth struct {
		Addresses     []string `yaml:"addresses"`
		AliveChecking struct {
			Enabled        bool          `yaml:"enabled"`
			DisableTimeout time.Duration `yaml:"disable_timeout"`
		} `yaml:"alive_checking"`
		Caching struct {
			Enabled          bool          `yaml:"enabled"`
			ActualizeTimeout time.Duration `yaml:"actualize_timeout"`
			TimeoutExpires   time.Duration `yaml:"expire_timeout"`
		} `yaml:"caching"`
	} `yaml:"auth"`
	PostAuth struct {
		Enabled      bool     `yaml:"enabled"`
		CountReaders int      `yaml:"count_readers"`
		Addresses    []string `yaml:"addresses"`
	} `yaml:"postauth"`
	Acct struct {
		Enabled      bool     `yaml:"enabled"`
		CountReaders int      `yaml:"count_readers"`
		Addresses    []string `yaml:"addresses"`
	} `yaml:"acct"`
	Timeout time.Duration `yaml:"timeout"`
}

type ApiResponse struct {
	Data       events.AuthResponse `json:"data"`
	Meta       interface{}         `json:"meta"`
	StatusCode int                 `json:"statusCode"`
}

type PostAuth struct {
	Request  events.AuthRequest  `json:"request"`
	Response events.AuthResponse `json:"response"`
}

func newPostAuth(req events.AuthRequest, resp events.AuthResponse) *PostAuth {
	p := new(PostAuth)
	p.Request = events.AuthRequest{
		NasIp:           req.NasIp,
		NasName:         req.NasName,
		DeviceMac:       req.DeviceMac,
		DhcpServerName:  req.DhcpServerName,
		DhcpServerId:    req.DhcpServerId,
		FramedIpAddress: req.FramedIpAddress,
		Class:           req.Class,
	}
	p.Response = events.AuthResponse{
		IpAddress:    resp.IpAddress,
		PoolName:     resp.PoolName,
		LeaseTimeSec: resp.LeaseTimeSec,
		Status:       resp.Status,
		Error:        resp.Error,
		Class:        resp.Class,
	}
	return p
}
