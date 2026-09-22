package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/http/pprof"
	"strings"

	"github.com/meklis/dhcp-radius-server/api"
	"github.com/meklis/dhcp-radius-server/config"
	"github.com/meklis/dhcp-radius-server/logger"
	"github.com/meklis/dhcp-radius-server/prom"
	"github.com/meklis/dhcp-radius-server/radius"
	"github.com/meklis/dhcp-radius-server/script"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ztrue/tracerr"
)

var (
	Config     config.Configuration
	pathConfig string
	lg         *logger.Logger
)

var (
	VERSION    = "0.2.12"
	BUILD_DATE = "2024-08-18"
)

func init() {
	flag.StringVar(&pathConfig, "c", "radius.server.conf.yml", "Configuration file for radius-server")
	flag.Parse()
}

func main() {
	fmt.Println("Initialize radius-server  ...")

	//Load configuration
	if err := config.LoadConfig(pathConfig, &Config); err != nil {
		panic(err)
	}
	//Configure logger from cronfiguration
	lg = config.ConfigureLogger(&Config)

	//Initialize prometheus
	if Config.Prometheus.Enabled {
		prom.PromEnabled = true
		prom.PromDetailedMacInfoEnabled = Config.Prometheus.Detailed
		lg.NoticeF("Exporter for prometheus is enabled...")
		http.Handle(Config.Prometheus.Path, promhttp.Handler())
		go func() {
			err := http.ListenAndServe(fmt.Sprintf(":%v", Config.Prometheus.Port), nil)
			lg.CriticalF("Prometheus exporter critical err: %v", err)
			panic(err)
		}()
		lg.NoticeF("Prometheus exporter started on 0.0.0.0:%v%v", Config.Prometheus.Port, Config.Prometheus.Path)
		prom.SysInfo(VERSION, BUILD_DATE)
	}
	//Configure pprof
	if Config.Profiler.Enabled {
		go func() {
			lg.NoticeF("Profiller is enabled, try start on port :%v", Config.Profiler.Port)
			r := http.NewServeMux()
			// Регистрация pprof-обработчиков
			r.HandleFunc("/debug/pprof/", pprof.Index)
			r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			r.HandleFunc("/debug/pprof/profile", pprof.Profile)
			r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			r.HandleFunc("/debug/pprof/trace", pprof.Trace)
			if err := http.ListenAndServe(fmt.Sprintf(":%v", Config.Profiler.Port), r); err != nil {
				panic(err)
			}
		}()
	}
	//Initialize processor (api или script - выбор по Config.Processor)
	var processor radius.Processor
	switch strings.ToLower(Config.Processor) {
	case "", config.ProcessorAPI:
		lg.NoticeF("processor: api")
		processor = api.Init(Config.Api, lg)
	case config.ProcessorScript:
		lg.NoticeF("processor: script")
		p, err := script.NewProcessor(Config.Script, lg)
		if err != nil {
			lg.FatalF("failed to init script processor: %v", err)
		}
		processor = p
	default:
		lg.FatalF("unknown processor %q, expected %q or %q", Config.Processor, config.ProcessorAPI, config.ProcessorScript)
	}

	//Initialize server
	rad := radius.Init()
	err := rad.SetProcessor(processor).
		SetListenAddr(Config.Radius.ListenAddr).
		SetLogger(lg).
		SetSecret(Config.Radius.Secret).
		SetReadBufferSize(Config.Radius.ReadBufferSize).
		ListenAndServe()
	if err != nil {
		panic(tracerr.Sprint(err))
	}
}
