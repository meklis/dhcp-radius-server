package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"

	"github.com/meklis/dhcp-radius-server/api"
	"github.com/meklis/dhcp-radius-server/config"
	"github.com/meklis/dhcp-radius-server/logger"
	"github.com/meklis/dhcp-radius-server/prom"
	"github.com/meklis/dhcp-radius-server/radius"
	"github.com/meklis/dhcp-radius-server/script"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// set at build time via -ldflags "-X main.VERSION=... -X main.BUILD_DATE=..."
var (
	VERSION    = "0.2.12"
	BUILD_DATE = "2024-08-18"
)

func main() {
	configPath := flag.String("c", "radius.server.conf.yml", "Configuration file for radius-server")
	flag.Parse()

	fmt.Println("Initialize radius-server  ...")
	conf, err := config.Load(*configPath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Loaded configuration from %v\n", *configPath)

	var out io.Writer = io.Discard
	if conf.Logger.Console.Enabled {
		out = os.Stdout
	}
	lg := logger.New(out, logger.Options{
		Level:     logger.Level(conf.Logger.Console.LogLevel),
		Color:     conf.Logger.Console.EnableColor,
		PrintFile: conf.Logger.Console.PrintFile,
	})

	if conf.Prometheus.Enabled {
		prom.Enabled = true
		prom.DetailedEnabled = conf.Prometheus.Detailed
		prom.SetVersion(VERSION, BUILD_DATE)
		mux := http.NewServeMux()
		mux.Handle(conf.Prometheus.Path, promhttp.Handler())
		go func() {
			err := http.ListenAndServe(fmt.Sprintf(":%v", conf.Prometheus.Port), mux)
			lg.FatalF("Prometheus exporter critical err: %v", err)
		}()
		lg.NoticeF("Prometheus exporter started on 0.0.0.0:%v%v", conf.Prometheus.Port, conf.Prometheus.Path)
	}
	if conf.Profiler.Enabled {
		lg.NoticeF("Profiler is enabled, try start on port :%v", conf.Profiler.Port)
		go func() {
			// net/http/pprof registers its handlers on the default mux
			err := http.ListenAndServe(fmt.Sprintf(":%v", conf.Profiler.Port), http.DefaultServeMux)
			lg.FatalF("Profiler critical err: %v", err)
		}()
	}

	var processor radius.Processor
	switch strings.ToLower(conf.Processor) {
	case "", config.ProcessorAPI:
		lg.NoticeF("processor: api")
		processor = api.New(conf.Api, lg)
	case config.ProcessorScript:
		lg.NoticeF("processor: script")
		if processor, err = script.NewProcessor(conf.Script, lg); err != nil {
			lg.FatalF("failed to init script processor: %v", err)
		}
	default:
		lg.FatalF("unknown processor %q, expected %q or %q", conf.Processor, config.ProcessorAPI, config.ProcessorScript)
	}

	if err := radius.ListenAndServe(conf.Radius, processor, lg); err != nil {
		lg.FatalF("radius server: %v", err)
	}
}
