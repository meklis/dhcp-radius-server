package prom

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Enabled gates every metric update: the exporter is optional, and the update
// functions sit on the hot path of every request.
var (
	Enabled         bool
	DetailedEnabled bool
)

type Level string

const (
	Critical Level = "CRITICAL"
	Error    Level = "ERROR"
	Warning  Level = "WARNING"
)

var (
	requests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_request_count",
		Help: "Count of requests from NAS",
	}, []string{"host"})
	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "rad_request_duration_seconds",
		Help:    "Time from receiving an Access-Request to writing the response (or to the decision to stay silent on an infrastructure error)",
		Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2, 3, 5},
	}, []string{"host"})
	// Plain counter next to the histogram so average latency can be computed
	// as rate(..._seconds_total) / rate(rad_request_count) without quantiles.
	requestDurationTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_request_duration_seconds_total",
		Help: "Cumulative time spent processing Access-Requests, in seconds, by NAS host",
	}, []string{"host"})
	acctRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_acct_requests_count",
		Help: "rad acct requests count",
	}, []string{"host", "server_name"})
	ipRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_request_ip_count",
		Help: "Count of requests from NAS",
	}, []string{"host"})
	poolRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_request_pool_count",
		Help: "Count of requests from NAS",
	}, []string{"host"})
	requestsByPool = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_request_by_pool_count",
		Help: "Count of requests from NAS by pool name",
	}, []string{"host", "pool_name"})
	errorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_errors",
		Help: "Count of errors/warnings, by NAS host, severity level (CRITICAL/ERROR/WARNING) and short reason",
	}, []string{"host", "level", "msg"})
	macRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_mac_server_count",
		Help: "Detailed requests count info by MAC - DHCP-server",
	}, []string{"host", "mac", "server_name", "response_type"})
	version = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rad_sys_version",
		Help: "Version of radius-server",
	}, []string{"version", "build_date"})

	cacheSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "rad_cache_responses_count",
		Help: "Count of responses in cache",
	})
	apiAlive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rad_api_alive_status",
		Help: "API alive status",
	}, []string{"api_addr"})
	postAuthQueueLen = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "rad_api_post_auth_queue_len",
		Help: "Queue len for post auth",
	})
	acctQueueLen = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "rad_api_acct_queue_len",
		Help: "Queue len for acct",
	})

	clientDBDevices = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "rad_clientdb_devices_count",
		Help: "Count of devices currently loaded in clientdb",
	})
	clientDBBinds = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rad_clientdb_binds_count",
		Help: "Count of binds currently loaded in clientdb, by source",
	}, []string{"source"})
	clientDBLastReload = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "rad_clientdb_last_reload_timestamp_seconds",
		Help: "Unix timestamp of the last successful clientdb reload",
	})
	clientDBRedisConnected = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "rad_clientdb_redis_connected",
		Help: "Connection status of the clientdb redis live-update subscription (1=connected, 0=disconnected)",
	})
	clientDBLiveUpdates = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_clientdb_live_update_received_count",
		Help: "Count of live-update messages received from redis, by bind source",
	}, []string{"db_type"})
	clientDBLiveUpdateErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_clientdb_live_update_errors_count",
		Help: "Count of live-update messages from redis that failed to apply, by bind source",
	}, []string{"db_type"})
	clientDBLastLiveUpdate = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "rad_clientdb_live_update_last_timestamp_seconds",
		Help: "Unix timestamp of the last live-update message received from redis",
	})
)

// IncError counts an error or warning. reason must be a fixed short string,
// never an error text or MAC, to keep label cardinality bounded.
func IncError(host string, level Level, reason string) {
	if Enabled {
		errorsTotal.WithLabelValues(host, string(level), reason).Inc()
	}
}

func ObserveRequestDuration(host string, seconds float64) {
	if Enabled {
		requestDuration.WithLabelValues(host).Observe(seconds)
		requestDurationTotal.WithLabelValues(host).Add(seconds)
	}
}

func IncRequest(host string) {
	if Enabled {
		requests.WithLabelValues(host).Inc()
	}
}

func IncIPRequest(host string) {
	if Enabled {
		ipRequests.WithLabelValues(host).Inc()
	}
}

func IncPoolRequest(host, poolName string) {
	if Enabled {
		poolRequests.WithLabelValues(host).Inc()
		requestsByPool.WithLabelValues(host, poolName).Inc()
	}
}

func IncMacRequest(host, serverName, mac, responseType string) {
	if Enabled && DetailedEnabled {
		macRequests.WithLabelValues(host, mac, serverName, responseType).Inc()
	}
}

func IncAcctRequest(host, serverName string) {
	if Enabled {
		acctRequests.WithLabelValues(host, serverName).Inc()
	}
}

func SetCacheSize(size int) {
	if Enabled {
		cacheSize.Set(float64(size))
	}
}

func SetPostAuthQueueLen(n int) {
	if Enabled {
		postAuthQueueLen.Set(float64(n))
	}
}

func SetAcctQueueLen(n int) {
	if Enabled {
		acctQueueLen.Set(float64(n))
	}
}

func SetAPIAlive(address string, alive bool) {
	if Enabled {
		apiAlive.WithLabelValues(address).Set(boolToFloat(alive))
	}
}

func SetClientDBDevices(count int) {
	if Enabled {
		clientDBDevices.Set(float64(count))
	}
}

func SetClientDBBinds(source string, count int) {
	if Enabled {
		clientDBBinds.WithLabelValues(source).Set(float64(count))
	}
}

func SetClientDBLastReload(unixSeconds int64) {
	if Enabled {
		clientDBLastReload.Set(float64(unixSeconds))
	}
}

func SetClientDBRedisConnected(connected bool) {
	if Enabled {
		clientDBRedisConnected.Set(boolToFloat(connected))
	}
}

func IncClientDBLiveUpdate(dbType string) {
	if Enabled {
		clientDBLiveUpdates.WithLabelValues(dbType).Inc()
	}
}

func IncClientDBLiveUpdateError(dbType string) {
	if Enabled {
		clientDBLiveUpdateErrors.WithLabelValues(dbType).Inc()
	}
}

func SetClientDBLastLiveUpdate(unixSeconds int64) {
	if Enabled {
		clientDBLastLiveUpdate.Set(float64(unixSeconds))
	}
}

func SetVersion(v, buildDate string) {
	if Enabled {
		version.WithLabelValues(v, buildDate).Set(1)
	}
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
