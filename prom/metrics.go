package prom

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	radRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_request_count",
		Help: "Count of requests from NAS",
	}, []string{"host"})
	// radRequestDuration - от получения Access-Request до записи ответа (Accept/
	// Reject) или до решения промолчать на инфраструктурной ошибке (KindError, см.
	// radius/events/auth_error.go) - в обоих случаях это всё время, которое NAS
	// реально ждёт до таймаута/ответа. Бакеты подобраны под типичный профиль
	// latency этого сервера (единицы-десятки мс, см. doc/LOAD_TESTING.md), с
	// запасом до SCRIPT_TIMEOUT
	radRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "rad_request_duration_seconds",
		Help:    "Time from receiving an Access-Request to writing the response (or to the decision to stay silent on an infrastructure error)",
		Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2, 3, 5},
	}, []string{"host"})
	// radRequestDurationTotal - то же самое значение, что уходит в radRequestDuration,
	// но отдельным простым Counter'ом (rad_request_duration_seconds_bucket/_sum/_count
	// от Histogram для этого не годятся напрямую как обычный счётчик - это его
	// внутренние служебные серии). rate(rad_request_duration_seconds_total[5m]) /
	// rate(rad_request_count[5m]) - средняя latency без histogram_quantile
	radRequestDurationTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_request_duration_seconds_total",
		Help: "Cumulative time spent processing Access-Requests, in seconds, by NAS host",
	}, []string{"host"})
	radAcctRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_acct_requests_count",
		Help: "rad acct requests count",
	}, []string{"host", "server_name"})
	radRequestsIpAddressCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_request_ip_count",
		Help: "Count of requests from NAS",
	}, []string{"host"})
	radRequestsIpPoolCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_request_pool_count",
		Help: "Count of requests from NAS",
	}, []string{"host"})
	radRequestsCountByPool = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_request_by_pool_count",
		Help: "Count of requests from NAS by pool name",
	}, []string{"host", "pool_name"})
	// radErrors - единый счётчик ошибок/предупреждений вместо трёх раздельных
	// (rad_critical_count/rad_errors_count/rad_warnings_count) - level и msg как
	// лейблы вместо трёх серий с одинаковой формой. msg - короткая фиксированная
	// причина (константа на месте вызова, не интерполированный текст ошибки/мак -
	// иначе кардинальность лейбла не ограничена), host - NAS, приславший запрос,
	// если применимо ("" для ошибок, не привязанных к конкретному NAS, например
	// API/скрипт-воркеры без запроса под рукой)
	radErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_errors",
		Help: "Count of errors/warnings, by NAS host, severity level (CRITICAL/ERROR/WARNING) and short reason",
	}, []string{"host", "level", "msg"})
	cacheSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rad_cache_responses_count",
		Help: "Count of responses in cache",
	}, []string{})
	apiAliveStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rad_api_alive_status",
		Help: "API alive status",
	}, []string{"api_addr"})
	apiPostAuthQueueLen = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rad_api_post_auth_queue_len",
		Help: "Queue len for post auth",
	}, []string{})
	apiAcctQueueLen = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rad_api_acct_queue_len",
		Help: "Queue len for acct",
	}, []string{})
	promSysInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rad_sys_version",
		Help: "Version of radius-server",
	}, []string{"version", "build_date"})
	radDetailedRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_mac_server_count",
		Help: "Detailed requests count info by MAC - DHCP-server",
	}, []string{"host", "mac", "server_name", "response_type"})
	clientDBDevicesCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rad_clientdb_devices_count",
		Help: "Count of devices currently loaded in clientdb",
	}, []string{})
	clientDBBindsCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rad_clientdb_binds_count",
		Help: "Count of binds currently loaded in clientdb, by source",
	}, []string{"source"})
	clientDBLastReloadTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rad_clientdb_last_reload_timestamp_seconds",
		Help: "Unix timestamp of the last successful clientdb reload",
	}, []string{})
	clientDBRedisConnected = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rad_clientdb_redis_connected",
		Help: "Connection status of the clientdb redis live-update subscription (1=connected, 0=disconnected)",
	}, []string{})
	clientDBLiveUpdateReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_clientdb_live_update_received_count",
		Help: "Count of live-update messages received from redis, by bind source",
	}, []string{"db_type"})
	clientDBLiveUpdateErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rad_clientdb_live_update_errors_count",
		Help: "Count of live-update messages from redis that failed to apply, by bind source",
	}, []string{"db_type"})
	clientDBLiveUpdateLastTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rad_clientdb_live_update_last_timestamp_seconds",
		Help: "Unix timestamp of the last live-update message received from redis",
	}, []string{})
	PromEnabled                bool
	PromDetailedMacInfoEnabled bool
)

type ErrLevel int

const Critical ErrLevel = 1
const Error ErrLevel = 2
const Warning ErrLevel = 3

// ErrorsInc - host: NAS, приславший запрос, к которому относится ошибка ("" если
// не привязана к конкретному запросу/NAS). msg: короткая фиксированная причина
// (константа на месте вызова - не текст ошибки/мак-адрес, иначе кардинальность
// лейбла станет неограниченной)
func ErrorsInc(host string, level ErrLevel, msg string) {
	if !PromEnabled {
		return
	}
	var levelStr string
	switch level {
	case Critical:
		levelStr = "CRITICAL"
	case Error:
		levelStr = "ERROR"
	case Warning:
		levelStr = "WARNING"
	default:
		return
	}
	radErrors.WithLabelValues(host, levelStr, msg).Inc()
}

func RadRequestsInc(host string) {
	if !PromEnabled {
		return
	}
	radRequests.WithLabelValues(host).Inc()
}

// ObserveRequestDuration - WithLabelValues (не With(Labels), который под
// капотом аллоцирует map на каждый вызов) - это горячий путь, вызывается на
// каждый Access-Request без исключений. Подтверждено нагрузочным тестированием
// (см. doc/LOAD_TESTING.md): переход с With на WithLabelValues по всему файлу
// вернул ~20% RPS, потерянных на map-аллокациях в этой и соседних функциях
func ObserveRequestDuration(host string, seconds float64) {
	if !PromEnabled {
		return
	}
	radRequestDuration.WithLabelValues(host).Observe(seconds)
	radRequestDurationTotal.WithLabelValues(host).Add(seconds)
}

func RadRequestsIpAddressInc(host string) {
	if !PromEnabled {
		return
	}
	radRequestsIpAddressCount.WithLabelValues(host).Inc()
}

func RadDetailedRequest(host, serverName, macAddr, responseType string) {
	if !PromEnabled || !PromDetailedMacInfoEnabled {
		return
	}
	radDetailedRequests.WithLabelValues(host, macAddr, serverName, responseType).Inc()
}

func RadRequestsPoolInc(host string) {
	if !PromEnabled {
		return
	}
	radRequestsIpPoolCount.WithLabelValues(host).Inc()
}
func RadAcctRequestsInc(host string, serverName string) {
	if !PromEnabled {
		return
	}
	radAcctRequests.WithLabelValues(host, serverName).Inc()
}

func RadRequestsByPoolInc(host, poolName string) {
	if !PromEnabled {
		return
	}
	radRequestsCountByPool.WithLabelValues(host, poolName).Inc()
}

func SetCacheSize(size int) {
	if !PromEnabled {
		return
	}
	cacheSize.WithLabelValues().Set(float64(size))
}
func SetPostAuthQueueSize(size int) {
	if !PromEnabled {
		return
	}
	apiPostAuthQueueLen.WithLabelValues().Set(float64(size))
}
func SetAcctQueueSize(size int) {
	if !PromEnabled {
		return
	}
	apiAcctQueueLen.WithLabelValues().Set(float64(size))
}

func SetApiStatus(address string, alive bool) {
	if !PromEnabled {
		return
	}
	status := 1
	if !alive {
		status = 0
	}
	apiAliveStatus.WithLabelValues(address).Set(float64(status))
}

func SetClientDBSize(devices int, binds map[string]int) {
	if !PromEnabled {
		return
	}
	clientDBDevicesCount.WithLabelValues().Set(float64(devices))
	for source, count := range binds {
		clientDBBindsCount.WithLabelValues(source).Set(float64(count))
	}
}

// SetClientDBBindsCount - обновление размера одного bind-источника после
// точечного live-update (см. clientdb.ApplyBindEvent), без полного reload
func SetClientDBBindsCount(source string, count int) {
	if !PromEnabled {
		return
	}
	clientDBBindsCount.WithLabelValues(source).Set(float64(count))
}

func SetClientDBLastReload(unixSeconds int64) {
	if !PromEnabled {
		return
	}
	clientDBLastReloadTimestamp.WithLabelValues().Set(float64(unixSeconds))
}

func SetClientDBRedisConnected(connected bool) {
	if !PromEnabled {
		return
	}
	status := 0
	if connected {
		status = 1
	}
	clientDBRedisConnected.WithLabelValues().Set(float64(status))
}

func IncClientDBLiveUpdateReceived(dbType string) {
	if !PromEnabled {
		return
	}
	clientDBLiveUpdateReceived.WithLabelValues(dbType).Inc()
}

func IncClientDBLiveUpdateError(dbType string) {
	if !PromEnabled {
		return
	}
	clientDBLiveUpdateErrors.WithLabelValues(dbType).Inc()
}

func SetClientDBLiveUpdateLastTimestamp(unixSeconds int64) {
	if !PromEnabled {
		return
	}
	clientDBLiveUpdateLastTimestamp.WithLabelValues().Set(float64(unixSeconds))
}

func SysInfo(version string, buildDate string) {
	if !PromEnabled {
		return
	}
	promSysInfo.WithLabelValues(version, buildDate).Inc()
}
