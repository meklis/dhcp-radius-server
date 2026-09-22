module github.com/meklis/dhcp-radius-server

go 1.24

require (
	github.com/imroc/req v0.3.0
	github.com/meklis/go-cache v2.1.0+incompatible
	github.com/prometheus/client_golang v1.11.1
	github.com/redis/go-redis/v9 v9.22.0
	github.com/yuin/gopher-lua v1.1.1
	github.com/ztrue/tracerr v0.3.0
	gopkg.in/yaml.v2 v2.3.0
	layeh.com/radius v0.0.0-20190322222518-890bc1058917
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/logrusorgru/aurora v0.0.0-20181002194514-a7b3b318ed4e // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.26.0 // indirect
	github.com/prometheus/procfs v0.6.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	google.golang.org/protobuf v1.26.0-rc.1 // indirect
)

// Локальный форк: server-packet.go умеет несколько параллельных ридеров
// сокета (NumReaders) и настраиваемый SO_RCVBUF (ReadBufferSize) - см.
// third_party/layeh-radius/README-FORK.md
replace layeh.com/radius => ./third_party/layeh-radius
