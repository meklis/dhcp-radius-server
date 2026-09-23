package radius

import (
	"net"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/meklis/dhcp-radius-server/logger"
	"github.com/meklis/dhcp-radius-server/radius/events"
	"layeh.com/radius"
)

// Processor is the request backend: HTTP (package api) or Lua (package script).
type Processor interface {
	Get(req *events.AuthRequest) (*events.AuthResponse, error)
	SendPostAuth(req events.AuthRequest, resp events.AuthResponse)
	SendAcct(acct *events.AcctRequest)
}

type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	Secret     string `yaml:"secret"`
	// ReadBufferSize is SO_RCVBUF in bytes, 0 keeps the system default.
	ReadBufferSize int `yaml:"read_buffer_size"`
}

type Server struct {
	processor Processor
	lg        *logger.Logger
	classID   atomic.Int64
}

func ListenAndServe(conf Config, processor Processor, lg *logger.Logger) error {
	s := &Server{processor: processor, lg: lg}
	s.classID.Store(time.Now().Unix())

	// More than a few readers does not help: the bottleneck moves to attribute
	// parsing and script execution.
	readers := min(max(runtime.NumCPU()/2, 1), 4)
	server := radius.PacketServer{
		Addr:           conf.ListenAddr,
		Network:        "udp",
		SecretSource:   radius.StaticSecretSource([]byte(conf.Secret)),
		Handler:        radius.HandlerFunc(s.serve),
		NumReaders:     readers,
		ReadBufferSize: conf.ReadBufferSize,
	}
	lg.NoticeF("radius readers=%v read_buffer_size=%v", readers, conf.ReadBufferSize)

	host, port, err := net.SplitHostPort(conf.ListenAddr)
	switch {
	case err != nil:
		lg.InfoF("Starting radius server on %v", conf.ListenAddr)
	case host != "" && host != "0.0.0.0" && host != "::":
		lg.InfoF("Starting radius server: interface=%v port=%v", host, port)
	default:
		lg.InfoF("Starting radius server: interface=%v (all) port=%v", host, port)
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLinkLocalUnicast() {
					lg.InfoF("  interface %v: %v", iface.Name, addr)
				}
			}
		}
	}
	return server.ListenAndServe()
}
