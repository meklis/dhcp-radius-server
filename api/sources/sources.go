package sources

import (
	"github.com/meklis/dhcp-radius-server/logger"
	"github.com/meklis/dhcp-radius-server/prom"
	"github.com/ztrue/tracerr"
	"sort"
	"sync"
	"time"
)

type Sources struct {
	sync.Mutex
	sources        map[string]Source
	lg             *logger.Logger
	disableTimeOut time.Duration
}
type Source struct {
	Address     string
	IsAlive     bool
	Requests    int
	DisableTime time.Time
}

func New(sources []string, lg *logger.Logger, disableTimeout time.Duration) *Sources {
	src := new(Sources)
	src.lg = lg
	src.disableTimeOut = disableTimeout
	src.sources = make(map[string]Source)
	for _, addr := range sources {
		src.sources[addr] = Source{
			Address:     addr,
			IsAlive:     true,
			Requests:    0,
			DisableTime: time.Now(),
		}
	}
	go src.sourcesWatcher()
	return src
}

func (s *Sources) sourcesWatcher() {
	for {
		func() {
			s.Lock()
			defer s.Unlock()
			for key, src := range s.sources {
				if src.IsAlive {
					continue
				}
				if src.DisableTime.Add(s.disableTimeOut).Before(time.Now()) {
					src.IsAlive = true
					prom.SetApiStatus(src.Address, true)
					s.lg.NoticeF("change source %v state to alive", src.Address)
					s.sources[key] = src
				}
			}
		}()
		time.Sleep(time.Second)
	}
}

func (s *Sources) Disable(sourceName string) {
	s.Lock()
	defer s.Unlock()
	src, ok := s.sources[sourceName]
	if !ok {
		return
	}
	s.lg.NoticeF("change source %v state to dead", src.Address)
	src.IsAlive = false
	src.DisableTime = time.Now()
	prom.SetApiStatus(sourceName, false)
	s.sources[sourceName] = src
	return
}

func (a *Sources) GetSource() (*Source, error) {
	a.Lock()
	defer a.Unlock()
	slice := make([]Source, 0)
	for _, s := range a.sources {
		if !s.IsAlive {
			a.lg.DebugF("source %v not alive, ignoring...", s.Address)
			continue
		}
		slice = append(slice, s)
	}
	if len(slice) == 0 {
		return nil, tracerr.New("not found alive sources for send request")
	}
	sort.Slice(slice, func(i, j int) bool {
		return slice[i].Requests < slice[j].Requests
	})
	return &slice[0], nil
}
func (s *Sources) IncRequests(addr string) {
	s.Lock()
	defer s.Unlock()
	src, ok := s.sources[addr]
	if !ok {
		return
	}
	src.Requests = src.Requests + 1
	s.sources[addr] = src
	return
}
