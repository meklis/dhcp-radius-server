package script

import (
	"runtime"
	"sync"
	"testing"

	"github.com/meklis/dhcp-radius-server/radius/events"
)

func TestEngineNoLeak(t *testing.T) {
	e := testEngineWithDB(t)

	goroutinesBefore := runtime.NumGoroutine()
	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)

	const total = 2000
	const workers = 20
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i := 0; i < total; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			_, err := e.CallAuthorize(&events.AuthRequest{
				NasIp:     "10.0.0.1",
				DeviceMac: "744D280EE846",
				AgentOption: &events.AuthRequestOption{
					RemoteId:     "08:5A:11:94:65:E0",
					RawCircuitId: dlinkCircuitID,
				},
			})
			if err != nil {
				t.Errorf("CallAuthorize: %v", err)
			}
		}()
	}
	wg.Wait()

	// пул должен быть полностью возвращён - ни одно состояние не потеряно и не задвоено
	if got := len(e.pool); got != cap(e.pool) {
		t.Errorf("pool не полностью возвращён: len=%v cap=%v", got, cap(e.pool))
	}

	runtime.GC()
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	goroutinesAfter := runtime.NumGoroutine()

	t.Logf("HeapAlloc before=%d after=%d calls=%d", m0.HeapAlloc, m1.HeapAlloc, total)
	t.Logf("goroutines before=%d after=%d", goroutinesBefore, goroutinesAfter)

	if m1.HeapAlloc > m0.HeapAlloc*3+10*1024*1024 {
		t.Errorf("подозрение на утечку: HeapAlloc вырос с %d до %d после %d вызовов", m0.HeapAlloc, m1.HeapAlloc, total)
	}
	if goroutinesAfter > goroutinesBefore+2 {
		t.Errorf("подозрение на утечку горутин: было %d, стало %d", goroutinesBefore, goroutinesAfter)
	}
}

func TestEngineNoLeakOnTimeout(t *testing.T) {
	// движок с pool_size=1 и очень маленьким timeout - часть вызовов не дождётся
	// свободного состояния и получит ошибку по таймауту. Пул всё равно должен
	// остаться консистентным (ни одно состояние не потеряно)
	lg := testLogger(t)
	e, err := New("examples/acct.lua", 1, 1, lg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = e.CallAccounting(&events.AcctRequest{DeviceMac: "AA:BB:CC:DD:EE:FF"})
		}()
	}
	wg.Wait()

	if got := len(e.pool); got != cap(e.pool) {
		t.Errorf("pool не полностью возвращён после таймаутов: len=%v cap=%v", got, cap(e.pool))
	}
}
