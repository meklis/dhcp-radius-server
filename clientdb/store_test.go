package clientdb

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/meklis/dhcp-radius-server/logger"
)

// clients - формат id;ip;client_mac;device_mac;port
const clientsSample = `1;33686018;744D280EE846;085A119465E0;3
2;33686018;AABBCCDDEEFF;085A119465E0;6
3;33686018;AABBCCDDEEFF;085A119465E0;7
4;2887141235;1C61B459F78F;085A11946600;6
`

// smart - формат id;ip;client_mac (без устройства и порта)
const smartSample = `1;33686018;744D280EE846
2;169088289;0418D6EE60F1
`

const devicesSample = `33686018;085A119465E0;dlink
33686018;085A11946600;dlink
`

func testLogger(t *testing.T) *logger.Logger {
	t.Helper()
	lg, err := logger.New("test", 0, os.Stdout)
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}
	return lg
}

func testServer(t *testing.T, devices, clients, smart string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("type") {
		case "devices":
			w.Write([]byte(devices))
		case "clients":
			w.Write([]byte(clients))
		case "smart":
			w.Write([]byte(smart))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

func testConfig(url string) Config {
	return Config{
		DevicesURL: url + "?type=devices",
		Binds: map[string]string{
			"clients": url + "?type=clients",
			"smart":   url + "?type=smart",
		},
		RefreshInterval: time.Hour,
	}
}

func TestNewAndLookups(t *testing.T) {
	srv := testServer(t, devicesSample, clientsSample, smartSample)
	defer srv.Close()

	s, err := New(testConfig(srv.URL), testLogger(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	d, ok := s.GetDeviceByMac("08:5a:11:94:65:e0")
	if !ok {
		t.Fatal("device not found")
	}
	if d.IP.String() != "2.2.2.2" || d.ParseType != "dlink" {
		t.Errorf("unexpected device: %+v", d)
	}
	if _, ok := s.GetDeviceByMac("00:00:00:00:00:00"); ok {
		t.Error("unexpected device found")
	}

	// smart - поиск только по мак клиента (устройство/порт в этом источнике отсутствуют)
	binds := s.GetBind("smart", "744D280EE846", "", "")
	if len(binds) != 1 || binds[0].IP.String() != "2.2.2.2" {
		t.Errorf("unexpected smart binds: %+v", binds)
	}

	// clients - несколько записей под одним мак клиента (разные устройства/порты)
	binds = s.GetBind("clients", "AABBCCDDEEFF", "", "")
	if len(binds) != 2 {
		t.Fatalf("expected 2 binds for shared mac, got %v: %+v", len(binds), binds)
	}

	// уточнение мак устройства + портом сужает до одной записи
	binds = s.GetBind("clients", "AA:BB:CC:DD:EE:FF", "085a119465e0", "6")
	if len(binds) != 1 || binds[0].Port != 6 {
		t.Errorf("unexpected bind by mac+device+port: %+v", binds)
	}

	// несуществующий порт не должен найтись при уточнении
	if binds := s.GetBind("clients", "744D280EE846", "085A119465E0", "99"); len(binds) != 0 {
		t.Errorf("expected no binds for wrong port, got %+v", binds)
	}

	// неизвестное имя базы - пустой результат, не паника
	if binds := s.GetBind("unknown-db", "744D280EE846", "", ""); len(binds) != 0 {
		t.Errorf("expected empty result for unknown db, got %+v", binds)
	}

	if binds := s.GetBind("clients", "unknown-mac", "", ""); len(binds) != 0 {
		t.Errorf("expected empty result for unknown mac, got %+v", binds)
	}
}

func TestReloadClearsStaleRecords(t *testing.T) {
	devices := devicesSample
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("type") {
		case "devices":
			w.Write([]byte(devices))
		case "clients", "smart":
			w.Write([]byte(clientsSample))
		}
	}))
	defer srv.Close()

	s, err := New(testConfig(srv.URL), testLogger(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	if _, ok := s.GetDeviceByMac("085A119465E0"); !ok {
		t.Fatal("expected device to be present before reload")
	}

	// источник больше не отдаёт эту конкретную запись, но остаётся непустым -
	// полностью пустой источник теперь отдельно отклоняется, см.
	// TestReloadRejectsEmptyDevices/TestReloadRejectsEmptyBinds
	devices = "33686018;085A11946600;dlink\n"
	if err := s.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if _, ok := s.GetDeviceByMac("085A119465E0"); ok {
		t.Error("stale record was not cleared after reload")
	}
	if _, ok := s.GetDeviceByMac("085A11946600"); !ok {
		t.Error("expected remaining device to still be present")
	}
}

// TestReloadRejectsEmptyDevices - HTTP 200 с пустым телом (например, баг на
// стороне источника) не должен молча заменить рабочий снапшот пустым - reload
// должен провалиться, а старые данные - продолжать обслуживать запросы
func TestReloadRejectsEmptyDevices(t *testing.T) {
	devices := devicesSample
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("type") {
		case "devices":
			w.Write([]byte(devices))
		case "clients", "smart":
			w.Write([]byte(clientsSample))
		}
	}))
	defer srv.Close()

	s, err := New(testConfig(srv.URL), testLogger(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	devices = ""
	if err := s.reload(); err == nil {
		t.Fatal("expected reload to fail on empty devices response")
	}

	if _, ok := s.GetDeviceByMac("085A119465E0"); !ok {
		t.Error("expected old snapshot to still serve requests after a rejected reload")
	}
}

// TestReloadRejectsEmptyBinds - тот же случай, но для одного из binds-источников
func TestReloadRejectsEmptyBinds(t *testing.T) {
	clients := clientsSample
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("type") {
		case "devices":
			w.Write([]byte(devicesSample))
		case "clients":
			w.Write([]byte(clients))
		case "smart":
			w.Write([]byte(smartSample))
		}
	}))
	defer srv.Close()

	s, err := New(testConfig(srv.URL), testLogger(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	clients = ""
	if err := s.reload(); err == nil {
		t.Fatal("expected reload to fail on empty binds.clients response")
	}

	if binds := s.GetBind("clients", "", "085A119465E0", "3"); len(binds) == 0 {
		t.Error("expected old snapshot to still serve requests after a rejected reload")
	}
}

func TestNewRequiresDevicesURL(t *testing.T) {
	if _, err := New(Config{}, testLogger(t)); err == nil {
		t.Fatal("expected error for empty devices_url")
	}
}

func TestApplyBindEventUpsertAndDelete(t *testing.T) {
	srv := testServer(t, devicesSample, clientsSample, smartSample)
	defer srv.Close()

	s, err := New(testConfig(srv.URL), testLogger(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	// точечное добавление новой записи в "smart" по id, без reload (action=add)
	if err := s.ApplyBindEvent(BindEvent{
		DBType: "smart",
		Action: "add",
		Object: BindEventObject{ID: "99", IP: "123456789", Mac: "AA11BB22CC33"},
	}); err != nil {
		t.Fatalf("ApplyBindEvent add: %v", err)
	}
	binds := s.GetBind("smart", "AA11BB22CC33", "", "")
	if len(binds) != 1 || binds[0].IP.String() == "" {
		t.Fatalf("new record not visible after add: %+v", binds)
	}
	if b, ok := s.GetBindByID("smart", "99"); !ok || b.ClientMac != "AA:11:BB:22:CC:33" {
		t.Fatalf("GetBindByID after add: %+v, ok=%v", b, ok)
	}

	// точечное обновление существующей записи "clients" (id=1) - меняем порт (action=update)
	if err := s.ApplyBindEvent(BindEvent{
		DBType: "clients",
		Action: "update",
		Object: BindEventObject{ID: "1", IP: "33686018", Mac: "744D280EE846", DeviceMac: "085A119465E0", Port: "42"},
	}); err != nil {
		t.Fatalf("ApplyBindEvent update: %v", err)
	}
	// старый порт больше не находится
	if binds := s.GetBind("clients", "744D280EE846", "085A119465E0", "3"); len(binds) != 0 {
		t.Errorf("old port still indexed after update: %+v", binds)
	}
	// новый порт находится
	binds = s.GetBind("clients", "744D280EE846", "085A119465E0", "42")
	if len(binds) != 1 || binds[0].Port != 42 {
		t.Errorf("updated record not found by new port: %+v", binds)
	}
	// byDevicePort (поиск без мак клиента) тоже видит обновление
	binds = s.GetBind("clients", "", "085A119465E0", "42")
	if len(binds) != 1 {
		t.Errorf("byDevicePort not updated: %+v", binds)
	}

	// точечное удаление по id
	if err := s.ApplyBindEvent(BindEvent{DBType: "clients", Action: "delete", Object: BindEventObject{ID: "2"}}); err != nil {
		t.Fatalf("ApplyBindEvent delete: %v", err)
	}
	if binds := s.GetBind("clients", "AABBCCDDEEFF", "085A119465E0", "6"); len(binds) != 0 {
		t.Errorf("expected record id=2 to be gone after delete: %+v", binds)
	}
	// сосед по тому же мак-адресу (id=3) должен остаться нетронутым
	if binds := s.GetBind("clients", "AABBCCDDEEFF", "085A119465E0", "7"); len(binds) != 1 {
		t.Errorf("expected sibling record id=3 to survive delete: %+v", binds)
	}
	if _, ok := s.GetBindByID("clients", "2"); ok {
		t.Error("GetBindByID should not find deleted id")
	}

	// неизвестный источник - ошибка, не паника
	if err := s.ApplyBindEvent(BindEvent{DBType: "unknown-db", Action: "delete", Object: BindEventObject{ID: "1"}}); err == nil {
		t.Error("expected error for unknown db")
	}

	// неизвестный action - ошибка
	if err := s.ApplyBindEvent(BindEvent{DBType: "clients", Action: "bogus", Object: BindEventObject{ID: "1"}}); err == nil {
		t.Error("expected error for unknown action")
	}
}

func TestReloadStillWinsOverLiveUpdates(t *testing.T) {
	srv := testServer(t, devicesSample, clientsSample, smartSample)
	defer srv.Close()

	s, err := New(testConfig(srv.URL), testLogger(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	if err := s.ApplyBindEvent(BindEvent{
		DBType: "smart",
		Action: "add",
		Object: BindEventObject{ID: "99", IP: "123456789", Mac: "AA11BB22CC33"},
	}); err != nil {
		t.Fatalf("ApplyBindEvent: %v", err)
	}
	if _, ok := s.GetBindByID("smart", "99"); !ok {
		t.Fatal("expected live-updated record before reload")
	}

	// полный reload от HTTP-источника (который не знает про точечное обновление)
	// должен полностью заменить снапшот, как и раньше
	if err := s.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := s.GetBindByID("smart", "99"); ok {
		t.Error("live-update should not survive a full reload from a source that doesn't have it")
	}
}

// TestLiveUpdateDuringReloadIsBufferedAndReplayed - гонка "live-update пришёл, пока
// идёт reload": событие не должно ни потеряться при подмене снапшота, ни примениться
// к снапшоту, который вот-вот заменят целиком. Оно должно отложиться и накатиться уже
// на свежий снапшот сразу после того, как reload его опубликует.
func TestLiveUpdateDuringReloadIsBufferedAndReplayed(t *testing.T) {
	var gate chan struct{} // nil - clients отдаётся сразу, не nil - блокируется до close(gate)
	started := make(chan struct{}, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("type") {
		case "devices":
			w.Write([]byte(devicesSample))
		case "smart":
			w.Write([]byte(smartSample))
		case "clients":
			if gate != nil {
				select {
				case started <- struct{}{}:
				default:
				}
				<-gate
			}
			w.Write([]byte(clientsSample))
		}
	}))
	defer srv.Close()

	s, err := New(testConfig(srv.URL), testLogger(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	gate = make(chan struct{})
	reloadDone := make(chan error, 1)
	go func() { reloadDone <- s.reload() }()

	<-started // reload сейчас внутри loadBindDB("clients") - s.reloading уже true

	if err := s.ApplyBindEvent(BindEvent{
		DBType: "clients",
		Action: "add",
		Object: BindEventObject{ID: "77", IP: "123456789", Mac: "FF11FF22FF33"},
	}); err != nil {
		t.Fatalf("ApplyBindEvent во время reload: %v", err)
	}

	// событие пришло до подмены снапшота - оно не должно быть видно немедленно
	if _, ok := s.GetBindByID("clients", "77"); ok {
		t.Error("live-update should be deferred while reload is in flight, not applied immediately")
	}

	close(gate) // отпускаем reload
	if err := <-reloadDone; err != nil {
		t.Fatalf("reload: %v", err)
	}

	// после reload отложенное обновление должно примениться поверх свежего снапшота
	if _, ok := s.GetBindByID("clients", "77"); !ok {
		t.Error("deferred live-update was not applied after reload completed")
	}
	// остальные данные reload'а на месте - буферизация не подменяет сам reload
	if _, ok := s.GetBindByID("clients", "1"); !ok {
		t.Error("reload data missing after replaying deferred live-update")
	}
}
