package script

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/meklis/all-ok-radius-server/clientdb"
	"github.com/meklis/all-ok-radius-server/radius/events"
)

// clients: реальная привязка (744D280EE846) на порту 3; порт 6 отдан под IPTV (2.2.2.2)
// под чужим маком (AABBCCDDEEFF) - имитирует checkAbonIPTV; порт 7 - две личные
// привязки разных абонентов на одном порту (несколько подключенных за одним свитч-портом);
// порт 8 отдан под Wifi (4.4.4.4) - имитирует checkAbonWifi; порт 10 - "youtube" (5.5.5.5)
const clientsBindsData = "1;16909060;744D280EE846;085A119465E0;3\n" +
	"2;33686018;AABBCCDDEEFF;085A119465E0;6\n" +
	"3;16909061;AAAAAAAAAAAA;085A119465E0;7\n" +
	"4;16909062;BBBBBBBBBBBB;085A119465E0;7\n" +
	"6;67372036;CCCCCCCCCCCD;085A119465E0;8\n" +
	"7;84215045;CCCCCCCCCCCE;085A119465E0;10\n"

func testDBServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("type") {
		case "devices":
			w.Write([]byte("33686018;085A119465E0;dlink\n"))
			w.Write([]byte("33686018;AABBCCDDEEAA;cdata\n"))
		case "clients":
			w.Write([]byte(clientsBindsData))
			w.Write([]byte("5;16909063;112233445577;AABBCCDDEEAA;2005\n"))
		}
	}))
}

func testEngineWithDB(t *testing.T) *Engine {
	t.Helper()
	srv := testDBServer(t)
	t.Cleanup(srv.Close)

	store, err := clientdb.New(clientdb.Config{
		DevicesURL:      srv.URL + "?type=devices",
		Binds:           map[string]string{"clients": srv.URL + "?type=clients"},
		RefreshInterval: time.Hour,
	}, testLogger(t))
	if err != nil {
		t.Fatalf("clientdb.New: %v", err)
	}
	t.Cleanup(store.Close)

	e, err := New("examples/auth.lua", 2, time.Second, testLogger(t), store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func TestEngineWithDBPersonalBind(t *testing.T) {
	e := testEngineWithDB(t)

	// circuit port=3 (dlinkCircuitID) совпадает с личной привязкой 744D280EE846 на порту 3
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "744D280EE846",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "08:5A:11:94:65:E0",
			RawCircuitId: dlinkCircuitID,
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.IpAddress != "1.2.3.4" {
		t.Errorf("expected ip_address=1.2.3.4, got %+v", resp)
	}
}

func TestEngineWithDBSharedPortIPTV(t *testing.T) {
	e := testEngineWithDB(t)

	// мак запроса не совпадает ни с одной привязкой - но порт 6 целиком отдан под IPTV
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "112233445566",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "08:5A:11:94:65:E0",
			RawCircuitId: "000000650006", // vlan=101, port=6
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.PoolName != "INET-101-FAKE" {
		t.Errorf("expected pool_name=INET-101-FAKE, got %+v", resp)
	}
	if resp.ExtraAttributes["Mikrotik-Address-List"] != "Triolan.IPTV" {
		t.Errorf("expected mikrotik Address-List=Triolan.IPTV, got %+v", resp.ExtraAttributes)
	}
}

func TestEngineWithDBSharedPortWifi(t *testing.T) {
	e := testEngineWithDB(t)

	// порт 8 целиком отдан под Triolan.Wifi (4.4.4.4)
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "112233445566",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "08:5A:11:94:65:E0",
			RawCircuitId: "000000650008", // vlan=101, port=8
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.PoolName != "INET-101-FAKE" {
		t.Errorf("expected pool_name=INET-101-FAKE, got %+v", resp)
	}
	if resp.ExtraAttributes["Mikrotik-Address-List"] != "Triolan.Wifi" {
		t.Errorf("expected mikrotik Address-List=Triolan.Wifi, got %+v", resp.ExtraAttributes)
	}
}

func TestEngineWithDBYoutubeBind(t *testing.T) {
	e := testEngineWithDB(t)

	// порт 10 - личная привязка на "youtube"-адрес (5.5.5.5)
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "CCCCCCCCCCCE",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "08:5A:11:94:65:E0",
			RawCircuitId: "00000065000A", // vlan=101, port=10
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.PoolName != "YOUTUBE-101" {
		t.Errorf("expected pool_name=YOUTUBE-101, got %+v", resp)
	}
	if resp.ExtraAttributes["Mikrotik-Address-List"] != "Triolan.Youtube" {
		t.Errorf("expected mikrotik Address-List=Triolan.Youtube, got %+v", resp.ExtraAttributes)
	}
}

func TestEngineWithDBCdataParser(t *testing.T) {
	e := testEngineWithDB(t)

	// cdata - алиас на bdcom-парсер: vlan=101(0x0065), unused=00, stack=2, port_raw=5 -> port=2005
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "112233445577",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "AA:BB:CC:DD:EE:AA",
			RawCircuitId: "0065000205",
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.IpAddress != "1.2.3.7" {
		t.Errorf("expected ip_address=1.2.3.7, got %+v", resp)
	}
}

func TestEngineWithDBMultipleBindsMatchByMac(t *testing.T) {
	e := testEngineWithDB(t)

	// порт 7 - две привязки (AAAAAAAAAAAA и BBBBBBBBBBBB), выбираем свою по мак-адресу
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "AAAAAAAAAAAA",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "08:5A:11:94:65:E0",
			RawCircuitId: "000000650007", // vlan=101, port=7
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.IpAddress != "1.2.3.5" {
		t.Errorf("expected ip_address=1.2.3.5, got %+v", resp)
	}
}

func TestEngineWithDBMultipleBindsNoMacMatch(t *testing.T) {
	e := testEngineWithDB(t)

	// порт 7 занят двумя ЧУЖИМИ привязками, наш мак среди них не встречается,
	// ни одна из них не магический IP - никакого совпадения, обычный фолбэк
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "CCCCCCCCCCCC",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "08:5A:11:94:65:E0",
			RawCircuitId: "000000650007",
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.PoolName != "INET-101-FAKE" || resp.LeaseTimeSec != 120 {
		t.Errorf("expected pool_name=INET-101-FAKE lease=120, got %+v", resp)
	}
}

func TestEngineWithDBGenericFallback(t *testing.T) {
	e := testEngineWithDB(t)

	// порт 9 не встречается ни в одной привязке - обычное "серое" устройство
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "999999999999",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "08:5A:11:94:65:E0",
			RawCircuitId: "000000650009", // vlan=101, port=9
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.PoolName != "INET-101-FAKE" || resp.LeaseTimeSec != 120 {
		t.Errorf("expected pool_name=INET-101-FAKE lease=120, got %+v", resp)
	}
}

func TestEngineWithDBWifiMacFallback(t *testing.T) {
	e := testEngineWithDB(t)

	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "66:99:CC:DD:EE:FF",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "08:5A:11:94:65:E0",
			RawCircuitId: "000000650009",
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.PoolName != "INET-101-WIFI" || resp.LeaseTimeSec != 1800 {
		t.Errorf("expected pool_name=INET-101-WIFI lease=1800, got %+v", resp)
	}
}

func TestEngineWithDBZteTextFormatNoRemoteId(t *testing.T) {
	e := testEngineWithDB(t)

	// ZTE OLT (l2-relay-agent): remote_id отсутствует, circuit_id - самоописываемый
	// текстовый формат (s=3 p=1 o=13 v=2146 m=e848.b842.2f7d) - тип парсинга должен
	// определиться по виду circuit_id, без похода в db по пустому macSw
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "E8:48:B8:42:2F:7D",
		AgentOption: &events.AuthRequestOption{
			RawCircuitId: "733D3320703D31206F3D313320763D32313436206D3D653834382E623834322E32663764",
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.PoolName != "INET-2146-FAKE" || resp.LeaseTimeSec != 120 {
		t.Errorf("expected pool_name=INET-2146-FAKE lease=120, got %+v", resp)
	}
}

func TestEngineWithDBNoRemoteIdLengthFallbackDlink(t *testing.T) {
	e := testEngineWithDB(t)

	// remote_id отсутствует, circuit_id - 12 hex (6 байт), формат не ZTE-текст -
	// тип парсинга определяется по длине (dlink), а не через db
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "999999999999",
		AgentOption: &events.AuthRequestOption{
			RawCircuitId: "000000650009", // vlan=101, port=9
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.PoolName != "INET-101-FAKE" || resp.LeaseTimeSec != 120 {
		t.Errorf("expected pool_name=INET-101-FAKE lease=120, got %+v", resp)
	}
}

func TestEngineWithDBNoRemoteIdLengthFallbackBdcom(t *testing.T) {
	e := testEngineWithDB(t)

	// remote_id отсутствует, circuit_id - 10 hex (5 байт) - тип парсинга
	// определяется по длине (bdcom)
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "999999999999",
		AgentOption: &events.AuthRequestOption{
			RawCircuitId: "0065000209", // vlan=101, stack=2, port_raw=9 -> port=2009
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.PoolName != "INET-101-FAKE" || resp.LeaseTimeSec != 120 {
		t.Errorf("expected pool_name=INET-101-FAKE lease=120, got %+v", resp)
	}
}

func TestEngineWithoutDB(t *testing.T) {
	// db не сконфигурирован - тип оборудования взять неоткуда, circuit_id не распознан
	e := testEngine(t, "examples/auth.lua")

	_, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "AA:BB:CC:DD:EE:FF",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "08:5A:11:94:65:E0",
			RawCircuitId: dlinkCircuitID,
		},
	})
	if err == nil {
		t.Fatal("expected error without configured db, got nil")
	}
}

func TestConcurrentAuthorizeWithDB(t *testing.T) {
	e := testEngineWithDB(t)

	done := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := e.CallAuthorize(&events.AuthRequest{
				NasIp:     "10.0.0.1",
				DeviceMac: "744D280EE846",
				AgentOption: &events.AuthRequestOption{
					RemoteId:     "08:5A:11:94:65:E0",
					RawCircuitId: dlinkCircuitID,
				},
			})
			done <- err
		}()
	}
	for i := 0; i < 10; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent CallAuthorize: %v", err)
		}
	}
}
