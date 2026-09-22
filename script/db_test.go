package script

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/meklis/dhcp-radius-server/clientdb"
	"github.com/meklis/dhcp-radius-server/radius/events"
)

// clients: реальная привязка (744D280EE846) на порту 3; порт 6 отдан под IPTV (2.2.2.2)
// под чужим маком (AABBCCDDEEFF) - имитирует checkAbonIPTV; порт 7 - две личные
// привязки разных абонентов на одном порту (несколько подключенных за одним свитч-портом);
// порт 8 отдан под Wifi (4.4.4.4) - имитирует checkAbonWifi; порт 10 - "youtube" (5.5.5.5);
// порт 11 - своя привязка на реальный IP СОСУЩЕСТВУЕТ на порту с IPTV-заглушкой
// (2.2.2.2 под чужим маком) - должна выигрывать своя привязка, а не общий IPTV-пул;
// порт 12 - единственная привязка на зарезервированный IP (1.1.1.1) под чужим маком -
// не должна ни выдаваться как реальный IP, ни включать какой-либо флаг (fallback);
// порт 13 - две личные привязки + youtube-заглушка (5.5.5.5), мак запроса не совпадает
// ни с одной личной привязкой - должны получить YOUTUBE, а не INET-*-FAKE
const clientsBindsData = "1;16909060;744D280EE846;085A119465E0;3\n" +
	"2;33686018;AABBCCDDEEFF;085A119465E0;6\n" +
	"3;16909061;AAAAAAAAAAAA;085A119465E0;7\n" +
	"4;16909062;BBBBBBBBBBBB;085A119465E0;7\n" +
	"6;67372036;CCCCCCCCCCCD;085A119465E0;8\n" +
	"7;84215045;CCCCCCCCCCCE;085A119465E0;10\n" +
	"9;2996209395;0096DF35AC12;085A119465E0;11\n" +
	"10;33686018;AAAAAAAAAAAA;085A119465E0;11\n" +
	"11;16843009;DDDDDDDDDDDD;085A119465E0;12\n" +
	"12;16909076;EEEEEEEEEEEE;085A119465E0;13\n" +
	"13;16909077;FFFFFFFFFFFF;085A119465E0;13\n" +
	"14;84215045;111111111111;085A119465E0;13\n"

func testDBServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("type") {
		case "devices":
			w.Write([]byte("33686018;085A119465E0;dlink\n"))
			w.Write([]byte("33686018;AABBCCDDEEAA;cdata\n"))
			w.Write([]byte("33686018;AABBCCDDEE11;bdcom\n"))
		case "clients":
			w.Write([]byte(clientsBindsData))
			w.Write([]byte("5;16909063;112233445577;AABBCCDDEEAA;2005\n"))
			w.Write([]byte("8;16909065;1122334455AA;AABBCCDDEE11;1\n"))
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

func TestEngineWithDBBdcomParserShort(t *testing.T) {
	e := testEngineWithDB(t)

	// bdcom, короткий вариант (4 байта/8 hex): раньше здесь ожидалась "родная"
	// bdcom-раскладка (vlan=0x0A90=2704, stack=0, port_raw=1 -> port=1), которая была
	// помечена как подтверждённая внешней системой учёта интерфейсов - но сверка
	// 847 реальных request/response пар этого формата через tools/pcapreplay против
	// прод-сервера показала 0/847 совпадений с этой раскладкой и 847/847 с
	// edgecore-раскладкой (см. circuitParsers["bdcom"] в auth.lua) - таким образом,
	// прежнее "подтверждение" было ошибочным. circuit_id=0A900001 по edgecore-раскладке:
	// stack=0x0A=10, port=0x90=144, vlan=0x0001=1 - бинда на порту 144 в фикстуре нет,
	// поэтому ожидаем общий FAKE-пул, а не персональный IP
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "1122334455AA",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "AA:BB:CC:DD:EE:11",
			RawCircuitId: "0A900001",
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.PoolName != "INET-1-FAKE" || resp.LeaseTimeSec != 120 {
		t.Errorf("expected pool_name=INET-1-FAKE lease=120, got %+v", resp)
	}
}

func TestEngineWithDBVlanZeroRejects(t *testing.T) {
	e := testEngineWithDB(t)

	// circuit_id=0000000205 (bdcom, 5-байтный вариант) даёт vlan=0 - в legacy
	// Perl-скрипте "if(!$vlan)" реджектит и это (0 - falsy в Perl), не только
	// undef. Подтверждено сверкой через tools/pcapreplay на реальном трафике
	// (kharkov.pcap): 98/98 сессий с vlan=0 из circuit_id реально получают
	// Access-Reject на проде - раньше мы ошибочно выдавали Accept на "INET-0-FAKE"
	_, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "1122334455AA",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "AA:BB:CC:DD:EE:11",
			RawCircuitId: "0000000205",
		},
	})
	if err == nil {
		t.Fatal("expected reject for vlan=0, got nil error")
	}
	if kind := events.ClassifyAuthError(err); kind != events.KindInvalid {
		t.Errorf("expected KindInvalid, got %v", kind)
	}
}

func TestEngineWithDBMultipleBindsMatchByMac(t *testing.T) {
	e := testEngineWithDB(t)

	// порт 7 - две привязки (AAAAAAAAAAAA и BBBBBBBBBBBB), выбираем свою по мак-адресу.
	// DeviceMac намеренно с двоеточиями - как реально приходит User-Name от коммутатора
	// в проде (см. TestEngineWithDBWifiMacFallback/^66:99: - этот формат подтверждён
	// самим кодом auth.lua), а не как b.client_mac хранится в clientdb (без разделителей,
	// см. clientdb/store.go:normalizeMac) - раньше тест писал DeviceMac без двоеточий
	// и этим маскировал реальный баг сравнения форматов в auth.lua
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "AA:AA:AA:AA:AA:AA",
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
		DeviceMac: "CC:CC:CC:CC:CC:CC",
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

func TestEngineWithDBOwnBindBeatsSharedIPTVOnSamePort(t *testing.T) {
	e := testEngineWithDB(t)

	// порт 11 - своя привязка на реальный IP (178.150.134.243) сосуществует с
	// IPTV-заглушкой (2.2.2.2) под чужим маком. Должны получить именно свой реальный
	// IP, а не общий INET-*-FAKE пул с Triolan.IPTV - до фикса нормализации мака в
	// auth.lua (b.client_mac сравнивался с "сырым" request.device_mac без нормализации)
	// сравнение никогда не совпадало и клиент ошибочно падал в общий IPTV-пул
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "00:96:DF:35:AC:12",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "08:5A:11:94:65:E0",
			RawCircuitId: "00000065000B", // vlan=101, port=11
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.IpAddress != "178.150.134.243" {
		t.Errorf("expected ip_address=178.150.134.243, got %+v", resp)
	}
	if resp.PoolName != "" {
		t.Errorf("expected no pool_name (direct ip), got %+v", resp)
	}
}

func TestEngineWithDBReservedIPIsNotABindOrFlag(t *testing.T) {
	e := testEngineWithDB(t)

	// порт 12 - единственная привязка на зарезервированный IP (1.1.1.1) под чужим
	// маком. Не должна выдаваться как реальный ip_address (это не настоящий адрес)
	// и не должна включать какой-либо сервисный флаг - обычный fallback на "серый" пул
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "12:34:56:78:9A:BC",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "08:5A:11:94:65:E0",
			RawCircuitId: "00000065000C", // vlan=101, port=12
		},
	})
	if err != nil {
		t.Fatalf("CallAuthorize: %v", err)
	}
	if resp.IpAddress != "" {
		t.Errorf("expected no direct ip (1.1.1.1 is reserved, not a real bind), got %+v", resp)
	}
	if resp.PoolName != "INET-101-FAKE" || resp.LeaseTimeSec != 120 {
		t.Errorf("expected pool_name=INET-101-FAKE lease=120, got %+v", resp)
	}
	// extra_attributes всегда несёт диагностический Reply-Message (см. auth.lua:
	// attach()), но не должен содержать Mikrotik-Address-List - тут нет сервисного флага
	if _, ok := resp.ExtraAttributes["Mikrotik-Address-List"]; ok {
		t.Errorf("expected no Mikrotik-Address-List (no service flag), got %+v", resp.ExtraAttributes)
	}
}

func TestEngineWithDBFlagWinsWhenNoOwnBindMatches(t *testing.T) {
	e := testEngineWithDB(t)

	// порт 13 - две ЧУЖИЕ личные привязки (шаг 1 не находит совпадение по маку) +
	// youtube-заглушка (5.5.5.5). Должны получить YOUTUBE-пул (шаг 2), а не обычный
	// INET-*-FAKE - наличие нескольких "чужих" реальных привязок не должно
	// перекрывать флаг сервисного пула
	resp, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "12:34:56:78:9A:BC",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "08:5A:11:94:65:E0",
			RawCircuitId: "00000065000D", // vlan=101, port=13
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

func TestEngineWithDBNoRemoteIdRejects(t *testing.T) {
	e := testEngineWithDB(t)

	// без remote_id мака свитча нет, а circuit_id не в самоописываемом ZTE-формате
	// (см. TestEngineWithDBNoRemoteIdZteStillParses) - тип парсера определить
	// неоткуда, обслужить запрос нечем, явный reject
	_, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "999999999999",
		AgentOption: &events.AuthRequestOption{
			RawCircuitId: dlinkCircuitID,
		},
	})
	if err == nil {
		t.Fatal("expected reject without remote_id, got nil error")
	}
	if kind := events.ClassifyAuthError(err); kind != events.KindReject {
		t.Errorf("expected KindReject, got %v", kind)
	}
}

func TestEngineWithDBNoRemoteIdZteStillParses(t *testing.T) {
	e := testEngineWithDB(t)

	// ZTE OLT (l2-relay-agent) иногда не шлёт remote-id вовсе, но circuit_id в этом
	// случае самоописываемый текстовый формат (s=3 p=1 o=13 v=2146 m=e848.b842.2f7d) -
	// тип парсера однозначен без похода в db. Подтверждено сверкой через
	// tools/pcapreplay на реальном трафике (kharkov.pcap): без этой ветки
	// реджектились 30/31 сессий, которые прод реально принимает
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

func TestEngineWithDBUnknownDeviceRejects(t *testing.T) {
	e := testEngineWithDB(t)

	// remote_id задан, но такого свитча нет в devices (db:getDeviceByMac вернул nil) -
	// явный reject, никакого фолбэка по виду/длине circuit_id больше нет
	_, err := e.CallAuthorize(&events.AuthRequest{
		NasIp:     "10.0.0.1",
		DeviceMac: "999999999999",
		AgentOption: &events.AuthRequestOption{
			RemoteId:     "FFFFFFFFFFFF",
			RawCircuitId: dlinkCircuitID,
		},
	})
	if err == nil {
		t.Fatal("expected reject for unknown device, got nil error")
	}
	if kind := events.ClassifyAuthError(err); kind != events.KindReject {
		t.Errorf("expected KindReject, got %v", kind)
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
