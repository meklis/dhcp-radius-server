package clientdb

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/meklis/dhcp-radius-server/logger"
	"github.com/meklis/dhcp-radius-server/macaddr"
	"github.com/meklis/dhcp-radius-server/prom"
)

// Config - параметры загрузки внешней базы устройств и привязок.
// Используется только скриптами (lua), api про этот пакет не знает.
// devices_url обязателен, binds - произвольный набор именованных источников
// (например clients/smart), доступных из lua через db:getBind(name, ...).
// Redis - опционально: точечные обновления записей binds по ID между полными
// reload'ами (см. BindEvent). Если Redis.Addr не задан - подписка не запускается.
type Config struct {
	DevicesURL      string            `yaml:"devices_url"`
	Binds           map[string]string `yaml:"binds"`
	RefreshInterval time.Duration     `yaml:"refresh_interval"`
	Timeout         time.Duration     `yaml:"timeout"`
	Redis           RedisConfig       `yaml:"redis"`
}

type Device struct {
	IP        net.IP
	Mac       string
	ParseType string
}

// Bind - одна запись привязки клиента к порту устройства (или просто к IP/MAC для
// источников без устройства/порта, например smart). ID - уникальный ключ записи у
// внешнего источника: по нему приходят точечные обновления через Redis (см. BindEvent),
// не затрагивающие остальные записи.
type Bind struct {
	ID        string
	IP        net.IP
	ClientMac string
	DeviceMac string
	Port      int
}

// bindIndex - один именованный источник привязок (например "clients" или "smart"),
// проиндексированный под разные варианты вызова GetBind, включая поиск без мак-адреса
// клиента (device+port) - нужен для портов, отданных под общий пул независимо от того,
// чей мак сейчас на них подключен. Значение - слайс, т.к. под одним ключом может быть
// несколько записей (например клиент подключён через разные устройства/порты).
//
// mu защищает вторичные индексы от гонок между чтением (GetBind) и точечными
// обновлениями по ID (upsert/deleteByID), которые применяются к уже опубликованному
// снапшоту напрямую, без пересоздания и подмены всего snapshot целиком - в отличие
// от полного reload() (см. store.go), который остаётся как есть.
type bindIndex struct {
	mu              sync.RWMutex
	byID            map[string]*Bind
	byMac           map[string][]*Bind
	byMacDevice     map[string][]*Bind
	byMacDevicePort map[string][]*Bind
	byDevicePort    map[string][]*Bind
	count           int // число записей в индексе (для лога/метрик)
}

func newBindIndex() *bindIndex {
	return &bindIndex{
		byID:            make(map[string]*Bind),
		byMac:           make(map[string][]*Bind),
		byMacDevice:     make(map[string][]*Bind),
		byMacDevicePort: make(map[string][]*Bind),
		byDevicePort:    make(map[string][]*Bind),
	}
}

// insertLocked добавляет запись во все вторичные индексы. Не трогает byID и count -
// вызывающий (upsertLocked) отвечает за них, чтобы корректно обработать замену
// существующего ID. Вызывающий должен либо держать mu (точечное обновление), либо
// быть единственным владельцем ещё неопубликованного индекса (первичная загрузка).
func (idx *bindIndex) insertLocked(b *Bind) {
	idx.byID[b.ID] = b
	idx.byMac[b.ClientMac] = append(idx.byMac[b.ClientMac], b)
	if b.DeviceMac == "" {
		return
	}
	key := b.ClientMac + "|" + b.DeviceMac
	idx.byMacDevice[key] = append(idx.byMacDevice[key], b)
	if b.Port == 0 {
		return
	}
	idx.byMacDevicePort[key+"|"+strconv.Itoa(b.Port)] = append(idx.byMacDevicePort[key+"|"+strconv.Itoa(b.Port)], b)
	dpKey := b.DeviceMac + "|" + strconv.Itoa(b.Port)
	idx.byDevicePort[dpKey] = append(idx.byDevicePort[dpKey], b)
}

// removeLocked убирает запись из всех вторичных индексов по её текущим (старым)
// значениям полей и из byID. См. insertLocked про требования к блокировке.
func (idx *bindIndex) removeLocked(old *Bind) {
	idx.byMac[old.ClientMac] = removeBind(idx.byMac[old.ClientMac], old.ID)
	if old.DeviceMac != "" {
		key := old.ClientMac + "|" + old.DeviceMac
		idx.byMacDevice[key] = removeBind(idx.byMacDevice[key], old.ID)
		if old.Port != 0 {
			pKey := key + "|" + strconv.Itoa(old.Port)
			idx.byMacDevicePort[pKey] = removeBind(idx.byMacDevicePort[pKey], old.ID)
			dpKey := old.DeviceMac + "|" + strconv.Itoa(old.Port)
			idx.byDevicePort[dpKey] = removeBind(idx.byDevicePort[dpKey], old.ID)
		}
	}
	delete(idx.byID, old.ID)
}

func removeBind(list []*Bind, id string) []*Bind {
	for i, b := range list {
		if b.ID == id {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// upsertLocked добавляет новую запись или заменяет существующую с тем же ID,
// возвращает true, если запись с таким ID уже была. Вызывающий отвечает за
// блокировку (см. upsert) либо за то, что индекс ещё не опубликован (первичная
// загрузка в loadBindDB).
func (idx *bindIndex) upsertLocked(b *Bind) bool {
	if old, ok := idx.byID[b.ID]; ok {
		idx.removeLocked(old)
		idx.insertLocked(b)
		return true
	}
	idx.count++
	idx.insertLocked(b)
	return false
}

// upsert - потокобезопасная версия upsertLocked для точечных обновлений уже
// опубликованного индекса (см. ApplyBindEvent). Возвращает true, если запись с
// таким ID уже была (т.е. это было обновление, а не создание).
func (idx *bindIndex) upsert(b *Bind) bool {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	return idx.upsertLocked(b)
}

// deleteByID удаляет запись по ID, если она есть, потокобезопасно. Возвращает
// true, если запись была и её удалили.
func (idx *bindIndex) deleteByID(id string) bool {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	old, ok := idx.byID[id]
	if !ok {
		return false
	}
	idx.removeLocked(old)
	idx.count--
	return true
}

// Count - число записей в индексе, потокобезопасно.
func (idx *bindIndex) Count() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.count
}

type snapshot struct {
	devices map[string]Device
	binds   map[string]*bindIndex
}

// Store - потокобезопасное хранилище с периодическим обновлением из HTTP-источников.
// Чтение (Get*) не блокируется обновлением - снапшот подменяется атомарно целиком.
// Дополнительно binds могут точечно патчиться по ID через Redis pub/sub (см.
// ApplyBindEvent) - это мутирует конкретный *bindIndex на месте (под его mu), не
// трогая остальную часть snapshot и не требуя полного reload.
type Store struct {
	conf   Config
	lg     *logger.Logger
	client *http.Client
	snap   atomic.Value // *snapshot
	stop   chan struct{}

	// liveMu защищает reloading/pendingLive - буферизацию точечных live-обновлений
	// (см. ApplyBindEvent) на время reload(). Без этого событие, применённое к
	// снапшоту прямо перед тем, как reload() подменит его целиком новым, было бы
	// молча потеряно (если то же изменение ещё не попало в свежий HTTP-дамп) - см.
	// finishReload.
	liveMu      sync.Mutex
	reloading   bool
	pendingLive []BindEvent
}

// New синхронно загружает базу при старте (fail-fast), поднимает (если настроено)
// подписку на точечные обновления binds через Redis и запускает фоновое полное
// обновление по HTTP.
func New(conf Config, lg *logger.Logger) (*Store, error) {
	if conf.DevicesURL == "" {
		return nil, fmt.Errorf("clientdb: devices_url not set")
	}
	if conf.RefreshInterval <= 0 {
		conf.RefreshInterval = 5 * time.Minute
	}
	if conf.Timeout <= 0 {
		conf.Timeout = 30 * time.Second
	}

	s := &Store{
		conf:   conf,
		lg:     lg,
		client: &http.Client{Timeout: conf.Timeout},
		stop:   make(chan struct{}),
	}

	if err := s.reload(); err != nil {
		return nil, err
	}
	if err := s.subscribeRedis(conf.Redis); err != nil {
		return nil, fmt.Errorf("clientdb: redis: %w", err)
	}
	go s.loop()
	return s, nil
}

// Close останавливает фоновое обновление и подписку на Redis (если была поднята)
func (s *Store) Close() { close(s.stop) }

func (s *Store) loop() {
	ticker := time.NewTicker(s.conf.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := s.reload(); err != nil {
				s.lg.ErrorF("clientdb: database update failed, keeping old data: %v", err)
			}
		case <-s.stop:
			return
		}
	}
}

// reload перезагружает devices и все binds с нуля по HTTP и атомарно подменяет
// весь snapshot. На время выполнения (от начала запроса к источнику до фактической
// публикации нового снапшота) точечные live-обновления через ApplyBindEvent не
// применяются напрямую, а копятся в pendingLive - иначе изменение, применённое к
// ещё старому снапшоту прямо перед подменой, было бы потеряно. finishReload (через
// defer, выполняется в любом случае - и при успехе, и при ошибке) снимает флаг и
// накатывает накопленное на снапшот, актуальный на момент завершения (новый - при
// успехе, старый - если reload провалился и снапшот не менялся).
func (s *Store) reload() error {
	s.lg.NoticeF("clientdb: start loading database")

	s.liveMu.Lock()
	s.reloading = true
	s.liveMu.Unlock()
	defer s.finishReload()

	devices, err := s.loadDevices(s.conf.DevicesURL)
	if err != nil {
		return fmt.Errorf("devices: %w", err)
	}
	// HTTP 200 с пустым/урезанным телом (например, баг на стороне источника)
	// не даёт scanner.Err() - без этой проверки reload() ниже безусловно
	// заменил бы текущий рабочий снапшот пустым, и db:getDeviceByMac начал бы
	// отвечать "не найдено" абсолютно всем - реджект всех абонентов до
	// следующего удачного reload. Старый снапшот в этом случае просто
	// продолжает обслуживать запросы (см. defer finishReload)
	if len(devices) == 0 {
		return fmt.Errorf("devices: got 0 devices from %v - refusing to replace a possibly-healthy snapshot with an empty one", s.conf.DevicesURL)
	}

	binds := make(map[string]*bindIndex, len(s.conf.Binds))
	for name, url := range s.conf.Binds {
		idx, err := s.loadBindDB(url)
		if err != nil {
			return fmt.Errorf("binds.%v: %w", name, err)
		}
		if idx.Count() == 0 {
			return fmt.Errorf("binds.%v: got 0 binds from %v - refusing to replace a possibly-healthy snapshot with an empty one", name, url)
		}
		binds[name] = idx
	}

	s.snap.Store(&snapshot{devices: devices, binds: binds})
	s.lg.NoticeF("clientdb: database updated: devices=%v", len(devices))
	bindCounts := make(map[string]int, len(binds))
	for name, idx := range binds {
		cnt := idx.Count()
		s.lg.NoticeF("clientdb: binds.%v=%v", name, cnt)
		bindCounts[name] = cnt
	}
	prom.SetClientDBSize(len(devices), bindCounts)
	prom.SetClientDBLastReload(time.Now().Unix())
	return nil
}

// finishReload снимает флаг reloading и применяет накопленные за время reload()
// live-события (см. ApplyBindEvent) к снапшоту, актуальному на этот момент - в
// том порядке, в котором они пришли. Вызывается через defer в reload(), поэтому
// отрабатывает и при ошибке reload (буфер не должен зависать навсегда, если
// источник недоступен).
func (s *Store) finishReload() {
	s.liveMu.Lock()
	pending := s.pendingLive
	s.pendingLive = nil
	s.reloading = false
	s.liveMu.Unlock()

	for _, ev := range pending {
		if err := s.applyBindEventNow(ev); err != nil {
			s.lg.ErrorF("clientdb: live-update (deferred during reload): %v", err)
		}
	}
}

func (s *Store) fetchURL(url string) (io.ReadCloser, error) {
	resp, err := s.client.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status: %v", resp.Status)
	}
	return resp.Body, nil
}

// loadDevices - строки вида ip_int;device_mac;parse_type, ключ - device_mac
func (s *Store) loadDevices(url string) (map[string]Device, error) {
	body, err := s.fetchURL(url)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	result := make(map[string]Device)
	scanner := newScanner(body)
	for scanner.Scan() {
		fields := strings.Split(strings.TrimSpace(scanner.Text()), ";")
		if len(fields) < 3 {
			continue
		}
		mac := macaddr.Normalize(fields[1])
		if mac == "" {
			continue
		}
		result[mac] = Device{
			IP:        intToIP(fields[0]),
			Mac:       mac,
			ParseType: strings.TrimSpace(fields[2]),
		}
	}
	return result, scanner.Err()
}

// loadBindDB разбирает один именованный источник привязок. Поддерживаются форматы строк:
//
//	id;ip;client_mac                      - например smart
//	id;ip;client_mac;device_mac;port      - например clients
//
// id - уникальный ключ записи у внешнего источника. Он же используется для точечных
// обновлений между reload'ами через Redis pub/sub, см. BindEvent/ApplyBindEvent.
func (s *Store) loadBindDB(url string) (*bindIndex, error) {
	body, err := s.fetchURL(url)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	idx := newBindIndex()

	scanner := newScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		b, ok := parseBindFields(strings.Split(line, ";"))
		if !ok {
			continue
		}
		// без блокировки - индекс ещё не опубликован в snapshot, дублирующийся id
		// в источнике обрабатывается как замена (последняя строка побеждает)
		idx.upsertLocked(b)
	}
	return idx, scanner.Err()
}

func parseBindFields(fields []string) (*Bind, bool) {
	if len(fields) < 3 {
		return nil, false
	}
	id := strings.TrimSpace(fields[0])
	if id == "" {
		return nil, false
	}
	clientMac := macaddr.Normalize(fields[2])
	if clientMac == "" {
		return nil, false
	}
	b := &Bind{ID: id, IP: intToIP(fields[1]), ClientMac: clientMac}
	if len(fields) >= 5 {
		b.DeviceMac = macaddr.Normalize(fields[3])
		b.Port, _ = strconv.Atoi(strings.TrimSpace(fields[4]))
	}
	return b, true
}

func newScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return scanner
}

// currentSnapshot - снапшот всегда есть: New() возвращает *Store только после
// успешного первого reload(), а reload() либо записывает снапшот целиком, либо
// возвращает ошибку до записи - Store с пустым/nil снапшотом наружу не попадает
func (s *Store) currentSnapshot() *snapshot {
	return s.snap.Load().(*snapshot)
}

func (s *Store) GetDeviceByMac(mac string) (Device, bool) {
	d, ok := s.currentSnapshot().devices[macaddr.Normalize(mac)]
	return d, ok
}

// GetBind ищет привязки в именованном источнике dbName (см. Config.Binds).
// mac - мак-адрес клиента, deviceMac/port - опциональные уточнения. mac тоже может
// быть пустым, если заданы deviceMac+port - тогда ищутся все привязки на этом порту
// устройства независимо от мак-адреса клиента (порт, отданный под общий пул).
// Возвращает все совпадения - пустой слайс, если ничего не найдено
// (в т.ч. если такого dbName нет вовсе)
func (s *Store) GetBind(dbName, mac, deviceMac, port string) []Bind {
	idx, ok := s.currentSnapshot().binds[dbName]
	if !ok {
		return nil
	}

	mac = macaddr.Normalize(mac)
	deviceMac = macaddr.Normalize(deviceMac)
	port = normalizePort(port)

	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var ptrs []*Bind
	switch {
	case mac != "" && deviceMac != "" && port != "":
		ptrs = idx.byMacDevicePort[mac+"|"+deviceMac+"|"+port]
	case mac != "" && deviceMac != "":
		ptrs = idx.byMacDevice[mac+"|"+deviceMac]
	case mac != "":
		ptrs = idx.byMac[mac]
	case deviceMac != "" && port != "":
		ptrs = idx.byDevicePort[deviceMac+"|"+port]
	}
	if len(ptrs) == 0 {
		return nil
	}

	result := make([]Bind, len(ptrs))
	for i, p := range ptrs {
		result[i] = *p
	}
	return result
}

// GetBindByID ищет одну запись по её уникальному ID в именованном источнике dbName.
// Используется в основном для проверки результата точечных обновлений (см. ApplyBindEvent).
func (s *Store) GetBindByID(dbName, id string) (Bind, bool) {
	idx, ok := s.currentSnapshot().binds[dbName]
	if !ok {
		return Bind{}, false
	}
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	b, ok := idx.byID[id]
	if !ok {
		return Bind{}, false
	}
	return *b, true
}

func normalizePort(port string) string {
	port = strings.TrimSpace(port)
	if port == "" {
		return ""
	}
	if n, err := strconv.Atoi(port); err == nil {
		return strconv.Itoa(n)
	}
	return port
}

func intToIP(s string) net.IP {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return nil
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, uint32(n))
	return ip
}
