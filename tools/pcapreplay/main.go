// Command pcapreplay читает tcpdump-дамп RADIUS auth-трафика (udp port 1812),
// сопоставляет в нём каждый Access-Request с тем Access-Accept/Reject, которым
// он реально был отвечен в проде, затем прогоняет тот же самый запрос
// (атрибуты копируются byte-in-byte, меняются только Identifier/Authenticator -
// они всегда уникальны на каждый Exchange) через целевой radius-server (-target)
// и сравнивает его ответ с тем, что реально отдал прод.
//
// Как снять дамп на проде - см. tools/pcapreplay/README.md.
//
// Использование:
//
//	go run ./tools/pcapreplay -pcap dump.pcap -target 127.0.0.1:1812 -secret "$RADIUS_SECRET"
package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/meklis/all-ok-radius-server/radius/redback"
	"github.com/meklis/all-ok-radius-server/radius/redback_agent_parsers"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

// reqKey сопоставляет Access-Request с ответившим на него Access-Accept/Reject
// внутри дампа: (клиент, сервер, RADIUS Identifier). Идентификатор - всего 1
// байт, поэтому при большом трафике одно и то же значение переиспользуется много
// раз в секунду - разрешаем коллизии FIFO-очередью на ключ (см. ниже), в
// предположении, что сервер отвечает клиенту в целом в том же порядке, в каком
// получил от него запросы. Это эвристика, не гарантия - на очень тяжёлом трафике
// возможны редкие неправильные пары, отсюда и вся эта проверка на реальных
// данных, а не теоретический расчёт
type reqKey struct {
	clientIP   string
	clientPort int
	serverIP   string
	id         byte
}

type pending struct {
	attrs radius.Attributes
}

type pair struct {
	req  radius.Attributes
	real *radius.Packet
}

func main() {
	pcapPath := flag.String("pcap", "", "путь к tcpdump-дампу (classic pcap, НЕ pcapng)")
	port := flag.Int("port", 1812, "UDP-порт RADIUS auth в дампе")
	target := flag.String("target", "", "адрес radius-server для прогона, host:port - НЕ боевой сервер, из которого снят дамп, если явно не хотите нагрузить прод повторно")
	secret := flag.String("secret", "", "RADIUS-секрет, настроенный на целевом сервере (-target)")
	timeout := flag.Duration("timeout", 3*time.Second, "таймаут одного запроса при прогоне")
	workers := flag.Int("workers", 20, "количество параллельных запросов при прогоне")
	limit := flag.Int("limit", 0, "ограничить число сопоставленных пар (0 = все)")
	csvPath := flag.String("out", "", "путь для CSV со всеми результатами (опционально)")
	portCheckCSVPath := flag.String("port-check-out", "", "путь для CSV со сверкой парсинга circuit_id (vlan/port из Reply-Message реального ответа vs Reply-Message ЭТОГО сервера при прогоне через -target, см. reply_message в auth.lua). Опционально, требует -target/-secret")
	flag.Parse()

	if *pcapPath == "" {
		fmt.Fprintln(os.Stderr, "usage: pcapreplay -pcap dump.pcap -target host:port -secret '...' [-workers N] [-limit N] [-out result.csv]")
		fmt.Fprintln(os.Stderr, "       pcapreplay -pcap dump.pcap                          # dry-run: only parse+match, no replay")
		os.Exit(2)
	}
	dryRun := *target == "" && *secret == ""
	if !dryRun && (*target == "" || *secret == "") {
		fmt.Fprintln(os.Stderr, "-target and -secret must be given together (or both omitted for a dry-run)")
		os.Exit(2)
	}

	fmt.Printf("reading %s (udp port %d) ...\n", *pcapPath, *port)
	pkts, err := readUDPPackets(*pcapPath, *port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read pcap: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("read %d udp packets on port %d\n", len(pkts), *port)

	pairs, unmatched := matchPairs(pkts)
	fmt.Printf("matched %d request/response pairs (%d requests in the capture never got a paired response - skipped)\n", len(pairs), unmatched)

	if dryRun {
		fmt.Println("dry-run (-target/-secret not given): stopping here, no replay performed")
		return
	}

	if *limit > 0 && len(pairs) > *limit {
		pairs = pairs[:*limit]
	}
	if len(pairs) == 0 {
		fmt.Println("nothing to replay")
		return
	}

	fmt.Printf("replaying %d requests against %s with %d workers ...\n", len(pairs), *target, *workers)
	results := replay(pairs, *target, *secret, *timeout, *workers)

	report(results, *csvPath)
	reportPortCheck(results, *portCheckCSVPath)
}

// matchPairs сопоставляет Access-Request'ы с ответившими на них Access-Accept/
// Reject внутри одного дампа (см. reqKey). Возвращает сопоставленные пары и
// число запросов, для которых пары не нашлось (retry без ответа, ответ за
// пределами окна захвата и т.п. - обычная ситуация, не ошибка).
func matchPairs(pkts []udpPacket) ([]pair, int) {
	queues := map[reqKey][]pending{}
	var pairs []pair

	for _, u := range pkts {
		p, err := radius.Parse(u.Payload, nil)
		if err != nil {
			continue
		}
		switch p.Code {
		case radius.CodeAccessRequest:
			key := reqKey{clientIP: u.SrcIP.String(), clientPort: u.SrcPort, serverIP: u.DstIP.String(), id: p.Identifier}
			queues[key] = append(queues[key], pending{attrs: p.Attributes})
		case radius.CodeAccessAccept, radius.CodeAccessReject:
			// ответ идёт сервер->клиент - собираем тот же ключ, что и у запроса, поменяв местами адреса
			key := reqKey{clientIP: u.DstIP.String(), clientPort: u.DstPort, serverIP: u.SrcIP.String(), id: p.Identifier}
			q := queues[key]
			if len(q) == 0 {
				continue
			}
			pairs = append(pairs, pair{req: q[0].attrs, real: p})
			queues[key] = q[1:]
		}
	}

	unmatched := 0
	for _, q := range queues {
		unmatched += len(q)
	}
	return pairs, unmatched
}

// summary - сравнимая выжимка ответа (реального из дампа или полученного при
// прогоне): всё, что реально влияет на выдачу клиенту. Class сюда намеренно
// не входит - это не решение скрипта, а monotonic-счётчик запросов процесса
// (см. radius/radius.go:getClassId), уникальный per-request и заведомо разный
// между продом и локальным прогоном - сравнивать его бессмысленно. Все поля -
// сравнимые типы, поэтому summary можно сравнивать через ==
type summary struct {
	code  string // Accept / Reject / Timeout
	ip    string
	pool  string
	lease uint32
}

// equalIgnoringLease сравнивает всё, кроме lease. lease_time_sec для INET-ответов
// считается по формуле "время до ближайших 6 утра" (см. script/examples/auth.lua:
// leaseTime) - т.е. зависит от часа, в который был обработан запрос. Между
// снятием дампа и прогоном replay проходит реальное время, и то же самое
// устройство закономерно получит другой (обычно на 3600с меньше за каждый
// прошедший час) lease при иначе полностью идентичном решении - это не
// расхождение логики, а ожидаемое следствие процедуры сравнения "было/прогнали
// позже". Само значение lease всё равно попадает в отчёт/CSV для информации
func (s summary) equalIgnoringLease(o summary) bool {
	return s.code == o.code && s.ip == o.ip && s.pool == o.pool
}

func summarize(p *radius.Packet, err error) summary {
	if err != nil || p == nil {
		return summary{code: "Timeout"}
	}
	if p.Code != radius.CodeAccessAccept {
		return summary{code: "Reject"}
	}
	ip := ""
	if raw := rfc2865.FramedIPAddress_Get(p); len(raw) == 4 && !raw.Equal(net.IPv4zero) {
		ip = raw.String()
	}
	return summary{
		code:  "Accept",
		ip:    ip,
		pool:  rfc2869.FramedPool_GetString(p),
		lease: uint32(rfc2865.SessionTimeout_Get(p)),
	}
}

type result struct {
	userName  string
	macSw     string
	circuitID string
	real      summary
	got       summary
	mismatch  bool

	// сверка парсинга circuit_id по Reply-Message (см. replymessage.go) - не
	// зависит от IP/пула/bindings, только от того, как каждая сторона прочитала
	// vlan/port из circuit_id. realRM/gotRM.haveVlan==false - у этой стороны нет
	// Reply-Message вовсе (например наш ранний reject "no remote_id"/"device not
	// found" до попытки парсинга, или реальный ответ легаси без Reply-Message)
	realRM         replyInfo
	gotRM          replyInfo
	haveRealRM     bool
	haveGotRM      bool
	portRMMismatch bool // сравнивалось (обе стороны имеют Reply-Message) и vlan/port разошлись
}

// replay прогоняет каждую пару через target: новый пакет с теми же атрибутами
// (Identifier/Authenticator - свежие, их всегда генерирует radius.New), тот же
// шаред-секрет, что настроен на target, и сравнивает ответ с реальным из дампа
func replay(pairs []pair, target, secret string, timeout time.Duration, workers int) []result {
	jobs := make(chan pair)
	out := make(chan result, len(pairs))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				pkt := radius.New(radius.CodeAccessRequest, []byte(secret))
				pkt.Attributes = cloneAttrs(p.req)

				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				resp, err := radius.Exchange(ctx, pkt, target)
				cancel()

				realSum := summarize(p.real, nil)
				gotSum := summarize(resp, err)

				reqPkt := &radius.Packet{Attributes: p.req}
				realRM, haveRealRM := parseReplyMessage(rfc2865.ReplyMessage_GetString(p.real))
				var gotRM replyInfo
				var haveGotRM bool
				if resp != nil {
					gotRM, haveGotRM = parseReplyMessage(rfc2865.ReplyMessage_GetString(resp))
				}
				portRMMismatch := false
				if haveRealRM && haveGotRM {
					portRMMismatch = realRM.vlan != gotRM.vlan || realRM.port != gotRM.port ||
						realRM.haveVlan != gotRM.haveVlan || realRM.havePort != gotRM.havePort
				}

				out <- result{
					userName:       rfc2865.UserName_GetString(pkt),
					macSw:          redback_agent_parsers.ParseRemoteId(redback.AgentRemoteID_Get(reqPkt)),
					circuitID:      fmt.Sprintf("%X", redback.AgentCircuitID_Get(reqPkt)),
					real:           realSum,
					got:            gotSum,
					mismatch:       !realSum.equalIgnoringLease(gotSum),
					realRM:         realRM,
					gotRM:          gotRM,
					haveRealRM:     haveRealRM,
					haveGotRM:      haveGotRM,
					portRMMismatch: portRMMismatch,
				}
			}
		}()
	}

	go func() {
		for _, p := range pairs {
			jobs <- p
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(out)
	}()

	results := make([]result, 0, len(pairs))
	done := 0
	for r := range out {
		results = append(results, r)
		done++
		if done%1000 == 0 {
			fmt.Printf("  ... %d/%d\n", done, len(pairs))
		}
	}
	return results
}

// reportPortCheck сверяет парсинг circuit_id: vlan/port из Reply-Message
// реального ответа (дамп) против vlan/port из Reply-Message, которое вернул сам
// целевой сервер при прогоне (см. result.realRM/gotRM, заполняются в replay()).
// Никакой отдельной Go-реализации парсинга circuit_id тут нет - "got" получен от
// РЕАЛЬНОГО сервера/auth.lua, а не reverse-engineered копии (ту разъезжающуюся с
// auth.lua копию раньше приходилось вручную досинхронизировать - см. историю этого
// файла). Не зависит от актуальности bindings/IP/пула - сравнивает только то, как
// каждая сторона прочитала circuit_id
func reportPortCheck(results []result, csvPath string) {
	var noRealRM, noGotRM, compared, mismatches int
	for _, r := range results {
		if !r.haveRealRM {
			noRealRM++
			continue
		}
		if !r.haveGotRM {
			noGotRM++
			continue
		}
		compared++
		if r.portRMMismatch {
			mismatches++
		}
	}

	fmt.Printf("\nport/vlan check: %d pairs skipped (real ответ без Reply-Message), %d skipped (наш ответ без Reply-Message - ранний reject до попытки парсинга)\n", noRealRM, noGotRM)
	if compared == 0 {
		fmt.Println("port/vlan check: nothing to compare")
		return
	}
	fmt.Printf("=== port/vlan: %d/%d matched (%.2f%%), %d mismatches ===\n",
		compared-mismatches, compared, 100*float64(compared-mismatches)/float64(compared), mismatches)

	shown := 0
	for _, r := range results {
		if !r.haveRealRM || !r.haveGotRM || !r.portRMMismatch {
			continue
		}
		if shown < 20 {
			fmt.Printf("PORT MISMATCH mac=%v mac_sw=%v circuit_id=%v real_parse_type=%v got_parse_type=%v\n  real: vlan=%v port=%v (have=%v/%v)\n  got:  vlan=%v port=%v (have=%v/%v)\n",
				r.userName, r.macSw, r.circuitID, r.realRM.parseType, r.gotRM.parseType,
				r.realRM.vlan, r.realRM.port, r.realRM.haveVlan, r.realRM.havePort,
				r.gotRM.vlan, r.gotRM.port, r.gotRM.haveVlan, r.gotRM.havePort)
		}
		shown++
	}
	if shown > 20 {
		fmt.Printf("... and %d more port mismatches (see -port-check-out CSV for the full list)\n", shown-20)
	}

	if csvPath == "" {
		return
	}
	f, err := os.Create(csvPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "port check: write csv: %v\n", err)
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"mismatch", "user_name", "mac_sw", "circuit_id", "real_parse_type", "got_parse_type",
		"real_vlan", "real_port", "got_vlan", "got_port"})
	for _, r := range results {
		if !r.haveRealRM || !r.haveGotRM {
			continue
		}
		w.Write([]string{
			fmt.Sprint(r.portRMMismatch), r.userName, r.macSw, r.circuitID, r.realRM.parseType, r.gotRM.parseType,
			fmt.Sprint(r.realRM.vlan), fmt.Sprint(r.realRM.port),
			fmt.Sprint(r.gotRM.vlan), fmt.Sprint(r.gotRM.port),
		})
	}
	fmt.Printf("wrote %s\n", csvPath)
}

func cloneAttrs(src radius.Attributes) radius.Attributes {
	dst := make(radius.Attributes, len(src))
	for typ, vals := range src {
		cp := make([]radius.Attribute, len(vals))
		for i, v := range vals {
			b := make(radius.Attribute, len(v))
			copy(b, v)
			cp[i] = b
		}
		dst[typ] = cp
	}
	return dst
}

func report(results []result, csvPath string) {
	mismatches := 0
	for _, r := range results {
		if r.mismatch {
			mismatches++
		}
	}

	fmt.Printf("\n=== %d/%d matched (%.2f%%), %d mismatches ===\n",
		len(results)-mismatches, len(results), 100*float64(len(results)-mismatches)/float64(len(results)), mismatches)

	shown := 0
	for _, r := range results {
		if !r.mismatch {
			continue
		}
		if shown < 20 {
			fmt.Printf("MISMATCH mac=%v\n  real: %+v\n  got:  %+v\n", r.userName, r.real, r.got)
		}
		shown++
	}
	if shown > 20 {
		fmt.Printf("... and %d more mismatches (see -out CSV for the full list)\n", shown-20)
	}

	if csvPath == "" {
		return
	}
	f, err := os.Create(csvPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write csv: %v\n", err)
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"mismatch", "user_name", "real_code", "real_ip", "real_pool", "real_lease", "got_code", "got_ip", "got_pool", "got_lease"})
	for _, r := range results {
		w.Write([]string{
			fmt.Sprint(r.mismatch), r.userName,
			r.real.code, r.real.ip, r.real.pool, fmt.Sprint(r.real.lease),
			r.got.code, r.got.ip, r.got.pool, fmt.Sprint(r.got.lease),
		})
	}
	fmt.Printf("wrote %s\n", csvPath)
}
