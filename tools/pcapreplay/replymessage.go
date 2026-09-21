package main

import (
	"regexp"
	"strconv"
	"strings"
)

// replyInfo - разобранный Reply-Message в формате "vlan=..;stack=..;port=..;
// macSw=..;parse-type=.." - его в каждый ответ (Accept И Reject) кладёт как
// legacy script.pl:authenticate, так и наш auth.lua (см. replyMessage() там) -
// одним и тем же парсером читаем оба, поэтому "реальный" (из дампа) и "наш"
// (из живого ответа при прогоне через -target) результат сравнимы напрямую,
// без отдельной Go-копии парсинга circuit_id
type replyInfo struct {
	vlan, port         int
	haveVlan, havePort bool
	macSw, parseType   string
}

var replyMessageRe = regexp.MustCompile(`^vlan=`)

func parseReplyMessage(msg string) (replyInfo, bool) {
	if !replyMessageRe.MatchString(msg) {
		return replyInfo{}, false
	}
	var r replyInfo
	for _, f := range strings.Split(msg, ";") {
		kv := strings.SplitN(f, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "vlan":
			if v, err := strconv.Atoi(kv[1]); err == nil {
				r.vlan, r.haveVlan = v, true
			}
		case "port":
			if v, err := strconv.Atoi(kv[1]); err == nil {
				r.port, r.havePort = v, true
			}
		case "macSw":
			r.macSw = kv[1]
		case "parse-type":
			r.parseType = kv[1]
		}
	}
	return r, true
}
