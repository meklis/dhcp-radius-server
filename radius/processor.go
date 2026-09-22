package radius

import "github.com/meklis/dhcp-radius-server/radius/events"

// Processor - бэкенд обработки radius-запросов. Реализуется либо пакетом api
// (HTTP), либо пакетом script (встроенный Lua) - radius ничего не знает про
// конкретную реализацию, выбор бэкенда происходит в server/main.go.
type Processor interface {
	Get(req *events.AuthRequest) (*events.AuthResponse, error)
	SendPostAuth(req events.AuthRequest, resp events.AuthResponse)
	SendAcct(acct *events.AcctRequest)
}
