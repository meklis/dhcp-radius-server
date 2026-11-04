package script

import (
	"strings"
	"testing"

	"github.com/meklis/dhcp-radius-server/radius/events"
)

func runLua(t *testing.T, body string) {
	t.Helper()
	e := luaEngine(t, "function accounting(request)\n"+body+"\nend", nil)
	if err := e.Accounting(&events.AcctRequest{}); err != nil {
		t.Fatalf("Accounting: %v", err)
	}
}

func TestJSONEncode(t *testing.T) {
	runLua(t, `
    assert(json.encode({b = 1, a = 'x"y'}) == '{"a":"x\\"y","b":1}')
    assert(json.encode({1, "two", true}) == '[1,"two",true]')
    assert(json.encode({list = {1, 2}, nested = {key = 1.5}}) == '{"list":[1,2],"nested":{"key":1.5}}')
    assert(json.encode({}) == '{}')
    assert(json.encode({[1] = "a", [3] = "c"}) == '{"1":"a","3":"c"}')
    assert(json.encode({"a", key = "b"}) == '{"1":"a","key":"b"}')
    assert(json.encode(1700000000) == '1700000000')
    assert(json.encode("<a&b>") == '"<a&b>"')
    assert(json.encode(nil) == 'null')`)
}

func TestJSONEncodeErrors(t *testing.T) {
	runLua(t, `
    local cycle = {}
    cycle.self = cycle
    for _, value in ipairs({cycle, {f = print}, {[true] = 1}, {n = 0/0}}) do
        local encoded, err = json.encode(value)
        assert(encoded == nil and err ~= nil)
    end`)
}

func TestJSONDecode(t *testing.T) {
	runLua(t, `
    local v = json.decode('{"id":123,"ok":true,"name":"x\\"y","list":[1,null,3],"nested":{"key":"value"},"none":null}')
    assert(v.id == 123 and v.ok == true and v.name == 'x"y')
    assert(v.list[1] == 1 and v.list[2] == nil and v.list[3] == 3)
    assert(v.nested.key == "value" and v.none == nil)

    local null, err = json.decode('null')
    assert(null == nil and err == nil)

    for _, value in ipairs({'{broken', '', '{} trailing'}) do
        local decoded, err = json.decode(value)
        assert(decoded == nil and err ~= nil)
    end`)
}

func TestJSONRoundTrip(t *testing.T) {
	runLua(t, strings.TrimSpace(`
    local source = '{"a":[1,2,{"b":"c"}],"d":false}'
    assert(json.encode(json.decode(source)) == source)`))
}
