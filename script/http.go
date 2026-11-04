package script

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// maxHTTPResponseSize keeps a misbehaving server from filling the memory of a
// pooled Lua state.
const maxHTTPResponseSize = 10 << 20

// httpClient is shared by all scripts. Calls are bounded by the script timeout;
// Timeout only covers the top-level chunk, which runs at startup without one.
var httpClient = newHTTPClient()

func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 32
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}
}

// httpFuncs is the script global http. A response with any status is a result,
// not an error: nil, err is returned only when no response was received.
var httpFuncs = map[string]lua.LGFunction{
	// get(url, [options]) -> response | nil, err
	"get": httpMethod(http.MethodGet, false),
	// delete(url, [options]) -> response | nil, err
	"delete": httpMethod(http.MethodDelete, false),
	// post(url, [body], [options]) -> response | nil, err
	"post": httpMethod(http.MethodPost, true),
	// put(url, [body], [options]) -> response | nil, err
	"put": httpMethod(http.MethodPut, true),
	// patch(url, [body], [options]) -> response | nil, err
	"patch": httpMethod(http.MethodPatch, true),
}

func httpMethod(method string, hasBody bool) lua.LGFunction {
	return func(l *lua.LState) int {
		url := l.CheckString(2)
		optionsIdx := 3
		var body io.Reader
		if hasBody {
			body = strings.NewReader(l.OptString(3, ""))
			optionsIdx = 4
		}
		options := l.OptTable(optionsIdx, nil)

		req, err := http.NewRequestWithContext(luaContext(l), method, url, body)
		if err != nil {
			return pushLuaError(l, err)
		}
		if options != nil {
			if headers, ok := options.RawGetString("headers").(*lua.LTable); ok {
				headers.ForEach(func(k, v lua.LValue) { req.Header.Set(k.String(), v.String()) })
			}
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return pushLuaError(l, err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseSize+1))
		if err != nil {
			return pushLuaError(l, err)
		}
		if len(data) > maxHTTPResponseSize {
			return pushLuaError(l, fmt.Errorf("http: response body exceeds %d bytes", maxHTTPResponseSize))
		}

		headers := l.NewTable()
		for key, values := range resp.Header {
			headers.RawSetString(key, lua.LString(strings.Join(values, ", ")))
		}
		t := l.NewTable()
		t.RawSetString("status", lua.LNumber(resp.StatusCode))
		t.RawSetString("body", lua.LString(data))
		t.RawSetString("headers", headers)
		l.Push(t)
		return 1
	}
}
