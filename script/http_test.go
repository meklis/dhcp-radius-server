package script

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/meklis/dhcp-radius-server/radius/events"
)

func TestHTTPMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Method", r.Method)
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, "%v|%v|%v|%s", r.Method, r.URL.RequestURI(), r.Header.Get("X-Token"), body)
	}))
	defer server.Close()

	runLua(t, fmt.Sprintf(`
    local url = %q
    local options = {headers = {["X-Token"] = "secret"}}

    local resp = http:get(url .. "/path?a=1", options)
    assert(resp.status == 202)
    assert(resp.body == "GET|/path?a=1|secret|")
    assert(resp.headers["X-Method"] == "GET")

    assert(http:delete(url, options).body == "DELETE|/|secret|")
    assert(http:post(url, "data", options).body == "POST|/|secret|data")
    assert(http:put(url, "data").body == "PUT|/||data")
    assert(http:patch(url, json.encode({a = 1})).body == 'PATCH|/||{"a":1}')
    assert(http:post(url, nil, options).body == "POST|/|secret|")`, server.URL))
}

func TestHTTPErrorStatusIsNotAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer server.Close()

	runLua(t, fmt.Sprintf(`
    local resp, err = http:get(%q)
    assert(err == nil and resp.status == 500)`, server.URL))
}

func TestHTTPErrorIsReturnedToScript(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()

	runLua(t, fmt.Sprintf(`
    for _, url in ipairs({%q, "://broken"}) do
        local resp, err = http:get(url)
        assert(resp == nil and err ~= nil)
    end`, url))
}

func TestHTTPResponseSizeLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", maxHTTPResponseSize+1)))
	}))
	defer server.Close()

	runLua(t, fmt.Sprintf(`
    local resp, err = http:get(%q)
    assert(resp == nil and err ~= nil)`, server.URL))
}

func TestHTTPStopsAtScriptTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "acct.lua")
	source := fmt.Sprintf("function accounting(request)\n http:get(%q)\nend", server.URL)
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(path, 1, 100*time.Millisecond, testLogger(t), nil, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	start := time.Now()
	if err := e.Accounting(&events.AcctRequest{}); err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("request was not cancelled, took %v", elapsed)
	}
}
