package radius

import (
	"errors"
	"io"
	"testing"

	"github.com/meklis/dhcp-radius-server/logger"
	"github.com/meklis/dhcp-radius-server/radius/events"
	"layeh.com/radius"
)

type fakeProcessor struct {
	resp     *events.AuthResponse
	err      error
	postAuth *events.AuthResponse
}

func (p *fakeProcessor) Get(*events.AuthRequest) (*events.AuthResponse, error) {
	return p.resp, p.err
}

func (p *fakeProcessor) SendPostAuth(_ events.AuthRequest, resp events.AuthResponse) {
	p.postAuth = &resp
}

func (p *fakeProcessor) SendAcct(*events.AcctRequest) {}

type fakeWriter struct {
	code radius.Code
	err  error
}

func (w *fakeWriter) Write(packet *radius.Packet) error {
	w.code = packet.Code
	return w.err
}

func TestPostAuthKeepsExtraAttributes(t *testing.T) {
	attrs := map[string]string{"Reply-Message": "reason"}
	cases := []struct {
		name       string
		processor  fakeProcessor
		writeErr   error
		wantCode   radius.Code
		wantStatus string
		wantAttrs  bool
	}{
		{
			name:      "accept",
			processor: fakeProcessor{resp: &events.AuthResponse{PoolName: "pool", ExtraAttributes: attrs}},
			wantCode:  radius.CodeAccessAccept,
			wantAttrs: true,
		},
		{
			name:       "reject",
			processor:  fakeProcessor{err: &events.AuthError{Kind: events.KindReject, Err: errors.New("denied"), ExtraAttributes: attrs}},
			wantCode:   radius.CodeAccessReject,
			wantStatus: "REJECT",
			wantAttrs:  true,
		},
		{
			name:       "invalid",
			processor:  fakeProcessor{err: &events.AuthError{Kind: events.KindInvalid, Err: errors.New("bad"), ExtraAttributes: attrs}},
			wantCode:   radius.CodeAccessReject,
			wantStatus: "INVALID",
			wantAttrs:  true,
		},
		{
			name:       "empty response",
			processor:  fakeProcessor{resp: &events.AuthResponse{ExtraAttributes: attrs}},
			wantCode:   radius.CodeAccessReject,
			wantStatus: "INVALID",
			wantAttrs:  true,
		},
		{
			name:       "write failed",
			processor:  fakeProcessor{resp: &events.AuthResponse{PoolName: "pool", ExtraAttributes: attrs}},
			writeErr:   errors.New("closed"),
			wantCode:   radius.CodeAccessAccept,
			wantStatus: "ERROR",
			wantAttrs:  true,
		},
		{
			name:       "infrastructure error is not answered",
			processor:  fakeProcessor{err: errors.New("boom")},
			wantStatus: "ERROR",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{processor: &c.processor, lg: logger.New(io.Discard, logger.Options{})}
			w := &fakeWriter{err: c.writeErr}
			s.serve(w, &radius.Request{Packet: radius.New(radius.CodeAccessRequest, []byte("secret"))})

			if w.code != c.wantCode {
				t.Errorf("code = %v, want %v", w.code, c.wantCode)
			}
			got := c.processor.postAuth
			if got == nil {
				t.Fatal("SendPostAuth was not called")
			}
			if got.Status != c.wantStatus {
				t.Errorf("status = %q, want %q", got.Status, c.wantStatus)
			}
			if c.wantAttrs && got.ExtraAttributes["Reply-Message"] != "reason" {
				t.Errorf("Reply-Message lost: %+v", got.ExtraAttributes)
			}
		})
	}
}
