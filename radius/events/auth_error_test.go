package events

import (
	"errors"
	"fmt"
	"testing"
)

func TestClassifyAuthError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want AuthErrorKind
	}{
		{"plain error", errors.New("boom"), KindError},
		{"invalid", NewInvalidError(errors.New("circuit_id parse failed")), KindInvalid},
		{"reject", NewRejectError(errors.New("blacklisted")), KindReject},
		{"wrapped invalid", fmt.Errorf("script.auth: %w", NewInvalidError(errors.New("x"))), KindInvalid},
		{"wrapped reject", fmt.Errorf("script.auth: %w", NewRejectError(errors.New("x"))), KindReject},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyAuthError(c.err); got != c.want {
				t.Errorf("ClassifyAuthError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
