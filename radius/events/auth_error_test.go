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
		{"invalid", &AuthError{Kind: KindInvalid, Err: errors.New("circuit_id parse failed")}, KindInvalid},
		{"reject", &AuthError{Kind: KindReject, Err: errors.New("blacklisted")}, KindReject},
		{"wrapped invalid", fmt.Errorf("script.auth: %w", &AuthError{Kind: KindInvalid, Err: errors.New("x")}), KindInvalid},
		{"wrapped reject", fmt.Errorf("script.auth: %w", &AuthError{Kind: KindReject, Err: errors.New("x")}), KindReject},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyAuthError(c.err); got != c.want {
				t.Errorf("ClassifyAuthError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
