package events

import "errors"

// AuthErrorKind tells the radius handler how to answer when authorize() fails.
// It mirrors the FreeRADIUS module codes used by the legacy Perl script:
//
//   - KindError (RLM_MODULE_FAIL): infrastructure failure unrelated to the
//     request (clientdb down, script crashed, no free worker). No answer is
//     sent, so the NAS retries later.
//   - KindInvalid (RLM_MODULE_INVALID): this request cannot be served, e.g.
//     circuit_id did not parse. Answered with Access-Reject.
//   - KindReject (RLM_MODULE_REJECT): explicit business decision to deny the
//     device. Answered with Access-Reject.
type AuthErrorKind string

const (
	KindError   AuthErrorKind = "ERROR"
	KindInvalid AuthErrorKind = "INVALID"
	KindReject  AuthErrorKind = "REJECT"
)

// AuthError carries the kind of an authorize() failure. Any other error is KindError.
type AuthError struct {
	Kind            AuthErrorKind
	Err             error
	ExtraAttributes map[string]string
}

func (e *AuthError) Error() string { return e.Err.Error() }
func (e *AuthError) Unwrap() error { return e.Err }

func ClassifyAuthError(err error) AuthErrorKind {
	var ae *AuthError
	if errors.As(err, &ae) {
		return ae.Kind
	}
	return KindError
}
