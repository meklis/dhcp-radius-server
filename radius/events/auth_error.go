package events

import "errors"

// AuthErrorKind классифицирует, почему authorize() не смог выдать ответ - по
// аналогии с кодами возврата модуля FreeRADIUS, которые использует legacy
// Perl-скрипт этого проекта (script.pl в корне репозитория, authenticate()):
// RLM_MODULE_FAIL / RLM_MODULE_INVALID / RLM_MODULE_REJECT. Подтверждено
// прогоном реального прод-трафика через tools/pcapreplay - RLM_MODULE_INVALID
// там реально приходит явным Access-Reject, а не молчанием.
//
//   - KindError   - инфраструктурная проблема, не связанная с конкретным
//     запросом (clientdb недоступна, Lua-скрипт упал/завис, пул воркеров
//     исчерпан). Аналог RLM_MODULE_FAIL. Ответ клиенту НЕ отправляется -
//     RADIUS-таймаут на NAS, чтобы тот переспросил, когда проблема пройдёт.
//     Явный Access-Reject был бы неверен - мы не знаем, отказать реально
//     этому устройству или нет, инфраструктура просто сейчас не работает.
//   - KindInvalid - скрипт определил, что этот конкретный запрос не может
//     быть обслужен (например не распарсился circuit_id). Аналог
//     RLM_MODULE_INVALID. Отправляется явный Access-Reject.
//   - KindReject  - явное бизнес-решение отказать этому устройству (в Perl
//     константа RLM_MODULE_REJECT определена, но нигде не используется -
//     задел на будущее). Отправляется явный Access-Reject.
type AuthErrorKind string

const (
	KindError   AuthErrorKind = "ERROR"
	KindInvalid AuthErrorKind = "INVALID"
	KindReject  AuthErrorKind = "REJECT"
)

// AuthError оборачивает ошибку authorize() её AuthErrorKind, чтобы вызывающий
// код (см. radius/handler.go) мог решить, отвечать явным Access-Reject
// (INVALID/REJECT) или промолчать (ERROR). Ошибка без такой обёртки (обычный
// error откуда угодно из стека вызовов) по умолчанию считается KindError.
type AuthError struct {
	Kind AuthErrorKind
	Err  error
}

func (e *AuthError) Error() string { return e.Err.Error() }
func (e *AuthError) Unwrap() error { return e.Err }

func NewInvalidError(err error) error { return &AuthError{Kind: KindInvalid, Err: err} }
func NewRejectError(err error) error  { return &AuthError{Kind: KindReject, Err: err} }

// ClassifyAuthError достаёт AuthErrorKind из ошибки (в т.ч. обёрнутой через
// fmt.Errorf("...: %w", ...)). Неклассифицированная ошибка (обычный error,
// не через NewInvalidError/NewRejectError) считается KindError - безопасный
// дефолт: молчание, а не ошибочный явный отказ устройству, которое ни в чём
// не виновато.
func ClassifyAuthError(err error) AuthErrorKind {
	var ae *AuthError
	if errors.As(err, &ae) {
		return ae.Kind
	}
	return KindError
}
