package agent

import (
	"net/http"
)

// Error codes from spec §6.1 codes plus local extensions. They are part of the
// panel-agent contract.
const (
	ErrInvalidParams         = "invalid_params"
	ErrProtocolMismatch      = "protocol_mismatch"
	ErrForbiddenByPolicy     = "forbidden_by_policy"
	ErrNotFound              = "not_found"
	ErrConflict              = "conflict"
	ErrPreexistingConfig     = "preexisting_config_error"
	ErrConfigTestFailed      = "config_test_failed"
	ErrUnsupported           = "unsupported"
	ErrInternal              = "internal"
	ErrPayloadTooLarge       = "payload_too_large"
	ErrTooManyRequests       = "too_many_requests"
	ErrUnauthorized          = "unauthorized"
	ErrMethodNotAllowed      = "method_not_allowed"
	ErrCapabilityUnavailable = "capability_unavailable"
)

// OpError is a protocol error. Handlers return it; the server renders it as
// {"error":{"code","message","details"}} with the HTTP status from HTTPStatus.
type OpError struct {
	Code    string
	Message string
	Details any
}

func (e *OpError) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

func (e *OpError) HTTPStatus() int {
	switch e.Code {
	case ErrInvalidParams, ErrProtocolMismatch:
		return http.StatusBadRequest
	case ErrForbiddenByPolicy:
		return http.StatusForbidden
	case ErrNotFound:
		return http.StatusNotFound
	case ErrConflict:
		return http.StatusConflict
	case ErrPreexistingConfig, ErrConfigTestFailed:
		return http.StatusUnprocessableEntity
	case ErrUnsupported, ErrCapabilityUnavailable:
		return http.StatusNotImplemented
	case ErrPayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case ErrTooManyRequests:
		return http.StatusTooManyRequests
	case ErrUnauthorized:
		return http.StatusUnauthorized
	case ErrMethodNotAllowed:
		return http.StatusMethodNotAllowed
	}
	return http.StatusInternalServerError
}

func newOpError(code, msg string, details any) *OpError {
	return &OpError{Code: code, Message: msg, Details: details}
}

func invalidParams(details any) *OpError {
	return newOpError(ErrInvalidParams, "validation failed", details)
}

type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Details any    `json:"details,omitempty"`
	} `json:"error"`
}

func (e *errorEnvelope) set(err *OpError) {
	e.Error.Code = err.Code
	e.Error.Message = err.Message
	e.Error.Details = err.Details
}
