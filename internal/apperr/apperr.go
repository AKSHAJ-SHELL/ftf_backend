// Package apperr defines a single typed error shape used by HTTP handlers
// to express user-facing failures. Internal causes are wrapped but never
// leaked to clients.
package apperr

import (
	"errors"
	"fmt"
	"net/http"
)

type Code string

const (
	CodeBadRequest   Code = "bad_request"
	CodeUnauthorized Code = "unauthorized"
	CodeForbidden    Code = "forbidden"
	CodeNotFound     Code = "not_found"
	CodeConflict     Code = "conflict"
	CodeRateLimited  Code = "rate_limited"
	CodeInternal     Code = "internal"
)

// Error is the wire-safe payload + a wrapped internal cause.
type Error struct {
	Status  int    `json:"-"`
	Code    Code   `json:"code"`
	Message string `json:"message"`
	cause   error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.cause }

// Wrap attaches a cause without changing the wire payload.
func (e *Error) Wrap(err error) *Error {
	if e == nil {
		return nil
	}
	cp := *e
	cp.cause = err
	return &cp
}

func BadRequest(msg string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: CodeBadRequest, Message: msg}
}
func Unauthorized(msg string) *Error {
	return &Error{Status: http.StatusUnauthorized, Code: CodeUnauthorized, Message: msg}
}
func Forbidden(msg string) *Error {
	return &Error{Status: http.StatusForbidden, Code: CodeForbidden, Message: msg}
}
func NotFound(msg string) *Error {
	return &Error{Status: http.StatusNotFound, Code: CodeNotFound, Message: msg}
}
func Conflict(msg string) *Error {
	return &Error{Status: http.StatusConflict, Code: CodeConflict, Message: msg}
}
func RateLimited(msg string) *Error {
	return &Error{Status: http.StatusTooManyRequests, Code: CodeRateLimited, Message: msg}
}
func Internal(msg string) *Error {
	return &Error{Status: http.StatusInternalServerError, Code: CodeInternal, Message: msg}
}

// As extracts an *Error from err if present.
func As(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
