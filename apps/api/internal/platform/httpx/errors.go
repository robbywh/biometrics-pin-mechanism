// Package httpx holds the error envelope, middleware and request helpers shared by the HTTP layer.
package httpx

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// Error is the contract error (ErrorResponse). Handlers return *Error from strict handlers and the central
// ResponseErrorHandler writes it; no other error text ever leaves the process.
type Error struct {
	Status                int
	Code                  string
	Message               string
	AttemptsRemaining     *int
	AttemptsUntilHardLock *int
	RetryAfter            *int
	LockType              string
	Required              string
	// RateLimit headers are only set for 429 responses.
	RateLimit *RateInfo
}

type RateInfo struct{ Limit, Remaining, Reset int }

func (e *Error) Error() string { return e.Code }

var defaultMessages = map[string]string{
	"VALIDATION_ERROR": "Invalid request.", "AUTH_FAILED": "Authentication failed.", "PIN_INVALID": "Authentication failed.",
	"UNLOCK_REQUIRED": "Unlock required.", "STEPUP_REQUIRED": "Additional verification is required.",
	"STEPUP_INVALID": "Additional verification is required.", "COOLING_OFF": "This action is temporarily limited.",
	"SCOPE_INSUFFICIENT": "Not permitted.", "NOT_FOUND": "Not found.", "PIN_ALREADY_SET": "Request could not be completed.",
	"DEVICE_LIMIT": "Request could not be completed.", "IDEMPOTENT_REPLAY": "Request already processed.",
	"PIN_WEAK": "Choose a less predictable PIN.", "PIN_UNCHANGED": "Choose a different PIN.",
	"IDEMPOTENCY_KEY_REUSED": "Request could not be completed.", "INVALID_PUBLIC_KEY": "Request could not be completed.",
	"INSUFFICIENT_FUNDS": "Request could not be completed.", "PIN_LOCKED": "Try again later.",
	"RATE_LIMITED": "Too many requests.", "SERVICE_UNAVAILABLE": "Service unavailable.", "INTERNAL": "Internal error.",
}

// New builds an Error with the generic message for code.
func New(status int, code string) *Error {
	return &Error{Status: status, Code: code, Message: defaultMessages[code]}
}

func Validation() *Error    { return New(http.StatusBadRequest, "VALIDATION_ERROR") }
func Unprocessable() *Error { return New(http.StatusUnprocessableEntity, "VALIDATION_ERROR") }
func AuthFailed() *Error    { return New(http.StatusUnauthorized, "AUTH_FAILED") }
func NotFound() *Error      { return New(http.StatusNotFound, "NOT_FOUND") }
func Internal() *Error      { return New(http.StatusInternalServerError, "INTERNAL") }
func Unavailable() *Error   { return New(http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE") }

func RateLimited(retryAfter int, info *RateInfo) *Error {
	e := New(http.StatusTooManyRequests, "RATE_LIMITED")
	e.RetryAfter = &retryAfter
	e.RateLimit = info
	return e
}

func Ptr[T any](v T) *T { return &v }

type body struct {
	Error errBody `json:"error"`
}
type errBody struct {
	Code                  string `json:"code"`
	Message               string `json:"message"`
	AttemptsRemaining     *int   `json:"attemptsRemaining,omitempty"`
	AttemptsUntilHardLock *int   `json:"attemptsUntilHardLock,omitempty"`
	RetryAfter            *int   `json:"retryAfter,omitempty"`
	LockType              string `json:"lockType,omitempty"`
	Required              string `json:"required,omitempty"`
}

// Write renders the envelope with the headers the contract declares for the status.
func (e *Error) Write(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	if e.RetryAfter != nil && (e.Status == http.StatusTooManyRequests || e.Code == "PIN_LOCKED") {
		h.Set("Retry-After", strconv.Itoa(*e.RetryAfter))
	}
	if e.RateLimit != nil {
		h.Set("RateLimit-Limit", strconv.Itoa(e.RateLimit.Limit))
		h.Set("RateLimit-Remaining", strconv.Itoa(e.RateLimit.Remaining))
		h.Set("RateLimit-Reset", strconv.Itoa(e.RateLimit.Reset))
	}
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(body{errBody{
		Code: e.Code, Message: e.Message, AttemptsRemaining: e.AttemptsRemaining, AttemptsUntilHardLock: e.AttemptsUntilHardLock,
		RetryAfter: e.RetryAfter, LockType: e.LockType, Required: e.Required,
	}})
}
