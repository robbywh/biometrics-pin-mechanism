// Package log builds the redacting slog logger (SEC-062). It is the only package allowed to construct loggers
// (forbidigo bans the default slog logger and fmt/log printing elsewhere).
//
// Two layers protect against leaks: (1) an ALLOWLIST of attribute keys, anything else is dropped; (2) a key-pattern
// redactor for the keys that are allowed but could carry secrets by mistake.
package log

import (
	"io"
	"log/slog"
	"regexp"
	"strings"
)

var secretKey = regexp.MustCompile(`(?i)pin|token|authorization|secret|signature|nonce|key|hash|salt|pepper|idempotency|password|cookie`)

// Allowed attribute keys for operational logs. Request logs carry ids and route templates only.
var allowed = map[string]bool{
	slog.TimeKey: true, slog.LevelKey: true, slog.MessageKey: true, slog.SourceKey: false,
	"component": true, "method": true, "route": true, "status": true, "latency_ms": true, "request_id": true,
	"user_id": true, "device_id": true, "session_id": true, "ip": true, "err_class": true, "code": true, "listen": true,
	"env": true, "demo_mode": true, "op": true, "count": true,
	// audit sink fields (see internal/audit)
	"event": true, "result": true, "ts_unix": true, "meta": true, "user_agent": true,
}

const Redacted = "[redacted]"

// New returns a JSON logger writing to w with allowlisting and redaction.
func New(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level, ReplaceAttr: replace}))
}

func replace(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		// Nested groups (audit metadata) are checked by the audit package against its own allowlist; here we only redact.
		if secretKey.MatchString(a.Key) {
			return slog.String(a.Key, Redacted)
		}
		return a
	}
	if !allowed[a.Key] {
		return slog.Attr{}
	}
	if a.Key != slog.MessageKey && a.Key != slog.LevelKey && a.Key != slog.TimeKey && secretKey.MatchString(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	return a
}

// Discard returns a logger that drops everything.
func Discard() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

// IsSecretKey exposes the redaction pattern for tests.
func IsSecretKey(k string) bool { return secretKey.MatchString(strings.ToLower(k)) }
