package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type ctxKey int

const infoKey ctxKey = 1

// Info is the mutable per-request record shared by middleware and handlers (ids only, never secrets).
type Info struct {
	mu        sync.Mutex
	RequestID string
	IP        string
	UserAgent string
	Route     string
	userID    string
	deviceID  string
	W         http.ResponseWriter
}

func (i *Info) SetActor(userID, deviceID string) {
	i.mu.Lock()
	if userID != "" {
		i.userID = userID
	}
	if deviceID != "" {
		i.deviceID = deviceID
	}
	i.mu.Unlock()
}

func (i *Info) Actor() (userID, deviceID string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.userID, i.deviceID
}

// InfoFrom never returns nil (a zero Info is returned outside of HTTP, e.g. unit tests).
func InfoFrom(ctx context.Context) *Info {
	if i, ok := ctx.Value(infoKey).(*Info); ok {
		return i
	}
	return &Info{}
}

// SetHeader sets a response header from deep inside a handler (rate-limit headers).
func SetHeader(ctx context.Context, k, v string) {
	if i := InfoFrom(ctx); i.W != nil {
		i.W.Header().Set(k, v)
	}
}

var reqIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// ClientIP reads the socket address; X-Forwarded-For is trusted only behind a configured proxy (last hop).
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(c int) {
	if s.status == 0 {
		s.status = c
	}
	s.ResponseWriter.WriteHeader(c)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Base installs request id, request info, security headers and the request logger (method, route template, status,
// latency, request id, user id, device id, ip: nothing else) and recovers panics with a generic 500.
func Base(log *slog.Logger, trustProxy bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rid := r.Header.Get("X-Request-Id")
			if !reqIDRe.MatchString(rid) {
				var b [16]byte
				_, _ = rand.Read(b[:])
				rid = hex.EncodeToString(b[:])
			}
			ua := r.UserAgent()
			if len(ua) > 200 {
				ua = ua[:200]
			}
			sw := &statusWriter{ResponseWriter: w}
			info := &Info{RequestID: rid, IP: ClientIP(r, trustProxy), UserAgent: ua, W: sw}
			h := w.Header()
			h.Set("X-Request-Id", rid)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Cache-Control", "no-store")
			if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") && trustProxy {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			ctx := context.WithValue(r.Context(), infoKey, info)
			defer func() {
				if p := recover(); p != nil {
					log.ErrorContext(ctx, "panic recovered", "component", "http", "request_id", rid, "err_class", "panic")
					if sw.status == 0 {
						Internal().Write(sw)
					}
				}
				uid, did := info.Actor()
				log.InfoContext(ctx, "request", "method", r.Method, "route", info.Route, "status", sw.status,
					"latency_ms", time.Since(start).Milliseconds(), "request_id", rid, "user_id", uid, "device_id", did, "ip", info.IP)
			}()
			next.ServeHTTP(sw, r.WithContext(ctx))
		})
	}
}

// BodyLimit caps request bodies (SEC-063).
func BodyLimit(max int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, max)
			}
			next.ServeHTTP(w, r)
		})
	}
}
