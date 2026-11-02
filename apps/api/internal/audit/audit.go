// Package audit writes append-only security events (SEC-061): to the audit_events table (INSERT-only role) and as a
// JSON line on the audit sink (stdout). Fields are an allowlist; PINs, tokens, nonces, signatures, public key bytes and
// hashes can never be emitted (only key fingerprints).
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"net/netip"
	"regexp"
	"sort"

	"github.com/google/uuid"

	"github.com/cryptoapp/api/internal/clock"
	"github.com/cryptoapp/api/internal/platform/httpx"
	"github.com/cryptoapp/api/internal/store"
	"github.com/cryptoapp/api/internal/store/db"
)

// Event types (SEC-061 plus PIN_UNLOCKED_AFTER_LOCK per SEC-012 and DEVICE_BLOCKED per SEC-009).
const (
	PinSet               = "PIN_SET"
	PinChanged           = "PIN_CHANGED"
	PinReset             = "PIN_RESET"
	PinVerifyFail        = "PIN_VERIFY_FAIL"
	PinLocked            = "PIN_LOCKED"
	PinHardLocked        = "PIN_HARD_LOCKED"
	PinUnlockedAfterLock = "PIN_UNLOCKED_AFTER_LOCK"
	BioEnrolled          = "BIO_ENROLLED"
	BioDisabled          = "BIO_DISABLED"
	BioKeyInvalidated    = "BIO_KEY_INVALIDATED"
	BioVerifyFail        = "BIO_VERIFY_FAIL"
	LoginOK              = "LOGIN_OK"
	RefreshReuse         = "REFRESH_REUSE"
	DeviceAdded          = "DEVICE_ADDED"
	DeviceRevoked        = "DEVICE_REVOKED"
	DeviceBlocked        = "DEVICE_BLOCKED"
	StepUpOK             = "STEPUP_OK"
	StepUpFail           = "STEPUP_FAIL"
	TxCreated            = "TX_CREATED"
	CoolingOffStarted    = "COOLING_OFF_STARTED"
	RateLimited          = "RATE_LIMITED"
)

// AllTypes lists every event type (coverage table test).
var AllTypes = []string{PinSet, PinChanged, PinReset, PinVerifyFail, PinLocked, PinHardLocked, PinUnlockedAfterLock, BioEnrolled,
	BioDisabled, BioKeyInvalidated, BioVerifyFail, LoginOK, RefreshReuse, DeviceAdded, DeviceRevoked, DeviceBlocked, StepUpOK,
	StepUpFail, TxCreated, CoolingOffStarted, RateLimited}

var validType = func() map[string]bool {
	m := map[string]bool{}
	for _, t := range AllTypes {
		m[t] = true
	}
	return m
}()

// metaAllow is the metadata key allowlist; values must be small bool/int/short-safe-string.
var metaAllow = map[string]bool{
	"method": true, "fingerprint": true, "reason": true, "lock_type": true, "fail_count": true, "scope": true, "action": true,
	"count": true, "amr": true, "level": true, "attestation": true, "limit_class": true, "recent_failures": true,
	"platform": true, "retry_after": true, "purpose": true, "proof": true,
}

var safeVal = regexp.MustCompile(`^[A-Za-z0-9_.:\- ]{0,48}$`)

type Event struct {
	Type     string
	UserID   *uuid.UUID
	DeviceID *uuid.UUID
	Result   string // ok | fail
	Meta     map[string]any
}

type Writer struct {
	st    *store.Store
	log   *slog.Logger
	clk   clock.Clock
	chain bool
}

func New(st *store.Store, log *slog.Logger, clk clock.Clock, chain bool) *Writer {
	return &Writer{st: st, log: log, clk: clk, chain: chain}
}

// Sanitize returns only allowlisted, safely-shaped metadata.
func Sanitize(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		if !metaAllow[k] {
			continue
		}
		switch x := v.(type) {
		case bool, int, int16, int32, int64:
			out[k] = x
		case string:
			if safeVal.MatchString(x) {
				out[k] = x
			}
		}
	}
	return out
}

// Emit never fails the request: errors are logged by class only.
func (w *Writer) Emit(ctx context.Context, e Event) {
	if !validType[e.Type] {
		w.log.ErrorContext(ctx, "audit: unknown event type", "component", "audit", "err_class", "bad_event")
		return
	}
	if e.Result == "" {
		e.Result = "ok"
	}
	info := httpx.InfoFrom(ctx)
	meta := Sanitize(e.Meta)
	now := w.clk.Now()
	var ip *netip.Addr
	if a, err := netip.ParseAddr(info.IP); err == nil {
		ip = &a
	}
	var ua, rid *string
	if info.UserAgent != "" {
		ua = &info.UserAgent
	}
	if info.RequestID != "" {
		rid = &info.RequestID
	}
	mb, _ := json.Marshal(meta)
	row := db.InsertAuditParams{Ts: now, UserID: e.UserID, DeviceID: e.DeviceID, EventType: e.Type, Result: e.Result, Ip: ip,
		UserAgent: ua, RequestID: rid, Metadata: mb}
	var err error
	if w.chain {
		err = w.insertChained(ctx, row)
	} else {
		err = w.st.Q.InsertAudit(ctx, row)
	}
	if err != nil {
		w.log.ErrorContext(ctx, "audit: store write failed", "component", "audit", "err_class", "store")
	}
	args := []any{"event", e.Type, "result", e.Result, "ts_unix", now.Unix(), "request_id", info.RequestID, "meta", slog.GroupValue(metaAttrs(meta)...)}
	if e.UserID != nil {
		args = append(args, "user_id", e.UserID.String())
	}
	if e.DeviceID != nil {
		args = append(args, "device_id", e.DeviceID.String())
	}
	args = append(args, "ip", info.IP)
	w.log.InfoContext(ctx, "audit", args...)
}

func metaAttrs(m map[string]any) []slog.Attr {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]slog.Attr, 0, len(keys))
	for _, k := range keys {
		out = append(out, slog.Any(k, m[k]))
	}
	return out
}

// RowHash is the chain hash of an audit row (canonical JSON of metadata, sorted keys).
func RowHash(id int64, ts int64, user, device *uuid.UUID, typ, result, ip, ua, rid string, meta []byte, prev []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	h.Write(b[:])
	for _, u := range []*uuid.UUID{user, device} {
		if u != nil {
			h.Write(u[:])
		} else {
			h.Write([]byte{0})
		}
	}
	for _, s := range []string{typ, result, ip, ua, rid, canonical(meta)} {
		h.Write([]byte{0x1f})
		h.Write([]byte(s))
	}
	return h.Sum(nil)
}

func canonical(meta []byte) string {
	var m map[string]any
	if len(meta) == 0 || json.Unmarshal(meta, &m) != nil {
		return ""
	}
	out, _ := json.Marshal(m) // Go sorts map keys
	return string(out)
}

func (w *Writer) insertChained(ctx context.Context, row db.InsertAuditParams) error {
	return w.st.InTx(ctx, func(q *db.Queries) error {
		if err := q.AuditChainLock(ctx); err != nil { // serialise chain appends across instances
			return err
		}
		last, err := q.LastAudit(ctx)
		if err != nil && !store.NotFound(err) {
			return err
		}
		if err == nil {
			row.PrevHash = hashOfRow(last)
		}
		return q.InsertAudit(ctx, row)
	})
}

func hashOfRow(r db.LastAuditRow) []byte {
	return RowHash(r.ID, r.Ts.UnixMicro(), r.UserID, r.DeviceID, r.EventType, r.Result, strOr(r.Ip), strOr(r.UserAgent), strOr(r.RequestID), r.Metadata, r.PrevHash)
}

func strOr(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case *string:
		if s != nil {
			return *s
		}
	}
	return ""
}

// VerifyChain recomputes the chain over all rows and reports the first broken id (0 = intact).
func VerifyChain(ctx context.Context, q *db.Queries) (int64, error) {
	var prevHash []byte
	var after int64
	for {
		rows, err := q.ListAuditSince(ctx, db.ListAuditSinceParams{ID: after, Limit: 500})
		if err != nil {
			return 0, err
		}
		if len(rows) == 0 {
			return 0, nil
		}
		for _, r := range rows {
			if prevHash != nil || r.PrevHash != nil {
				if !bytes.Equal(prevHash, r.PrevHash) {
					return r.ID, nil
				}
			}
			prevHash = RowHash(r.ID, r.Ts.UnixMicro(), r.UserID, r.DeviceID, r.EventType, r.Result, strOr(r.Ip), strOr(r.UserAgent), strOr(r.RequestID), r.Metadata, r.PrevHash)
			after = r.ID
		}
	}
}
