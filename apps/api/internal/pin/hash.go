package pin

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sync/semaphore"
)

var (
	// ErrBusy is returned when the bounded Argon2 pool stays saturated (maps to 429 RATE_LIMITED; SEC-005b).
	ErrBusy = errors.New("pin: hashing capacity exhausted")
	b64     = base64.RawStdEncoding
)

// Params are the Argon2id cost parameters stored inside every hash string.
type Params struct {
	MemoryKiB   uint32
	Time        uint32
	Parallelism uint8
}

type Hasher struct {
	peppers map[int16][]byte
	cur     int16
	params  Params
	sem     *semaphore.Weighted
	wait    time.Duration
	dummy   string

	inflight, maxInflight atomic.Int64
	evaluations           atomic.Int64
}

// NewHasher builds a Hasher. peppers maps version -> secret; cur is the version used for new hashes.
func NewHasher(peppers map[int16][]byte, cur int16, p Params, concurrency int, wait time.Duration) (*Hasher, error) {
	if len(peppers[cur]) < 32 {
		return nil, errors.New("pin: pepper missing or shorter than 32 bytes")
	}
	if concurrency < 1 {
		concurrency = 1
	}
	h := &Hasher{peppers: peppers, cur: cur, params: p, sem: semaphore.NewWeighted(int64(concurrency)), wait: wait}
	d, err := h.hashLocked("000000")
	if err != nil {
		return nil, err
	}
	h.dummy = d
	return h, nil
}

// Acquire reserves one slot of the bounded pool; it fails with ErrBusy after the wait budget (2 s by default).
func (h *Hasher) Acquire(ctx context.Context) (release func(), err error) {
	ctx, cancel := context.WithTimeout(ctx, h.wait)
	defer cancel()
	if err := h.sem.Acquire(ctx, 1); err != nil {
		return nil, ErrBusy
	}
	n := h.inflight.Add(1)
	for {
		m := h.maxInflight.Load()
		if n <= m || h.maxInflight.CompareAndSwap(m, n) {
			break
		}
	}
	return func() { h.inflight.Add(-1); h.sem.Release(1) }, nil
}

// MaxInflight and Evaluations expose instrumentation for the concurrency tests.
func (h *Hasher) MaxInflight() int64    { return h.maxInflight.Load() }
func (h *Hasher) Evaluations() int64    { return h.evaluations.Load() }
func (h *Hasher) CurrentVersion() int16 { return h.cur }

func (h *Hasher) derive(pin string, version int16, salt []byte, p Params) ([]byte, error) {
	pep, ok := h.peppers[version]
	if !ok {
		return nil, errors.New("pin: unknown pepper version")
	}
	mac := hmac.New(sha256.New, pep)
	pb := []byte(pin)
	mac.Write(pb)
	for i := range pb {
		pb[i] = 0
	}
	key := mac.Sum(nil)
	out := argon2.IDKey(key, salt, p.Time, p.MemoryKiB, p.Parallelism, 32)
	for i := range key {
		key[i] = 0
	}
	return out, nil
}

// HashLocked hashes without acquiring the pool: the caller must hold a slot from Acquire.
func (h *Hasher) HashLocked(pin string) (string, error) { return h.hashLocked(pin) }

func (h *Hasher) hashLocked(pin string) (string, error) {
	h.evaluations.Add(1)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	out, err := h.derive(pin, h.cur, salt, h.params)
	if err != nil {
		return "", err
	}
	s := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s$pv=%d", h.params.MemoryKiB, h.params.Time, h.params.Parallelism,
		b64.EncodeToString(salt), b64.EncodeToString(out), h.cur)
	for i := range out {
		out[i] = 0
	}
	return s, nil
}

// Hash acquires a pool slot and hashes.
func (h *Hasher) Hash(ctx context.Context, pin string) (string, error) {
	rel, err := h.Acquire(ctx)
	if err != nil {
		return "", err
	}
	defer rel()
	return h.hashLocked(pin)
}

type parsed struct {
	p       Params
	salt    []byte
	hash    []byte
	version int16
}

func parse(s string) (parsed, error) {
	var r parsed
	parts := strings.Split(s, "$")
	if len(parts) != 7 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" || !strings.HasPrefix(parts[6], "pv=") {
		return r, errors.New("pin: malformed hash")
	}
	var m, t, p uint64
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(v, 10, 32)
		if !ok || err != nil {
			return r, errors.New("pin: malformed hash")
		}
		switch k {
		case "m":
			m = n
		case "t":
			t = n
		case "p":
			p = n
		}
	}
	if m < 8 || m > 1<<20 || t < 1 || t > 16 || p < 1 || p > 16 {
		return r, errors.New("pin: parameters out of range")
	}
	var err error
	if r.salt, err = b64.DecodeString(parts[4]); err != nil || len(r.salt) < 8 {
		return r, errors.New("pin: malformed hash")
	}
	if r.hash, err = b64.DecodeString(parts[5]); err != nil || len(r.hash) != 32 {
		return r, errors.New("pin: malformed hash")
	}
	v, err := strconv.ParseInt(strings.TrimPrefix(parts[6], "pv="), 10, 16)
	if err != nil {
		return r, errors.New("pin: malformed hash")
	}
	r.p = Params{uint32(m), uint32(t), uint8(p)}
	r.version = int16(v)
	return r, nil
}

// VerifyLocked checks pin against a stored hash; the caller must hold a pool slot. needsRehash reports a stale
// pepper version or parameter set (upgrade-on-login).
func (h *Hasher) VerifyLocked(pin, stored string) (ok, needsRehash bool, err error) {
	h.evaluations.Add(1)
	r, err := parse(stored)
	if err != nil {
		return false, false, err
	}
	got, err := h.derive(pin, r.version, r.salt, r.p)
	if err != nil {
		return false, false, err
	}
	ok = subtle.ConstantTimeCompare(got, r.hash) == 1
	for i := range got {
		got[i] = 0
	}
	return ok, ok && (r.version != h.cur || r.p != h.params), nil
}

// DummyLocked burns the same work as a verification (unknown-user / no-PIN paths) and always reports false.
func (h *Hasher) DummyLocked() {
	_, _, _ = h.VerifyLocked("000000", h.dummy)
}
