// Package idem implements Idempotency-Key handling (SEC-060). Keys are stored per (user, endpoint, SHA-256(key)) with
// a request fingerprint. The insert runs INSIDE the operation's transaction, so concurrent identical requests execute
// once (the second insert waits on the first's unique index entry). Token-bearing responses are never stored.
package idem

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/cryptoapp/api/internal/store"
	"github.com/cryptoapp/api/internal/store/db"
)

const Retention = 24 * time.Hour

var ErrNotV4 = errors.New("idem: key is not a UUIDv4")

type State int

const (
	Fresh  State = iota // first time: proceed
	Replay              // same key and body already succeeded
	Reused              // same key, different body
)

type Key struct {
	UserID   uuid.UUID
	Endpoint string
	KeyHash  []byte
	ReqHash  []byte
}

type Stored struct {
	Status int
	Body   []byte // nil for token-bearing endpoints
}

// New validates the key (UUIDv4) and builds the record identity. reqMAC is HMAC-SHA256(secret, canonical body): the
// request hash is keyed so a database leak cannot be used to brute-force PINs contained in request bodies.
func New(userID uuid.UUID, endpoint string, key uuid.UUID, body []byte, macKey []byte) (Key, error) {
	if key.Version() != 4 || key.Variant() != uuid.RFC4122 {
		return Key{}, ErrNotV4
	}
	kh := sha256.Sum256(key[:])
	m := hmac.New(sha256.New, macKey)
	m.Write([]byte(endpoint))
	m.Write([]byte{0})
	m.Write(body)
	return Key{UserID: userID, Endpoint: endpoint, KeyHash: kh[:], ReqHash: m.Sum(nil)}, nil
}

// Peek looks for a completed record outside any transaction (replays are answered before credentials are consumed).
func Peek(ctx context.Context, q *db.Queries, k Key, now time.Time) (State, *Stored, error) {
	row, err := q.GetIdempotency(ctx, db.GetIdempotencyParams{UserID: k.UserID, Endpoint: k.Endpoint, KeyHash: k.KeyHash, ExpiresAt: now})
	if err != nil {
		if store.NotFound(err) {
			return Fresh, nil, nil
		}
		return Fresh, nil, err
	}
	return classify(row, k)
}

func classify(row db.IdempotencyKey, k Key) (State, *Stored, error) {
	if !hmac.Equal(row.RequestHash, k.ReqHash) {
		return Reused, nil, nil
	}
	return Replay, &Stored{Status: int(row.ResponseStatus), Body: row.ResponseBody}, nil
}

// Begin registers the key inside the operation's transaction.
func Begin(ctx context.Context, q *db.Queries, k Key, now time.Time) (State, *Stored, error) {
	_, err := q.InsertIdempotency(ctx, db.InsertIdempotencyParams{UserID: k.UserID, Endpoint: k.Endpoint, KeyHash: k.KeyHash,
		RequestHash: k.ReqHash, CreatedAt: now, ExpiresAt: now.Add(Retention)})
	if err == nil {
		return Fresh, nil, nil
	}
	if !store.NotFound(err) {
		return Fresh, nil, err
	}
	row, err := q.GetIdempotency(ctx, db.GetIdempotencyParams{UserID: k.UserID, Endpoint: k.Endpoint, KeyHash: k.KeyHash, ExpiresAt: now})
	if err != nil {
		return Fresh, nil, err
	}
	return classify(row, k)
}

// Complete records the final status (and body, for non-token responses).
func Complete(ctx context.Context, q *db.Queries, k Key, status int, body []byte) error {
	return q.CompleteIdempotency(ctx, db.CompleteIdempotencyParams{UserID: k.UserID, Endpoint: k.Endpoint, KeyHash: k.KeyHash,
		ResponseStatus: int16(status), ResponseBody: body})
}

// Abort removes the key (used when a request fails after Begin but its transaction is committed anyway).
func Abort(ctx context.Context, q *db.Queries, k Key) error {
	return q.DeleteIdempotency(ctx, db.DeleteIdempotencyParams{UserID: k.UserID, Endpoint: k.Endpoint, KeyHash: k.KeyHash})
}
