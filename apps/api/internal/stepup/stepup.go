// Package stepup holds the step-up policy (SEC-041) and the single-use step-up token (SEC-040). Consume runs inside
// the caller's DB transaction so token consumption and the authorised action are atomic.
package stepup

import (
	"context"
	"crypto/hmac"
	"time"

	"github.com/google/uuid"

	"github.com/cryptoapp/api/internal/auth"
	"github.com/cryptoapp/api/internal/store"
	"github.com/cryptoapp/api/internal/store/db"
)

type Outcome int

const (
	Consumed Outcome = iota
	Invalid          // unknown, expired, already used, other session/device/user: nothing consumed
	Mismatch         // token was valid for this session/device but bound to another action/hash: it IS consumed (burned)
)

// Consume atomically spends the token. Callers must treat Mismatch as "commit the burn, fail the request".
// The returned proof ("bio" | "pin") is only meaningful for Consumed.
func Consume(ctx context.Context, q *db.Queries, raw string, userID, sessionID, deviceID uuid.UUID, action string, bound []byte, now time.Time) (Outcome, string, error) {
	row, err := q.ConsumeStepUpToken(ctx, db.ConsumeStepUpTokenParams{
		TokenHash: auth.HashToken(raw), UserID: userID, SessionID: sessionID, DeviceID: deviceID, ConsumedAt: &now})
	if err != nil {
		if store.NotFound(err) {
			return Invalid, "", nil
		}
		return Invalid, "", err
	}
	if row.Action != action || !hmac.Equal(row.BoundHash, bound) {
		return Mismatch, "", nil
	}
	return Consumed, row.Proof, nil
}

// Mint stores a fresh step-up token bound to session, device, action and bound hash; returns the raw token.
func Mint(ctx context.Context, q *db.Queries, userID, sessionID, deviceID uuid.UUID, action string, bound []byte, proof string, ttl time.Duration, now time.Time) (string, int, error) {
	raw, hash, err := auth.NewOpaque()
	if err != nil {
		return "", 0, err
	}
	if err := q.InsertStepUpToken(ctx, db.InsertStepUpTokenParams{TokenHash: hash, UserID: userID, SessionID: sessionID, DeviceID: deviceID,
		Action: action, BoundHash: bound, Proof: proof, ExpiresAt: now.Add(ttl)}); err != nil {
		return "", 0, err
	}
	return raw, int(ttl.Seconds()), nil
}

// Policy inputs for the transaction proof decision.
type Policy struct {
	KeyPresent      bool
	KeyInCoolingOff bool
	AttestationNone bool
	Prod            bool
	OverBioMax      bool
}

// RequiredForTx decides the acceptable proof server-side (SEC-041): "pin" or "either".
func RequiredForTx(p Policy) string {
	if !p.KeyPresent || p.KeyInCoolingOff || p.OverBioMax || (p.Prod && p.AttestationNone) {
		return "pin"
	}
	return "either"
}
