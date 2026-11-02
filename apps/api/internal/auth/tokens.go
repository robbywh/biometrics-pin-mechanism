// Package auth issues and validates access JWTs (EdDSA), opaque tokens (bootstrap, refresh, step-up) and sessions
// with rotating refresh families (SEC-031..037). No handler parses tokens itself.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/cryptoapp/api/internal/clock"
)

const (
	Audience     = "cryptoapp-api"
	Issuer       = "cryptoapp-api"
	ScopeSession = "session"
)

type Claims struct {
	jwt.RegisteredClaims
	SID      string `json:"sid"`
	DID      string `json:"did"`
	AMR      string `json:"amr"`
	AuthTime int64  `json:"auth_time"`
	Scope    string `json:"scope"`
}

type Tokens struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	clk  clock.Clock
	ttl  time.Duration
}

func NewTokens(seed []byte, clk clock.Clock, ttl time.Duration) (*Tokens, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("auth: signing seed must be 32 bytes")
	}
	if ttl <= 0 || ttl > 10*time.Minute {
		return nil, errors.New("auth: access TTL must be in (0, 10m]")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Tokens{priv: priv, pub: priv.Public().(ed25519.PublicKey), clk: clk, ttl: ttl}, nil
}

// Issue signs an access token; the second return value is expiresIn in seconds.
func (t *Tokens) Issue(userID, sessionID, deviceID uuid.UUID, amr string, authTime time.Time) (string, int, error) {
	now := t.clk.Now()
	c := Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: userID.String(), Audience: jwt.ClaimStrings{Audience}, Issuer: Issuer,
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(t.ttl))},
		SID: sessionID.String(), DID: deviceID.String(), AMR: amr, AuthTime: authTime.Unix(), Scope: ScopeSession,
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c).SignedString(t.priv)
	return s, int(t.ttl.Seconds()), err
}

// Parse validates signature, algorithm, audience, issuer, expiry and scope.
func (t *Tokens) Parse(raw string) (*Claims, error) {
	var c Claims
	p := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithAudience(Audience), jwt.WithIssuer(Issuer),
		jwt.WithExpirationRequired(), jwt.WithTimeFunc(t.clk.Now), jwt.WithLeeway(0))
	tok, err := p.ParseWithClaims(raw, &c, func(*jwt.Token) (any, error) { return t.pub, nil })
	if err != nil || !tok.Valid || c.Scope != ScopeSession {
		return nil, errors.New("auth: invalid token")
	}
	return &c, nil
}

var opaqueRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43,512}$`)

// LooksOpaque reports whether s has the shape of an opaque token (bootstrap/refresh/step-up).
func LooksOpaque(s string) bool { return opaqueRe.MatchString(s) }

// NewOpaque returns a 256-bit random token (base64url, 43 chars) and its SHA-256 hash.
func NewOpaque() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", nil, err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	return raw, h[:], nil
}

// HashToken is the stored form of an opaque token.
func HashToken(raw string) []byte { h := sha256.Sum256([]byte(raw)); return h[:] }

// BearerToken extracts the token from an Authorization header ("Bearer <t>"); "" if absent/malformed.
func BearerToken(h string) string {
	const p = "Bearer "
	if len(h) <= len(p) || h[:len(p)] != p {
		return ""
	}
	return h[len(p):]
}
