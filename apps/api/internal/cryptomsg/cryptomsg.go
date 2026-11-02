// Package cryptomsg builds the signed/hashed byte layouts of contract-notes.md (sections 1-3) and verifies P-256
// signatures strictly. It has no dependency on HTTP or DB packages (T7).
package cryptomsg

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

const (
	TagBio    = "CRYPTOAPP/BIO/v1"
	TagTx     = "CRYPTOAPP/TX/v1"
	TagAction = "CRYPTOAPP/ACTION/v1"

	PurposeLogin  = "login"
	PurposeEnroll = "enroll"
	PurposeStepUp = "stepup"

	MaxSPKILen = 200
)

var (
	ErrInvalidKey   = errors.New("cryptomsg: invalid public key")
	ErrInvalidField = errors.New("cryptomsg: invalid field")
	b64url          = base64.RawURLEncoding.Strict()
	decimalRe       = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})(\.[0-9]{1,18})?$`)
	destRe          = regexp.MustCompile(`^[A-Za-z0-9]{26,90}$`)
	uuidRe          = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// lp appends uint16 big-endian length || b.
func lp(dst, b []byte) []byte {
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(b)))
	dst = append(dst, l[:]...)
	return append(dst, b...)
}

// ChallengeMessage is the message signed for login/enroll/stepup (contract-notes section 1).
func ChallengeMessage(purpose, userID, deviceID string, nonce []byte, expiresAt int64, boundHash []byte) []byte {
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(expiresAt))
	m := lp(nil, []byte(TagBio))
	m = lp(m, []byte(purpose))
	m = lp(m, []byte(userID))
	m = lp(m, []byte(deviceID))
	m = lp(m, nonce)
	m = lp(m, exp[:])
	return lp(m, boundHash)
}

// TxFields are the transaction inputs as submitted by the client.
type TxFields struct {
	Asset, Network, Destination, Amount, Fee, TxNonce string
	Expiry                                            int64
}

// NormalizeDecimal implements the amount/fee normalisation of contract-notes section 2.
func NormalizeDecimal(s string) (string, error) {
	if !decimalRe.MatchString(s) {
		return "", ErrInvalidField
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = strings.TrimRight(s, "0")
		s = strings.TrimSuffix(s, ".")
	}
	return s, nil
}

// ValidPair reports whether asset/network is an allowed combination.
func ValidPair(asset, network string) bool {
	switch asset + "/" + network {
	case "BTC/bitcoin", "ETH/ethereum", "USDC/ethereum":
		return true
	}
	return false
}

// TxCanonical returns the canonical pre-image (contract-notes section 2).
func TxCanonical(f TxFields) ([]byte, error) {
	amt, err := NormalizeDecimal(f.Amount)
	if err != nil {
		return nil, err
	}
	fee, err := NormalizeDecimal(f.Fee)
	if err != nil {
		return nil, err
	}
	if !ValidPair(f.Asset, f.Network) || !destRe.MatchString(f.Destination) || !uuidRe.MatchString(f.TxNonce) || f.Expiry < 0 {
		return nil, ErrInvalidField
	}
	m := lp(nil, []byte(TagTx))
	m = lp(m, []byte(f.Asset))
	m = lp(m, []byte(f.Network))
	m = lp(m, []byte(f.Destination))
	m = lp(m, []byte(amt))
	m = lp(m, []byte(fee))
	m = lp(m, []byte(f.TxNonce))
	return lp(m, []byte(strconv.FormatInt(f.Expiry, 10))), nil
}

// TxHash = SHA-256(TxCanonical).
func TxHash(f TxFields) ([]byte, error) {
	p, err := TxCanonical(f)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(p)
	return h[:], nil
}

// ActionHash is the bound hash for enable_biometric / revoke_device (contract-notes section 3).
func ActionHash(action, targetDeviceID string) []byte {
	m := lp(nil, []byte(TagAction))
	m = lp(m, []byte(action))
	m = lp(m, []byte(targetDeviceID))
	h := sha256.Sum256(m)
	return h[:]
}

// NewNonce returns 32 CSPRNG bytes.
func NewNonce() ([]byte, error) {
	n := make([]byte, 32)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return n, nil
}

// EncodeB64 / DecodeB64 are base64url without padding; the decoder is strict (no padding, no whitespace, no +/).
func EncodeB64(b []byte) string { return b64url.EncodeToString(b) }

func DecodeB64(s string) ([]byte, error) {
	if s == "" || len(s) > 1024 {
		return nil, ErrInvalidField
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return nil, ErrInvalidField
		}
	}
	b, err := b64url.DecodeString(s)
	if err != nil {
		return nil, ErrInvalidField
	}
	return b, nil
}

// ParseSPKI parses a P-256 SubjectPublicKeyInfo (<= 200 bytes, on curve, canonical, no trailing bytes).
func ParseSPKI(der []byte) (*ecdsa.PublicKey, error) {
	if len(der) == 0 || len(der) > MaxSPKILen {
		return nil, ErrInvalidKey
	}
	k, err := x509.ParsePKIXPublicKey(der) // rejects trailing data, off-curve points
	if err != nil {
		return nil, ErrInvalidKey
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrInvalidKey
	}
	if canon, err := x509.MarshalPKIXPublicKey(pub); err != nil || !bytes.Equal(canon, der) {
		return nil, ErrInvalidKey
	}
	return pub, nil
}

// Fingerprint is the first 8 bytes of SHA-256(SPKI DER); the only key form allowed in logs/audit.
func Fingerprint(spki []byte) []byte {
	h := sha256.Sum256(spki)
	return h[:8]
}

type ecdsaSig struct{ R, S *big.Int }

// VerifyDER verifies an ASN.1 DER ECDSA-P256-SHA256 signature over msg. Strict: trailing bytes, non-minimal
// encodings and r/s outside [1,n-1] are rejected. High-S is accepted (contract-notes section 0).
func VerifyDER(pub *ecdsa.PublicKey, msg, sig []byte) bool {
	if pub == nil || len(sig) == 0 || len(sig) > 80 {
		return false
	}
	var s ecdsaSig
	rest, err := asn1.Unmarshal(sig, &s)
	if err != nil || len(rest) != 0 || s.R == nil || s.S == nil {
		return false
	}
	if again, err := asn1.Marshal(s); err != nil || !bytes.Equal(again, sig) {
		return false
	}
	n := pub.Curve.Params().N
	if s.R.Sign() <= 0 || s.S.Sign() <= 0 || s.R.Cmp(n) >= 0 || s.S.Cmp(n) >= 0 {
		return false
	}
	h := sha256.Sum256(msg)
	return ecdsa.Verify(pub, h[:], s.R, s.S)
}
