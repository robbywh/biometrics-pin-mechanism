package cryptomsg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type vecFile struct {
	Vectors []struct {
		ID               string           `json:"id"`
		Kind             string           `json:"kind"`
		Input            map[string]any   `json:"input"`
		EquivalentInputs []map[string]any `json:"equivalentInputs"`
		SegmentsHex      []string         `json:"segmentsHex"`
		TotalBytes       int              `json:"totalBytes"`
	} `json:"vectors"`
}

func loadVectors(t *testing.T) vecFile {
	t.Helper()
	b, err := os.ReadFile("../../../../docs/features/biometric-pin-login/vectors/vectors.json")
	require.NoError(t, err)
	var v vecFile
	require.NoError(t, json.Unmarshal(b, &v))
	return v
}

func concatHex(t *testing.T, segs []string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(segs, ""))
	require.NoError(t, err)
	return b
}

func txFrom(in map[string]any) TxFields {
	return TxFields{
		Asset: in["asset"].(string), Network: in["network"].(string), Destination: in["destination"].(string),
		Amount: in["amount"].(string), Fee: in["fee"].(string), TxNonce: in["txNonce"].(string), Expiry: int64(in["expiry"].(float64)),
	}
}

func TestSharedVectors(t *testing.T) {
	v := loadVectors(t)
	require.Len(t, v.Vectors, 2)
	for _, vec := range v.Vectors {
		want := concatHex(t, vec.SegmentsHex)
		if vec.Kind == "challenge-message" { // NOTE: tx-preimage-1 declares totalBytes=140 but its segments sum to 138 (contract issue, reported)
			require.Equal(t, vec.TotalBytes, len(want), vec.ID)
		}
		switch vec.Kind {
		case "challenge-message":
			nonce, _ := hex.DecodeString(vec.Input["nonceHex"].(string))
			bh, _ := hex.DecodeString(vec.Input["boundHashHex"].(string))
			got := ChallengeMessage(vec.Input["purpose"].(string), vec.Input["userId"].(string), vec.Input["deviceId"].(string), nonce, int64(vec.Input["expiresAt"].(float64)), bh)
			require.Equal(t, want, got)
			// mutation: every single field changes the output
			base := vec.Input
			for _, mut := range []func() []byte{
				func() []byte {
					return ChallengeMessage("stepup", base["userId"].(string), base["deviceId"].(string), nonce, 1700000000, bh)
				},
				func() []byte {
					return ChallengeMessage("login", "11111111-1111-4111-8111-111111111112", base["deviceId"].(string), nonce, 1700000000, bh)
				},
				func() []byte {
					return ChallengeMessage("login", base["userId"].(string), "22222222-2222-4222-8222-222222222223", nonce, 1700000000, bh)
				},
				func() []byte {
					n2 := append([]byte{}, nonce...)
					n2[0] ^= 1
					return ChallengeMessage("login", base["userId"].(string), base["deviceId"].(string), n2, 1700000000, bh)
				},
				func() []byte {
					return ChallengeMessage("login", base["userId"].(string), base["deviceId"].(string), nonce, 1700000001, bh)
				},
				func() []byte {
					return ChallengeMessage("login", base["userId"].(string), base["deviceId"].(string), nonce, 1700000000, make([]byte, 32))
				},
			} {
				require.NotEqual(t, want, mut())
			}
		case "tx-canonical":
			f := txFrom(vec.Input)
			got, err := TxCanonical(f)
			require.NoError(t, err)
			require.Equal(t, want, got)
			h, _ := TxHash(f)
			sum := sha256.Sum256(want)
			require.Equal(t, sum[:], h)
			for _, eq := range vec.EquivalentInputs {
				g := f
				g.Amount = eq["amount"].(string)
				got2, err := TxCanonical(g)
				require.NoError(t, err)
				require.Equal(t, want, got2)
			}
			muts := []func(TxFields) TxFields{
				func(x TxFields) TxFields { x.Asset = "USDC"; return x },
				func(x TxFields) TxFields {
					x.Destination = strings.ToUpper(x.Destination[:30]) + x.Destination[30:]
					return x
				},
				func(x TxFields) TxFields { x.Amount = "1.6"; return x },
				func(x TxFields) TxFields { x.Fee = "0.002"; return x },
				func(x TxFields) TxFields { x.TxNonce = "33333333-3333-4333-8333-333333333334"; return x },
				func(x TxFields) TxFields { x.Expiry++; return x },
			}
			for _, m := range muts {
				g, err := TxCanonical(m(f))
				require.NoError(t, err)
				require.NotEqual(t, want, g)
			}
		}
	}
}

func TestNormalizeDecimal(t *testing.T) {
	for in, want := range map[string]string{"1.50": "1.5", "2.000": "2", "0.10": "0.1", "0": "0", "10": "10", "100.0100": "100.01"} {
		got, err := NormalizeDecimal(in)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	for _, bad := range []string{"01", "1.", ".5", "1e3", "-1", "+1", "", "1.0000000000000000001", "1234567890123456789", " 1", "1,5", "0x10"} {
		_, err := NormalizeDecimal(bad)
		require.Error(t, err, bad)
	}
}

func TestTxCanonicalRejects(t *testing.T) {
	ok := TxFields{"ETH", "ethereum", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1", "0", "33333333-3333-4333-8333-333333333333", 1}
	_, err := TxCanonical(ok)
	require.NoError(t, err)
	for _, mut := range []func(*TxFields){
		func(f *TxFields) { f.Asset = "BTC" }, // BTC/ethereum invalid pair
		func(f *TxFields) { f.Destination = "short" },
		func(f *TxFields) { f.TxNonce = "33333333-3333-4333-8333-33333333333G" },
		func(f *TxFields) { f.TxNonce = "AAAAAAAA-3333-4333-8333-333333333333" },
	} {
		g := ok
		mut(&g)
		_, err := TxCanonical(g)
		require.Error(t, err)
	}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func sign(t *testing.T, k *ecdsa.PrivateKey, msg []byte) []byte {
	h := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, k, h[:])
	require.NoError(t, err)
	return sig
}

func TestSignVerifyRoundTripAndPurposeConfusion(t *testing.T) {
	k := newKey(t)
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	require.Len(t, spki, 91)
	pub, err := ParseSPKI(spki)
	require.NoError(t, err)
	nonce, _ := NewNonce()
	u, d := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	msg := ChallengeMessage(PurposeLogin, u, d, nonce, 1700000000, nil)
	sig := sign(t, k, msg)
	require.True(t, VerifyDER(pub, msg, sig))
	for _, p := range []string{PurposeStepUp, PurposeEnroll} {
		require.False(t, VerifyDER(pub, ChallengeMessage(p, u, d, nonce, 1700000000, nil), sig), p)
	}
	require.False(t, VerifyDER(pub, ChallengeMessage(PurposeLogin, u, d, nonce, 1700000000, make([]byte, 32)), sig))
	require.False(t, VerifyDER(pub, msg, append(append([]byte{}, sig...), 0x00)), "trailing byte")
	other := newKey(t)
	require.False(t, VerifyDER(&other.PublicKey, msg, sig))
}

func TestVerifyDERStrictness(t *testing.T) {
	k := newKey(t)
	msg := []byte("m")
	good := sign(t, k, msg)
	require.True(t, VerifyDER(&k.PublicKey, msg, good))
	n := k.Curve.Params().N
	enc := func(r, s *big.Int) []byte { b, _ := asn1.Marshal(ecdsaSig{r, s}); return b }
	h := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
	require.NoError(t, err)
	require.True(t, VerifyDER(&k.PublicKey, msg, enc(r, s)))
	// high-S variant is accepted
	s2 := new(big.Int).Sub(n, s)
	require.True(t, VerifyDER(&k.PublicKey, msg, enc(r, s2)))
	// out of range
	require.False(t, VerifyDER(&k.PublicKey, msg, enc(big.NewInt(0), s)))
	require.False(t, VerifyDER(&k.PublicKey, msg, enc(r, n)))
	require.False(t, VerifyDER(&k.PublicKey, msg, enc(new(big.Int).Neg(r), s)))
	// non-minimal INTEGER: prefix r with a redundant 0x00 (valid BER, invalid DER)
	rb := r.Bytes()
	if rb[0]&0x80 == 0 {
		nm := []byte{0x30, byte(len(rb) + 1 + 2 + 2 + len(s.Bytes()) + 1), 0x02, byte(len(rb) + 1), 0x00}
		nm = append(nm, rb...)
		sb := s.Bytes()
		pad := 0
		if sb[0]&0x80 != 0 {
			pad = 1
		}
		nm = append(nm, 0x02, byte(len(sb)+pad))
		if pad == 1 {
			nm = append(nm, 0)
		}
		nm = append(nm, sb...)
		nm[1] = byte(len(nm) - 2)
		require.False(t, VerifyDER(&k.PublicKey, msg, nm))
	}
	// garbage
	for _, g := range [][]byte{nil, {0x30}, {0x30, 0x00}, make([]byte, 200), {0x30, 0x80, 0x00, 0x00}} {
		require.False(t, VerifyDER(&k.PublicKey, msg, g))
	}
}

func TestParseSPKIRejects(t *testing.T) {
	k := newKey(t)
	good, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	_, err := ParseSPKI(good)
	require.NoError(t, err)

	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	_, err = ParseSPKI(der384)
	require.Error(t, err)

	// RSA
	rsaDER, _ := hex.DecodeString("30820122300d06092a864886f70d01010105000382010f003082010a0282010100c4" + strings.Repeat("11", 255) + "0203010001")
	_, err = ParseSPKI(rsaDER)
	require.Error(t, err)

	// off-curve point (flip a Y byte)
	off := append([]byte{}, good...)
	off[len(off)-1] ^= 0xff
	_, err = ParseSPKI(off)
	require.Error(t, err)

	// trailing byte, oversize (201), empty
	_, err = ParseSPKI(append(append([]byte{}, good...), 0))
	require.Error(t, err)
	_, err = ParseSPKI(make([]byte, 201))
	require.Error(t, err)
	_, err = ParseSPKI(nil)
	require.Error(t, err)
	// compressed point form
	comp := elliptic.MarshalCompressed(elliptic.P256(), k.X, k.Y)
	hdr, _ := hex.DecodeString("3039301306072a8648ce3d020106082a8648ce3d03010703220000")
	hdr = append(hdr[:len(hdr)-2], comp...)
	_, err = ParseSPKI(hdr)
	require.Error(t, err)
}

func TestDecodeB64Strict(t *testing.T) {
	for _, bad := range []string{"", "AA==", "a+b/", "a b", "AA\n", "A"} {
		_, err := DecodeB64(bad)
		require.Error(t, err, bad)
	}
	b, err := DecodeB64("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	require.NoError(t, err)
	require.Len(t, b, 32)
	require.Equal(t, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", EncodeB64(b))
}

func TestActionHashDistinct(t *testing.T) {
	a := ActionHash("enable_biometric", "22222222-2222-4222-8222-222222222222")
	require.Len(t, a, 32)
	require.NotEqual(t, a, ActionHash("revoke_device", "22222222-2222-4222-8222-222222222222"))
	require.NotEqual(t, a, ActionHash("enable_biometric", "22222222-2222-4222-8222-222222222223"))
}

func TestNonceUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		n, err := NewNonce()
		require.NoError(t, err)
		require.Len(t, n, 32)
		require.False(t, seen[string(n)])
		seen[string(n)] = true
	}
}

func FuzzVerifyDER(f *testing.F) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h := sha256.Sum256([]byte("m"))
	sig, _ := ecdsa.SignASN1(rand.Reader, k, h[:])
	f.Add(sig)
	f.Add([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01})
	f.Fuzz(func(t *testing.T, b []byte) { _ = VerifyDER(&k.PublicKey, []byte("m"), b) })
}

func FuzzParseSPKI(f *testing.F) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	f.Add(der)
	f.Fuzz(func(t *testing.T, b []byte) {
		if pub, err := ParseSPKI(b); err == nil && pub == nil {
			t.Fatal("nil key without error")
		}
	})
}

func FuzzDecodeB64AndTx(f *testing.F) {
	f.Add("AAECAwQ", "1.50")
	f.Fuzz(func(t *testing.T, s, d string) {
		_, _ = DecodeB64(s)
		_, _ = NormalizeDecimal(d)
	})
}
