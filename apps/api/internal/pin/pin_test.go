package pin

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var fast = Params{MemoryKiB: 64, Time: 1, Parallelism: 1}

func pepper(b byte) []byte { return []byte(strings.Repeat(string(b), 40)) }

func TestPolicy(t *testing.T) {
	weak := []string{"000000", "111111", "999999", "123456", "234567", "345678", "654321", "987654", "876543", "012345", "890123",
		"121212", "343434", "123123", "456456", "112233", "445566", "520520", "159753", "147258", "010203", "abcdef", "12345", "1234567", "", "12345a", " 123456", "٠١٢٣٤٥", "123 56", "010190"}
	for _, p := range weak {
		require.ErrorIs(t, Validate(p), ErrWeak, p)
	}
	good := []string{"493017", "508264", "731905", "264809", "917350", "382046", "605193", "829471", "140826", "756320",
		"318507", "962481", "074295", "851936", "239750", "467018", "590273", "128964", "703518", "386092"}
	for _, p := range good {
		require.NoError(t, Validate(p), p)
	}
	require.GreaterOrEqual(t, CommonCount(), 200)
}

func newH(t *testing.T, conc int, wait time.Duration) *Hasher {
	h, err := NewHasher(map[int16][]byte{1: pepper('a'), 2: pepper('b')}, 1, fast, conc, wait)
	require.NoError(t, err)
	return h
}

func TestHashVerifyAndFormat(t *testing.T) {
	h := newH(t, 2, time.Second)
	s, err := h.Hash(context.Background(), "493017")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(s, "$argon2id$v=19$m=64,t=1,p=1$"))
	require.True(t, strings.HasSuffix(s, "$pv=1"))
	require.NotContains(t, s, "493017")
	require.NotContains(t, s, string(pepper('a')))
	ok, re, err := h.VerifyLocked("493017", s)
	require.NoError(t, err)
	require.True(t, ok)
	require.False(t, re)
	ok, _, _ = h.VerifyLocked("493018", s)
	require.False(t, ok)
	// distinct salts
	s2, _ := h.Hash(context.Background(), "493017")
	require.NotEqual(t, s, s2)
}

func TestWrongPepperFails(t *testing.T) {
	h1 := newH(t, 1, time.Second)
	s, _ := h1.Hash(context.Background(), "493017")
	// same version number, different secret
	h2, _ := NewHasher(map[int16][]byte{1: pepper('z')}, 1, fast, 1, time.Second)
	ok, _, err := h2.VerifyLocked("493017", s)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestPepperVersionAndParamUpgrade(t *testing.T) {
	old, _ := NewHasher(map[int16][]byte{1: pepper('a')}, 1, fast, 1, time.Second)
	s, _ := old.Hash(context.Background(), "493017")
	nw, _ := NewHasher(map[int16][]byte{1: pepper('a'), 2: pepper('b')}, 2, fast, 1, time.Second)
	ok, re, err := nw.VerifyLocked("493017", s)
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, re, "older pepper version must request a rehash")
	up, _ := NewHasher(map[int16][]byte{1: pepper('a')}, 1, Params{128, 2, 1}, 1, time.Second)
	_, re, _ = up.VerifyLocked("493017", s)
	require.True(t, re, "weaker params must request a rehash")
	s2, _ := nw.Hash(context.Background(), "493017")
	ok, re, _ = nw.VerifyLocked("493017", s2)
	require.True(t, ok)
	require.False(t, re)
}

func TestMalformedHashes(t *testing.T) {
	h := newH(t, 1, time.Second)
	for _, s := range []string{"", "x", "$argon2id$v=19$m=64,t=1,p=1$AAAA$BBBB$pv=1", "$argon2i$v=19$m=64,t=1,p=1$AAAAAAAAAAAAAAAAAAAA$AAAA$pv=1", "$argon2id$v=19$m=99999999999,t=1,p=1$AA$AA$pv=1"} {
		_, _, err := h.VerifyLocked("493017", s)
		require.Error(t, err)
	}
}

func TestSemaphoreBoundsConcurrencyAndReturnsBusy(t *testing.T) {
	h := newH(t, 4, 5*time.Millisecond)
	var busy, done atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := h.Acquire(context.Background())
			if err != nil {
				busy.Add(1)
				return
			}
			defer rel()
			time.Sleep(20 * time.Millisecond)
			done.Add(1)
		}()
	}
	wg.Wait()
	require.LessOrEqual(t, h.MaxInflight(), int64(4))
	require.Greater(t, busy.Load(), int64(0), "excess callers must be refused")
	require.Equal(t, int64(200), busy.Load()+done.Load())
}

func TestDummyAlwaysFalseAndCosts(t *testing.T) {
	h := newH(t, 1, time.Second)
	before := h.Evaluations()
	h.DummyLocked()
	require.Equal(t, before+1, h.Evaluations())
}

func TestShortPepperRejected(t *testing.T) {
	_, err := NewHasher(map[int16][]byte{1: []byte("short")}, 1, fast, 1, time.Second)
	require.Error(t, err)
}

func BenchmarkHashDemoParams(b *testing.B) { benchHash(b, Params{19456, 2, 1}) }
func BenchmarkHashProdParams(b *testing.B) { benchHash(b, Params{65536, 3, 1}) }

func benchHash(b *testing.B, p Params) {
	h, _ := NewHasher(map[int16][]byte{1: pepper('a')}, 1, p, 1, time.Second)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.HashLocked("493017")
	}
}
