// Package config loads the server configuration from the environment and FAILS CLOSED (SEC-004, SEC-016, SEC-065).
// Error messages never contain secret values. There are no defaults for any secret.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Argon2 struct {
	MemoryKiB   uint32
	Time        uint32
	Parallelism uint8
	Concurrency int
}

// Limit is a fixed-window rate limit.
type Limit struct {
	N      int
	Window time.Duration
}

// Limits holds the SEC-057 table (decisions.md D-12). Zero N disables a rule (tests only).
type Limits struct {
	DemoLoginIPMin, DemoLoginIPHour, DemoLoginGlobal Limit
	PinVerifyDevice, PinVerifyIP                     Limit
	BioChallengeDevice, BioChallengeIP               Limit
	BioVerifyDevice, BioVerifyIP                     Limit
	RefreshDevice, RefreshIP                         Limit
	StepUpUser                                       Limit
	EnrollUser                                       Limit
	PinChangeUser                                    Limit
	TxUser                                           Limit
	GlobalIP                                         Limit
	DemoBreakerOpenFor                               time.Duration
	DeviceFailMax                                    int
	DeviceFailWindow                                 time.Duration
	DeviceBlockFor                                   time.Duration
}

func DefaultLimits() Limits {
	m, h := time.Minute, time.Hour
	return Limits{
		DemoLoginIPMin: Limit{5, m}, DemoLoginIPHour: Limit{20, h}, DemoLoginGlobal: Limit{100, m},
		PinVerifyDevice: Limit{10, m}, PinVerifyIP: Limit{30, m},
		BioChallengeDevice: Limit{10, m}, BioChallengeIP: Limit{30, m},
		BioVerifyDevice: Limit{10, m}, BioVerifyIP: Limit{30, m},
		RefreshDevice: Limit{6, m}, RefreshIP: Limit{60, m},
		StepUpUser: Limit{10, m}, EnrollUser: Limit{5, h}, PinChangeUser: Limit{5, h}, TxUser: Limit{20, m},
		GlobalIP:           Limit{600, m},
		DemoBreakerOpenFor: time.Minute,
		DeviceFailMax:      10, DeviceFailWindow: 15 * m, DeviceBlockFor: h,
	}
}

type Config struct {
	Env        string // dev | prod
	DemoMode   bool
	ListenAddr string

	DatabaseURL string
	DBMaxConns  int32

	Pepper           []byte
	PepperVersion    int16
	PepperOld        []byte
	PepperOldVersion int16
	SigningSeed      []byte
	DemoSecrets      map[string]string

	Argon2       Argon2
	LockSchedule [5]int // seconds for failures 5..9
	AccessTTL    time.Duration
	UnlockWindow time.Duration
	IdleWindow   time.Duration
	ChallengeTTL time.Duration
	StepUpTTL    time.Duration
	BootstrapTTL time.Duration

	BioOnlyMax         *big.Rat // mock USD
	CoolingOffDuration time.Duration
	CoolingOffMax      *big.Rat
	Prices             map[string]*big.Rat // asset -> mock USD price

	TrustedProxy bool
	AuditChain   bool
	Limits       Limits
}

const redacted = "[redacted]"

// LogValue implements slog.LogValuer: secrets are never printed (also protects %+v via String()).
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("env", c.Env), slog.Bool("demo_mode", c.DemoMode), slog.String("listen", c.ListenAddr),
		slog.String("database_url", redacted), slog.String("pepper", redacted), slog.String("signing_key", redacted),
		slog.String("demo_secrets", redacted),
		slog.Int("argon2_memory_kib", int(c.Argon2.MemoryKiB)), slog.Int("argon2_time", int(c.Argon2.Time)),
	)
}

// String and GoString make fmt verbs (%v, %+v, %#v) print the redacted form only.
func (c *Config) String() string   { return c.LogValue().String() }
func (c *Config) GoString() string { return c.String() }

// Format ensures no fmt verb can dump the struct.
func (c Config) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(c.String())) }

type Getenv func(string) string

// Load reads the configuration. migrateURL is NEVER read here (only cmd/migrate reads DATABASE_MIGRATE_URL).
func Load(get Getenv) (*Config, error) {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	str := func(k, def string) string {
		if v := strings.TrimSpace(get(k)); v != "" {
			return v
		}
		return def
	}
	num := func(k string, def int) int {
		v := strings.TrimSpace(get(k))
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			fail("%s must be a non-negative integer", k)
			return def
		}
		return n
	}
	secs := func(k string, def int) time.Duration { return time.Duration(num(k, def)) * time.Second }
	boolean := func(k string) bool { return strings.EqualFold(strings.TrimSpace(get(k)), "true") }
	rat := func(k, def string) *big.Rat {
		r, ok := new(big.Rat).SetString(str(k, def))
		if !ok || r.Sign() < 0 {
			fail("%s must be a non-negative decimal", k)
			return new(big.Rat)
		}
		return r
	}

	c := &Config{Limits: DefaultLimits()}
	c.Env = str("ENV", "")
	if c.Env != "dev" && c.Env != "prod" {
		fail("ENV must be dev or prod")
	}
	c.DemoMode = boolean("DEMO_MODE")
	if c.Env == "prod" && c.DemoMode {
		fail("DEMO_MODE must not be enabled when ENV=prod")
	}
	c.ListenAddr = str("LISTEN_ADDR", "127.0.0.1:8080")

	c.DatabaseURL = str("DATABASE_URL", "")
	switch {
	case c.DatabaseURL == "":
		fail("DATABASE_URL is required")
	case c.Env == "prod" && (strings.Contains(c.DatabaseURL, "sslmode=disable") || !strings.Contains(c.DatabaseURL, "sslmode=")):
		fail("DATABASE_URL must use TLS when ENV=prod")
	case strings.Contains(c.DatabaseURL, "CHANGE_ME"):
		fail("DATABASE_URL still contains a placeholder")
	}
	c.DBMaxConns = int32(num("DB_MAX_CONNS", 10))
	if c.DBMaxConns < 1 {
		c.DBMaxConns = 10
	}

	// Pepper (SEC-004): >= 32 bytes, from PEPPER_FILE or PEPPER.
	pep := get("PEPPER")
	if f := strings.TrimSpace(get("PEPPER_FILE")); f != "" {
		b, err := os.ReadFile(f) // #nosec G304 -- operator-supplied secret file path
		if err != nil {
			fail("PEPPER_FILE is not readable")
		} else {
			pep = strings.TrimSpace(string(b))
		}
	}
	if len(pep) < 32 || strings.HasPrefix(pep, "CHANGE_ME") {
		fail("PEPPER is missing, too short (< 32 bytes) or a placeholder")
	}
	c.Pepper = []byte(pep)
	pv := num("PEPPER_VERSION", 1)
	if pv < 1 || pv > 32000 {
		fail("PEPPER_VERSION out of range")
	}
	c.PepperVersion = int16(pv)
	if old := get("PEPPER_OLD"); old != "" {
		ov := num("PEPPER_OLD_VERSION", 0)
		if len(old) < 32 || ov < 1 || int16(ov) == c.PepperVersion {
			fail("PEPPER_OLD/PEPPER_OLD_VERSION invalid")
		} else {
			c.PepperOld, c.PepperOldVersion = []byte(old), int16(ov)
		}
	}

	// Access-token signing key (Ed25519 seed, base64).
	key := strings.TrimSpace(get("ACCESS_SIGNING_KEY"))
	if key == "" || strings.HasPrefix(key, "CHANGE_ME") {
		fail("ACCESS_SIGNING_KEY is missing or a placeholder")
	} else if b, err := decodeB64(key); err != nil || len(b) != 32 {
		fail("ACCESS_SIGNING_KEY must be base64 of a 32-byte seed")
	} else {
		c.SigningSeed = b
	}

	// Demo secrets.
	c.DemoSecrets = map[string]string{}
	if c.DemoMode {
		raw := strings.TrimSpace(get("DEMO_SECRETS"))
		if raw == "" {
			fail("DEMO_SECRETS is required when DEMO_MODE=true")
		}
		for _, pair := range strings.Split(raw, ",") {
			u, s, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if !ok || u == "" || len(s) < 12 || strings.HasPrefix(s, "CHANGE_ME") {
				fail("DEMO_SECRETS entries must be username=secret with secret >= 12 chars and not a placeholder")
				break
			}
			c.DemoSecrets[u] = s
		}
	}

	// Argon2 (SEC-003).
	c.Argon2 = Argon2{
		MemoryKiB: uint32(num("ARGON2_MEMORY_KIB", 19456)), Time: uint32(num("ARGON2_TIME", 2)),
		Parallelism: uint8(num("ARGON2_PARALLELISM", 1)), Concurrency: num("ARGON2_CONCURRENCY", 4),
	}
	floorM, floorT := uint32(19456), uint32(2)
	if c.Env == "prod" {
		floorM, floorT = 65536, 3
	}
	if c.Argon2.MemoryKiB < floorM || c.Argon2.Time < floorT || c.Argon2.Parallelism < 1 || c.Argon2.Concurrency < 1 {
		fail("ARGON2 parameters below the minimum for ENV=%s", c.Env)
	}

	// Lock schedule.
	c.LockSchedule = [5]int{30, 60, 300, 900, 3600}
	if v := strings.TrimSpace(get("LOCK_SCHEDULE")); v != "" {
		parts := strings.Split(v, ",")
		if len(parts) != 5 {
			fail("LOCK_SCHEDULE needs 5 comma-separated seconds")
		} else {
			for i, p := range parts {
				n, err := strconv.Atoi(strings.TrimSpace(p))
				if err != nil || n < 1 {
					fail("LOCK_SCHEDULE invalid")
					break
				}
				c.LockSchedule[i] = n
			}
		}
	}
	c.AccessTTL = secs("ACCESS_TTL", 300)
	if c.AccessTTL <= 0 || c.AccessTTL > 600*time.Second {
		fail("ACCESS_TTL must be 1..600 seconds")
	}
	c.UnlockWindow = secs("UNLOCK_WINDOW", 900)
	c.IdleWindow = secs("IDLE_WINDOW", 300)
	c.ChallengeTTL = secs("CHALLENGE_TTL", 60)
	c.StepUpTTL = secs("STEPUP_TOKEN_TTL", 60)
	c.BootstrapTTL = secs("BOOTSTRAP_TTL", 600)
	if c.BootstrapTTL > 600*time.Second || c.StepUpTTL > 60*time.Second || c.ChallengeTTL > 60*time.Second || c.ChallengeTTL <= 0 {
		fail("TTL settings exceed the SEC maximums (bootstrap 600 s, challenge/step-up 60 s)")
	}

	c.BioOnlyMax = rat("BIO_ONLY_MAX", "1000")
	c.CoolingOffMax = rat("COOLING_OFF_MAX", "500")
	c.CoolingOffDuration = secs("COOLING_OFF_DURATION", 86400)
	c.Prices = map[string]*big.Rat{}
	for _, pair := range strings.Split(str("MOCK_PRICES", "BTC=65000,ETH=2500,USDC=1"), ",") {
		a, p, ok := strings.Cut(strings.TrimSpace(pair), "=")
		r, ok2 := new(big.Rat).SetString(p)
		if !ok || !ok2 || r.Sign() <= 0 {
			fail("MOCK_PRICES invalid")
			break
		}
		c.Prices[a] = r
	}
	for _, a := range []string{"BTC", "ETH", "USDC"} {
		if c.Prices[a] == nil {
			fail("MOCK_PRICES must price BTC, ETH and USDC")
			break
		}
	}
	c.TrustedProxy = boolean("TRUSTED_PROXY")
	c.AuditChain = boolean("AUDIT_HASH_CHAIN")

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// Usernames returns the sorted demo usernames.
func (c *Config) Usernames() []string {
	out := make([]string, 0, len(c.DemoSecrets))
	for u := range c.DemoSecrets {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func decodeB64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// copyForTest returns a shallow copy (tests dump a value, not a pointer).
func (c *Config) copyForTest() *Config { cp := *c; return &cp }
