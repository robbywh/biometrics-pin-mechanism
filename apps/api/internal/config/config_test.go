package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func env(over map[string]string) Getenv {
	m := map[string]string{
		"ENV": "dev", "DEMO_MODE": "true", "DATABASE_URL": "postgres://u:dbpass-secret@127.0.0.1:5432/x?sslmode=disable",
		"PEPPER": strings.Repeat("P", 40), "ACCESS_SIGNING_KEY": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"DEMO_SECRETS": "alice=alice-secret-value1,bob=bob-secret-value222",
	}
	for k, v := range over {
		if v == "-" {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return func(k string) string { return m[k] }
}

func TestLoadOK(t *testing.T) {
	c, err := Load(env(nil))
	require.NoError(t, err)
	require.Equal(t, []string{"alice", "bob"}, c.Usernames())
	require.Equal(t, [5]int{30, 60, 300, 900, 3600}, c.LockSchedule)
	require.EqualValues(t, 19456, c.Argon2.MemoryKiB)
}

// spec s7 test 14: fail closed.
func TestFailClosed(t *testing.T) {
	for name, over := range map[string]map[string]string{
		"missing pepper":         {"PEPPER": "-"},
		"short pepper":           {"PEPPER": "short"},
		"placeholder pepper":     {"PEPPER": "CHANGE_ME_AT_LEAST_32_BYTES_BASE64_PADDING"},
		"missing signing key":    {"ACCESS_SIGNING_KEY": "-"},
		"bad signing key":        {"ACCESS_SIGNING_KEY": "dG9vc2hvcnQ="},
		"placeholder key":        {"ACCESS_SIGNING_KEY": "CHANGE_ME_BASE64"},
		"demo secrets missing":   {"DEMO_SECRETS": "-"},
		"weak demo secret":       {"DEMO_SECRETS": "alice=short"},
		"placeholder demo":       {"DEMO_SECRETS": "alice=CHANGE_ME_ALICE_SECRET"},
		"prod with demo mode":    {"ENV": "prod", "DEMO_MODE": "true", "DATABASE_URL": "postgres://u:p@h/x?sslmode=require", "ARGON2_MEMORY_KIB": "65536", "ARGON2_TIME": "3"},
		"missing env":            {"ENV": "-"},
		"bogus env":              {"ENV": "staging"},
		"missing database url":   {"DATABASE_URL": "-"},
		"prod sslmode disable":   {"ENV": "prod", "DEMO_MODE": "false", "DATABASE_URL": "postgres://u:p@h/x?sslmode=disable", "ARGON2_MEMORY_KIB": "65536", "ARGON2_TIME": "3"},
		"prod without sslmode":   {"ENV": "prod", "DEMO_MODE": "false", "DATABASE_URL": "postgres://u:p@h/x", "ARGON2_MEMORY_KIB": "65536", "ARGON2_TIME": "3"},
		"argon2 below floor":     {"ARGON2_MEMORY_KIB": "1024"},
		"prod argon2 demo floor": {"ENV": "prod", "DEMO_MODE": "false", "DATABASE_URL": "postgres://u:p@h/x?sslmode=require"},
		"access ttl too long":    {"ACCESS_TTL": "3600"},
		"bootstrap ttl too long": {"BOOTSTRAP_TTL": "6000"},
	} {
		c, err := Load(env(over))
		require.Error(t, err, name)
		require.Nil(t, c, name)
		for _, secret := range []string{"dbpass-secret", strings.Repeat("P", 40), "alice-secret-value1", "bob-secret-value222"} {
			require.NotContains(t, err.Error(), secret, name+": error text must not carry secrets")
		}
	}
}

func TestProdProfileAccepted(t *testing.T) {
	_, err := Load(env(map[string]string{"ENV": "prod", "DEMO_MODE": "false", "DEMO_SECRETS": "-", "DATABASE_URL": "postgres://u:p@h/x?sslmode=require", "ARGON2_MEMORY_KIB": "65536", "ARGON2_TIME": "3"}))
	require.NoError(t, err)
}

// Config dump redaction: %v, %+v, %#v and slog never reveal a secret.
func TestConfigDumpRedaction(t *testing.T) {
	c, err := Load(env(nil))
	require.NoError(t, err)
	secrets := []string{"dbpass-secret", strings.Repeat("P", 40), "alice-secret-value1", "bob-secret-value222", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}
	for _, out := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprintf("%s", c), fmt.Sprint(*c.copyForTest())} {
		for _, s := range secrets {
			require.NotContains(t, out, s)
		}
	}
	var b bytes.Buffer
	slog.New(slog.NewJSONHandler(&b, nil)).Info("cfg", "config", c)
	for _, s := range secrets {
		require.NotContains(t, b.String(), s)
	}
	require.Contains(t, b.String(), "[redacted]")
}

// There is no default for any secret in code: an empty environment never yields a usable config.
func TestNoSecretDefaults(t *testing.T) {
	_, err := Load(func(string) string { return "" })
	require.Error(t, err)
	for _, k := range []string{"PEPPER", "ACCESS_SIGNING_KEY", "DATABASE_URL", "ENV"} {
		require.Contains(t, err.Error(), k)
	}
}

func TestDefaultLimitsMatchSEC057(t *testing.T) {
	l := DefaultLimits()
	require.Equal(t, 5, l.DemoLoginIPMin.N)
	require.Equal(t, 20, l.DemoLoginIPHour.N)
	require.Equal(t, 10, l.PinVerifyDevice.N)
	require.Equal(t, 30, l.PinVerifyIP.N)
	require.Equal(t, 10, l.BioChallengeDevice.N)
	require.Equal(t, 30, l.BioVerifyIP.N)
	require.Equal(t, 6, l.RefreshDevice.N)
	require.Equal(t, 10, l.StepUpUser.N)
	require.Equal(t, 5, l.EnrollUser.N)
	require.Equal(t, 5, l.PinChangeUser.N)
	require.Equal(t, 20, l.TxUser.N)
	require.Equal(t, 10, l.DeviceFailMax)
}

func TestPepperFromFile(t *testing.T) {
	f := t.TempDir() + "/pepper"
	require.NoError(t, os.WriteFile(f, []byte(strings.Repeat("F", 40)+"\n"), 0o600))
	c, err := Load(env(map[string]string{"PEPPER": "-", "PEPPER_FILE": f}))
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("F", 40), string(c.Pepper))
	_, err = Load(env(map[string]string{"PEPPER": "-", "PEPPER_FILE": f + ".missing"}))
	require.Error(t, err)
	require.NotContains(t, err.Error(), f, "paths are not echoed either")
}
