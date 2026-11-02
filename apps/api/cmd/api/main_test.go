package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func setEnv(t *testing.T, over map[string]string) {
	base := map[string]string{
		"ENV": "dev", "DEMO_MODE": "true", "DATABASE_URL": "postgres://u:p@127.0.0.1:1/x?sslmode=disable&connect_timeout=1",
		"PEPPER": strings.Repeat("P", 40), "ACCESS_SIGNING_KEY": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"DEMO_SECRETS": "alice=alice-secret-value1",
	}
	for k, v := range over {
		base[k] = v
	}
	for k, v := range base {
		t.Setenv(k, v)
	}
}

// spec s7 test 14: the process refuses to start (non-zero exit code) on every fail-closed condition.
func TestStartupFailsClosed(t *testing.T) {
	for name, over := range map[string]map[string]string{
		"missing pepper":       {"PEPPER": ""},
		"demo mode in prod":    {"ENV": "prod", "DEMO_MODE": "true", "DATABASE_URL": "postgres://u:p@h/x?sslmode=require", "ARGON2_MEMORY_KIB": "65536", "ARGON2_TIME": "3"},
		"missing signing key":  {"ACCESS_SIGNING_KEY": ""},
		"demo secrets missing": {"DEMO_SECRETS": ""},
		"database unreachable": {},
		"missing database url": {"DATABASE_URL": ""},
	} {
		setEnv(t, over)
		require.Equal(t, 1, run(), name)
	}
}
