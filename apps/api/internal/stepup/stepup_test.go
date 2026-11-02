package stepup

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequiredForTx(t *testing.T) {
	cases := []struct {
		name string
		p    Policy
		want string
	}{
		{"small, key ok", Policy{KeyPresent: true}, "either"},
		{"no key", Policy{}, "pin"},
		{"key in cooling-off", Policy{KeyPresent: true, KeyInCoolingOff: true}, "pin"},
		{"over bio-only max", Policy{KeyPresent: true, OverBioMax: true}, "pin"},
		{"unattested key in prod", Policy{KeyPresent: true, AttestationNone: true, Prod: true}, "pin"},
		{"unattested key in dev", Policy{KeyPresent: true, AttestationNone: true}, "either"},
	}
	for _, c := range cases {
		require.Equal(t, c.want, RequiredForTx(c.p), c.name)
	}
}
