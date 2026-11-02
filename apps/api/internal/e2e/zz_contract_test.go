package e2e

import (
	"flag"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/require"

	"github.com/cryptoapp/api/internal/apigen"
)

// Statuses declared in the contract that cannot be produced by a black-box test of a healthy server, with the reason.
var coverageAllowlist = map[string]string{
	"demologin 503":        "SERVICE_UNAVAILABLE needs an unreachable store mid-request; the fail-closed path is exercised through healthz 503 and TestHealthzFailsClosedWhenStoreUnavailable",
	"verifypin 503":        "same as demologin 503",
	"registerdevice 429":   "device registration has no dedicated limiter (the global per-IP limit applies); the 429 envelope is covered on other operations",
	"listdevices 429":      "only the global per-IP limit applies; the 429 envelope is covered on other operations",
	"revokedevice 429":     "same as listdevices 429",
	"setpin 429":           "hashing saturation returns 429 (TestSec5b_*) but via verifyPin; setPin shares the same code path (Hasher.Acquire)",
	"resetpin 429":         "per-user PIN-change limiter covered via changePin; reset shares the limiter",
	"biometricdisable 429": "only the global per-IP limit applies",
	"getdashboard 429":     "only the global per-IP limit applies",
}

var allowlistedCodes = map[string]string{
	"SERVICE_UNAVAILABLE": "covered by healthz 503",
}

func TestZContractCoverage(t *testing.T) {
	if f := flag.Lookup("test.run"); f != nil && f.Value.String() != "" && f.Value.String() != "." {
		t.Skip("coverage needs the whole e2e suite (run without -run, or with -run .)")
	}
	doc, err := apigen.GetSpec()
	require.NoError(t, err)
	covMu.Lock()
	defer covMu.Unlock()
	var missing []string
	for _, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			for status := range op.Responses.Map() {
				if status == "default" {
					continue // DefaultError: every non-listed status is validated against it by the transport
				}
				key := strings.ToLower(op.OperationID) + " " + status
				if cov[key] {
					continue
				}
				if _, ok := coverageAllowlist[key]; ok {
					continue
				}
				missing = append(missing, key)
			}
		}
	}
	sort.Strings(missing)
	require.Empty(t, missing, "contract (operation, status) pairs never produced by any test")

	var codes []string
	for _, c := range doc.Components.Schemas["ErrorCode"].Value.Enum {
		code := c.(string)
		if !covCodes[code] {
			if _, ok := allowlistedCodes[code]; !ok {
				codes = append(codes, code)
			}
		}
	}
	require.Empty(t, codes, "ErrorCode values never exercised")
}

// (c) no response schema exposes secret-ish property names.
func TestContractNoSecretPropertiesInResponseSchemas(t *testing.T) {
	doc, err := apigen.GetSpec()
	require.NoError(t, err)
	banned := regexp.MustCompile(`^(pin|pinHash|hash|salt|pepper|privateKey|secret|oldPin|newPin)$`)
	seen := map[*openapi3.Schema]bool{}
	var walk func(path string, s *openapi3.SchemaRef)
	walk = func(path string, ref *openapi3.SchemaRef) {
		if ref == nil || ref.Value == nil || seen[ref.Value] {
			return
		}
		s := ref.Value
		seen[s] = true
		for name, p := range s.Properties {
			require.False(t, banned.MatchString(name), "response schema %s exposes property %q", path, name)
			walk(path+"."+name, p)
		}
		walk(path+"[]", s.Items)
		for _, group := range []openapi3.SchemaRefs{s.AllOf, s.OneOf, s.AnyOf} {
			for _, g := range group {
				walk(path, g)
			}
		}
	}
	for p, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			for status, r := range op.Responses.Map() {
				if r.Value == nil {
					continue
				}
				for _, mt := range r.Value.Content {
					walk(op.OperationID+" "+status+" "+p, mt.Schema)
				}
			}
		}
	}
}

// (d) no operation takes credentials in the path or query string.
func TestContractNoTokensInURLs(t *testing.T) {
	doc, err := apigen.GetSpec()
	require.NoError(t, err)
	re := regexp.MustCompile(`(?i)token|secret|pin|password|key|nonce|signature`)
	for p, item := range doc.Paths.Map() {
		require.False(t, strings.Contains(strings.ToLower(p), "token"), p)
		for _, op := range item.Operations() {
			for _, prm := range append(item.Parameters, op.Parameters...) {
				require.NotEqual(t, "query", prm.Value.In, "%s %s: query parameters are not allowed", op.OperationID, prm.Value.Name)
				if prm.Value.In == "path" {
					require.False(t, re.MatchString(prm.Value.Name), "%s: path parameter %s", op.OperationID, prm.Value.Name)
				}
			}
		}
	}
}

// Every operation requires an Idempotency-Key exactly where D-09 says.
func TestContractIdempotencyOperations(t *testing.T) {
	doc, err := apigen.GetSpec()
	require.NoError(t, err)
	want := map[string]bool{"registerdevice": true, "setpin": true, "changepin": true, "resetpin": true, "biometricenroll": true, "createtransaction": true}
	got := map[string]bool{}
	for _, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			for _, prm := range op.Parameters {
				if prm.Value.Name == "Idempotency-Key" {
					got[strings.ToLower(op.OperationID)] = true
				}
			}
		}
	}
	require.Equal(t, want, got)
	_ = strconv.Itoa
}
