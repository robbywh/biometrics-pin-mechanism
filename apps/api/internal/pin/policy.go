// Package pin implements the PIN policy (SEC-001) and the peppered Argon2id hashing (SEC-003/004/005/005b).
package pin

import (
	_ "embed"
	"errors"
	"regexp"
	"strings"
)

//go:embed common_pins.txt
var commonRaw string

var (
	ErrWeak   = errors.New("pin: weak")
	pinRe     = regexp.MustCompile(`^[0-9]{6}$`)
	commonSet = func() map[string]struct{} {
		m := map[string]struct{}{}
		for _, l := range strings.Split(commonRaw, "\n") {
			l = strings.TrimSpace(l)
			if len(l) == 6 && !strings.HasPrefix(l, "#") {
				m[l] = struct{}{}
			}
		}
		return m
	}()
)

// CommonCount is the size of the embedded blocklist (>= 200 required).
func CommonCount() int { return len(commonSet) }

// Validate applies the format check and then the blocklist. It returns ErrWeak for every rejection (no list leak).
func Validate(p string) error {
	if !pinRe.MatchString(p) {
		return ErrWeak
	}
	d := make([]int, 6)
	for i := 0; i < 6; i++ {
		d[i] = int(p[i] - '0')
	}
	// all same digits
	same := true
	for i := 1; i < 6; i++ {
		if d[i] != d[0] {
			same = false
		}
	}
	if same {
		return ErrWeak
	}
	// ascending / descending runs (step +1 / -1, wrapping 9 -> 0)
	asc, desc := true, true
	for i := 1; i < 6; i++ {
		if d[i] != (d[i-1]+1)%10 {
			asc = false
		}
		if d[i] != (d[i-1]+9)%10 {
			desc = false
		}
	}
	if asc || desc {
		return ErrWeak
	}
	// repeating pairs (ababab) and triples (abcabc)
	if p[0:2] == p[2:4] && p[2:4] == p[4:6] {
		return ErrWeak
	}
	if p[0:3] == p[3:6] {
		return ErrWeak
	}
	// doubled digits (aabbcc) and mirrored halves (abccba)
	if p[0] == p[1] && p[2] == p[3] && p[4] == p[5] {
		return ErrWeak
	}
	if p[0] == p[5] && p[1] == p[4] && p[2] == p[3] {
		return ErrWeak
	}
	if _, bad := commonSet[p]; bad {
		return ErrWeak
	}
	return nil
}
