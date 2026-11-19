package version

import (
	"strconv"
	"strings"
)

// Compare orders two semantic versions (semver.org precedence). Build metadata after "+" is ignored and a leading "v"
// is allowed. It returns -1, 0 or 1 and ok=true, or ok=false when either string is not a valid semver.
func Compare(a, b string) (cmp int, ok bool) {
	pa, oka := parse(a)
	pb, okb := parse(b)
	if !oka || !okb {
		return 0, false
	}
	for i := 0; i < 3; i++ {
		if pa.num[i] != pb.num[i] {
			if pa.num[i] < pb.num[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return comparePre(pa.pre, pb.pre), true
}

type semver struct {
	num [3]uint64
	pre []string
}

func parse(s string) (semver, bool) {
	var v semver
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre := s[i+1:]
		s = s[:i]
		if pre == "" {
			return v, false
		}
		v.pre = strings.Split(pre, ".")
		for _, id := range v.pre {
			if id == "" || !identOK(id) || (isNum(id) && len(id) > 1 && id[0] == '0') {
				return v, false
			}
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		if !isNum(p) || (len(p) > 1 && p[0] == '0') {
			return v, false
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return v, false
		}
		v.num[i] = n
	}
	return v, true
}

func isNum(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func identOK(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-') {
			return false
		}
	}
	return true
}

// comparePre: a version without a pre-release is greater than one with it; otherwise identifiers compare left to right,
// numeric ones numerically and below alphanumeric ones, and a shorter list is lower when all else is equal.
func comparePre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		nx, ny := isNum(x), isNum(y)
		switch {
		case nx && ny:
			ix, _ := strconv.ParseUint(x, 10, 64)
			iy, _ := strconv.ParseUint(y, 10, 64)
			if ix != iy {
				if ix < iy {
					return -1
				}
				return 1
			}
		case nx:
			return -1
		case ny:
			return 1
		case x != y:
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// BuildOrder is how the build metadata of a target version compares with the current one when the two versions have the
// same semver precedence.
type BuildOrder string

const (
	BuildNewer     BuildOrder = "newer"
	BuildOlder     BuildOrder = "older"
	BuildSame      BuildOrder = "same"
	BuildUnordered BuildOrder = "unordered"
)

// build returns the text after the first "+" ("" when there is none).
func build(v string) string {
	if i := strings.IndexByte(v, '+'); i >= 0 {
		return v[i+1:]
	}
	return ""
}

func isStamp(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// CompareBuild orders the "+build" part of target against cur. It is meant for versions of equal precedence (Compare
// returned 0): release.sh stamps builds as +YYYYMMDDHHMM (UTC), so two 12-digit stamps are ordered numerically. Two
// versions without build metadata count as the same build. Anything else (one side without a stamp, a stamp that is not 12
// digits) is unordered, and callers treat that like a downgrade. The shared vectors are docs/protocol/testdata/version-compare.json.
func CompareBuild(cur, target string) BuildOrder {
	a, b := build(cur), build(target)
	switch {
	case a == "" && b == "":
		return BuildSame
	case isStamp(a) && isStamp(b):
		switch {
		case b > a:
			return BuildNewer
		case b < a:
			return BuildOlder
		}
		return BuildSame
	}
	return BuildUnordered
}
