package version

import "testing"

func TestCompare(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"0.3.1", "0.3.1", 0},
		{"0.3.1+202611181227", "0.3.1", 0}, // build metadata ignored
		{"0.3.1+202611181227", "0.3.1+202701010000", 0},
		{"0.3.0+999", "0.3.1", -1},
		{"0.4.0", "0.3.9", 1},
		{"1.0.0", "0.99.99", 1},
		{"0.10.0", "0.9.0", 1}, // numeric, not lexical
		{"v0.3.1", "0.3.1", 0},
		{"0.1.0-dev", "0.1.0", -1},
		{"0.1.0", "0.1.0-dev", 1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
	} {
		got, ok := Compare(tc.a, tc.b)
		if !ok || got != tc.want {
			t.Errorf("Compare(%q,%q) = %d,%v want %d", tc.a, tc.b, got, ok, tc.want)
		}
		if back, _ := Compare(tc.b, tc.a); back != -tc.want {
			t.Errorf("not antisymmetric for %q %q", tc.a, tc.b)
		}
	}
	for _, bad := range []string{"", "1", "1.2", "1.2.3.4", "a.b.c", "01.2.3", "1.2.3-", "1.2.x", "latest"} {
		if _, ok := Compare(bad, "1.0.0"); ok {
			t.Errorf("%q should be invalid", bad)
		}
	}
}
