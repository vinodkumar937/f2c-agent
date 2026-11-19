package version

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vectorCase struct {
	Name         string
	Cur, Target  string
	TargetSigned bool
	Expect       struct {
		Cmp   *int
		Build *string
	}
}

func loadVectors(t *testing.T) []vectorCase {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "protocol", "testdata", "version-compare.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct{ Cases []vectorCase }
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Cases) != 28 {
		t.Fatalf("the shared vectors have 28 cases, got %d", len(d.Cases))
	}
	return d.Cases
}

// The cmp and build fields of all shared vectors (the decision field is tested in internal/update).
func TestSharedVectorsCompare(t *testing.T) {
	for _, c := range loadVectors(t) {
		if !c.TargetSigned {
			if c.Expect.Cmp != nil {
				t.Errorf("%s: an unsigned target has no cmp", c.Name)
			}
			continue
		}
		cmp, ok := Compare(c.Target, c.Cur)
		if c.Expect.Cmp == nil {
			if ok {
				t.Errorf("%s: want unparseable, got %d", c.Name, cmp)
			}
			continue
		}
		if !ok || cmp != *c.Expect.Cmp {
			t.Errorf("%s: Compare = %d (%v), want %d", c.Name, cmp, ok, *c.Expect.Cmp)
			continue
		}
		if cmp == 0 {
			if c.Expect.Build == nil || string(CompareBuild(c.Cur, c.Target)) != *c.Expect.Build {
				t.Errorf("%s: CompareBuild = %s, want %v", c.Name, CompareBuild(c.Cur, c.Target), c.Expect.Build)
			}
		} else if c.Expect.Build != nil {
			t.Errorf("%s: build only applies at equal precedence", c.Name)
		}
	}
}

func TestCompareBuildBasics(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want BuildOrder
	}{
		{"1.0.0", "1.0.0", BuildSame},
		{"1.0.0+202611190800", "1.0.0+202611190800", BuildSame},
		{"1.0.0+202611190800", "1.0.0+202611190801", BuildNewer},
		{"1.0.0+202611190801", "1.0.0+202611190800", BuildOlder},
		{"1.0.0", "1.0.0+202611190800", BuildUnordered},
		{"1.0.0+20261119080", "1.0.0+202611190800", BuildUnordered}, // 11 digits
		{"1.0.0+abc", "1.0.0+abc", BuildUnordered},
		{"1.0.0+2026111908xx", "1.0.0+202611190800", BuildUnordered},
	} {
		if got := CompareBuild(c.a, c.b); got != c.want {
			t.Errorf("CompareBuild(%q,%q) = %s, want %s", c.a, c.b, got, c.want)
		}
	}
}
