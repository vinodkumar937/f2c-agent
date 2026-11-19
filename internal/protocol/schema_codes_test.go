package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The code lists in the spec (schema and section 5.1 table) and in the code must be the same lists.
func TestCodeListsMatchSpec(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "protocol", "schemas", "common.json"))
	if err != nil {
		t.Skip("spec not in this checkout")
	}
	var c struct {
		Defs map[string]struct {
			Enum []string `json:"enum"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	want := append(append([]string{}, V1Codes...), KeptV1Codes...)
	if !reflect.DeepEqual(c.Defs["resultCodeV1"].Enum, want) {
		t.Fatalf("resultCodeV1 differs from V1Codes+KeptV1Codes:\n%v\n%v", c.Defs["resultCodeV1"].Enum, want)
	}
	var legacy []string
	for k := range LegacyCodes {
		legacy = append(legacy, k)
	}
	sort.Strings(legacy)
	got := append([]string{}, c.Defs["resultCodeLegacy"].Enum...)
	sort.Strings(got)
	if !reflect.DeepEqual(got, legacy) {
		t.Fatalf("resultCodeLegacy differs from LegacyCodes: %v vs %v", got, legacy)
	}
	md, err := os.ReadFile(filepath.Join("..", "..", "docs", "protocol.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range want {
		if !strings.Contains(string(md), "| `"+code+"` |") {
			t.Errorf("code %s has no row in docs/protocol.md section 5.1", code)
		}
	}
}
