package util

import (
	"strconv"
)

// --- helpers ---------------------------------------------------------------------------------

func Str(args map[string]any, k string) string {
	s, _ := args[k].(string)
	return s
}

func Num(args map[string]any, k string) float64 {
	switch v := args[k].(type) {
	case float64:
		return v
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	}
	return 0
}

func Tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}
