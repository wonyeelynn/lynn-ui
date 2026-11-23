package main

import (
	"reflect"
	"testing"
)

func TestReorderArgs(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		// Flags after the positional (the documented order) must still work.
		{[]string{"https://example.com/sub", "--rules", "embedded"}, []string{"--rules", "embedded", "https://example.com/sub"}},
		{[]string{"./sub.txt", "--out", "clash.yaml"}, []string{"--out", "clash.yaml", "./sub.txt"}},
		// Flags before the positional keep working.
		{[]string{"--rules", "embedded", "https://example.com/sub"}, []string{"--rules", "embedded", "https://example.com/sub"}},
		// "=" form is not split.
		{[]string{"https://example.com/sub", "--rules=embedded"}, []string{"--rules=embedded", "https://example.com/sub"}},
		// "-" (stdin) stays a positional.
		{[]string{"-", "--rules", "embedded"}, []string{"--rules", "embedded", "-"}},
		// Bool flags take no value.
		{[]string{"https://example.com/sub", "--hy2-skip-verify=false"}, []string{"--hy2-skip-verify=false", "https://example.com/sub"}},
		// No flags at all.
		{[]string{"https://example.com/sub"}, []string{"https://example.com/sub"}},
	}
	for _, c := range cases {
		if got := reorderArgs(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("reorderArgs(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
