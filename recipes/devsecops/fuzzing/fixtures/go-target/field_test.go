package labfuzz

import (
	"strings"
	"testing"
)

func TestParseField(t *testing.T) {
	name, value, err := ParseField("Host: example.test")
	if err != nil || name != "Host" || value != "example.test" {
		t.Fatalf("got (%q, %q, %v)", name, value, err)
	}
}

// FuzzParseField checks two properties: the parser never panics, and the
// name it returns never contains the separator.
func FuzzParseField(f *testing.F) {
	f.Add("Host: example.test")
	f.Add("X-Trace:abc")
	f.Add("no separator")
	f.Fuzz(func(t *testing.T, line string) {
		name, _, err := ParseField(line)
		if err != nil {
			return
		}
		if strings.ContainsRune(name, ':') {
			t.Fatalf("name %q contains the separator", name)
		}
	})
}
