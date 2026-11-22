// Package labfuzz is a lab fixture for devsecops/fuzzing.
// It contains one intentional bug. Do not reuse this code.
package labfuzz

import (
	"errors"
	"strings"
)

// ErrNoSeparator is returned when a line has no "name:" part.
var ErrNoSeparator = errors.New("field: missing ':' separator")

// ParseField splits a "Name: value" line into its name and value.
// One space after the colon is optional and is dropped.
func ParseField(line string) (name, value string, err error) {
	idx := strings.IndexByte(line, ':')
	if idx <= 0 {
		return "", "", ErrNoSeparator
	}
	name = line[:idx]
	rest := line[idx+1:]
	// Intentional bug: rest is empty for a line that ends with the colon,
	// so rest[0] panics with "index out of range".
	if rest[0] == ' ' {
		rest = rest[1:]
	}
	return name, rest, nil
}
