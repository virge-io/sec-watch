package registry

import (
	"strconv"
	"strings"
)

// versionGTE returns true if version a >= b using dot-separated numeric comparison.
// Strips pre-release suffixes (anything non-numeric after digits/dots).
func versionGTE(a, b string) bool {
	aParts := splitVersion(a)
	bParts := splitVersion(b)

	// Pad shorter slice with zeros.
	for len(aParts) < len(bParts) {
		aParts = append(aParts, 0)
	}
	for len(bParts) < len(aParts) {
		bParts = append(bParts, 0)
	}

	for i := range aParts {
		if aParts[i] > bParts[i] {
			return true
		}
		if aParts[i] < bParts[i] {
			return false
		}
	}
	return true // equal
}

// splitVersion parses a version string into numeric components.
// It stops at the first component that cannot be parsed as an integer
// (e.g., "1.2.3a4" → [1, 2, 3]).
func splitVersion(v string) []int {
	// Strip leading non-version characters (e.g., ">=1.2" → "1.2")
	v = strings.TrimLeft(v, "^~>=<! ")

	// Take the part before any pre-release marker (-, +, a, b, rc etc.)
	// We do this by only keeping dot-and-digit characters from the start.
	var clean strings.Builder
	for _, ch := range v {
		if ch == '.' || (ch >= '0' && ch <= '9') {
			clean.WriteRune(ch)
		} else {
			break
		}
	}
	v = clean.String()
	v = strings.Trim(v, ".")

	if v == "" {
		return []int{0}
	}

	rawParts := strings.Split(v, ".")
	parts := make([]int, 0, len(rawParts))
	for _, p := range rawParts {
		if p == "" {
			parts = append(parts, 0)
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		parts = append(parts, n)
	}
	if len(parts) == 0 {
		return []int{0}
	}
	return parts
}
