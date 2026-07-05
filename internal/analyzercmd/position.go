package analyzercmd

import (
	"strconv"
	"strings"
)

// SplitPosition parses a token.Position string ("file:line:col", "file:line",
// or "file") into its parts. It peels trailing numeric fields off the right,
// so a Windows drive letter ("C:\path\file.go:12:5") is not mistaken for a
// field separator, and a non-numeric trailing field stays part of the path
// ("C:\path\file.go" has no line at all).
func SplitPosition(pos string) (path string, line, col int) {
	path = pos
	if rest, n, ok := trimTrailingNumber(path); ok {
		col = n
		path = rest
		if rest, n, ok := trimTrailingNumber(path); ok {
			// Two trailing numbers: the leftward one is the line, and the
			// first-peeled one keeps its place as the column.
			line = n
			path = rest
		} else {
			// One trailing number: it is the line, and there is no column.
			line, col = col, 0
		}
	}
	return path, line, col
}

// trimTrailingNumber splits a trailing ":<number>" off s, returning the
// remainder and the parsed number. It reports false when s has no such suffix.
func trimTrailingNumber(s string) (rest string, n int, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 || i == len(s)-1 {
		return s, 0, false
	}
	num, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return s, 0, false
	}
	return s[:i], num, true
}
