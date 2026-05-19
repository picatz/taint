package main

import (
	"path/filepath"
	"strconv"
	"strings"
)

// AnalyzerJSON mirrors the structure produced by analysis singlechecker
// when invoked with the -json flag: { pkgPath: { analyzerName: [{posn, message}] } }.
type AnalyzerJSON map[string]map[string][]AnalyzerDiagnosticJSON

// AnalyzerDiagnosticJSON is one element of the singlechecker -json output.
type AnalyzerDiagnosticJSON struct {
	Posn    string `json:"posn"`
	Message string `json:"message"`
}

// Normalize converts raw analyzer JSON output into a deterministic
// AnalyzerResult keyed by analyzer name, with file paths rebased relative
// to the target root. Diagnostics that fall outside the target root are
// dropped because they refer to stdlib or module-cache files and are not
// stable across machines.
//
// Findings are deduplicated by (file, line, column, message): when an
// analyzer is invoked over `./...`, go/packages reports both the regular
// package and its test-augmented variant, so the same callsite shows up
// twice. From the user's perspective the duplicate is just noise.
func Normalize(rawByAnalyzer map[string][]AnalyzerDiagnosticJSON, root string) map[string]AnalyzerResult {
	out := make(map[string]AnalyzerResult, len(rawByAnalyzer))
	for name, diags := range rawByAnalyzer {
		res := AnalyzerResult{}
		seen := map[string]struct{}{}
		for _, d := range diags {
			f, ok := normalizeFinding(d, root)
			if !ok {
				continue
			}
			key := findingKey(f)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			res.Findings = append(res.Findings, f)
		}
		res.Count = len(res.Findings)
		out[name] = res
	}
	return out
}

// MergeAnalyzerJSON flattens a multi-package singlechecker JSON document into
// a map of analyzer name → diagnostics across all packages.
func MergeAnalyzerJSON(doc AnalyzerJSON) map[string][]AnalyzerDiagnosticJSON {
	merged := map[string][]AnalyzerDiagnosticJSON{}
	for _, byAnalyzer := range doc {
		for name, diags := range byAnalyzer {
			merged[name] = append(merged[name], diags...)
		}
	}
	return merged
}

// normalizeFinding parses a `posn` field of the form "/abs/path:line:col" and
// rebases the file path relative to root. The boolean return is false when the
// finding refers to a file outside the target tree.
func normalizeFinding(d AnalyzerDiagnosticJSON, root string) (Finding, bool) {
	path, line, col := splitPosn(d.Posn)
	if path == "" {
		return Finding{}, false
	}
	rel, ok := relativeToRoot(path, root)
	if !ok {
		return Finding{}, false
	}
	return Finding{
		File:    rel,
		Line:    line,
		Column:  col,
		Message: d.Message,
	}, true
}

// splitPosn parses a "file:line:col" position string. Missing line or column
// values default to 0. An empty input returns ("", 0, 0).
func splitPosn(posn string) (path string, line, col int) {
	if posn == "" {
		return "", 0, 0
	}
	parts := strings.Split(posn, ":")
	// On Windows the path may itself contain ":", so peel components off the
	// right rather than splitting from the left.
	if len(parts) >= 3 {
		col = atoiSafe(parts[len(parts)-1])
		line = atoiSafe(parts[len(parts)-2])
		path = strings.Join(parts[:len(parts)-2], ":")
	} else if len(parts) == 2 {
		line = atoiSafe(parts[1])
		path = parts[0]
	} else {
		path = parts[0]
	}
	return path, line, col
}

func atoiSafe(s string) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return 0
}

// relativeToRoot returns p expressed as a forward-slash path relative to
// root. If p is not inside root the boolean return is false.
func relativeToRoot(p, root string) (string, bool) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	absPath, err := filepath.Abs(p)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return "", false
	}
	if strings.HasPrefix(rel, "..") {
		return "", false
	}
	return filepath.ToSlash(rel), true
}
