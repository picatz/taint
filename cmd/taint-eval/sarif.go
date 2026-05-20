package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/picatz/taint/internal/analyzercmd"
)

// WriteSnapshotSARIF writes one SARIF report per analyzer for a target
// snapshot. Reports are named <target>-<analyzer>.sarif.
func WriteSnapshotSARIF(dir, target string, snap *Snapshot) error {
	if snap == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(snap.Analyzers))
	for name := range snap.Analyzers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		res := snap.Analyzers[name]
		findings := make([]analyzercmd.Finding, 0, len(res.Findings))
		for _, f := range res.Findings {
			findings = append(findings, analyzercmd.Finding{
				RuleID:  name,
				URI:     f.File,
				Line:    f.Line,
				Column:  f.Column,
				Message: f.Message,
			})
		}
		log := analyzercmd.SARIFLogFromFindings(name, analyzerDoc(name), findings)
		path := filepath.Join(dir, sanitizeFileComponent(target)+"-"+sanitizeFileComponent(name)+".sarif")
		if err := writeSARIF(path, log); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}

func writeSARIF(path string, log analyzercmd.SARIFLog) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func analyzerDoc(name string) string {
	switch name {
	case "sqli":
		return "finds potential SQL injection issues"
	case "logi":
		return "finds potential log injection issues"
	case "cmdi":
		return "finds potential command injection issues"
	case "xss":
		return "finds potential XSS issues"
	default:
		return name
	}
}

func sanitizeFileComponent(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	if b.Len() == 0 {
		return "report"
	}
	return b.String()
}
