// Command vuln scans Go code for known vulnerabilities from the Go
// vulnerability database and ranks each by how strongly the code is exposed:
// from merely depending on a vulnerable module up to attacker-controlled data
// reaching the vulnerable symbol.
//
// It is the taint project's answer to govulncheck: same authoritative data and
// reachability, plus a taint tier that reports whether untrusted input actually
// flows into the vulnerable call, with an evidence trace.
//
// Usage:
//
//	vuln [flags] [packages]
//
// Exit status is 0 when no vulnerabilities are found, 3 when findings are
// reported, and 1 on error, so CI can gate on the exit code.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/picatz/taint/internal/analyzercmd"
	"github.com/picatz/taint/vulncheck"
	"github.com/picatz/taint/vulndb"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// exit codes, following govulncheck's convention so CI gating is portable.
const (
	exitNoFindings = 0
	exitError      = 1
	exitFindings   = 3
)

type options struct {
	dir      string
	format   string
	db       string
	tags     string
	tests    bool
	noCache  bool
	minTier  string
	goVer    string
	patterns []string
}

func run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseFlags(args, stderr)
	if err != nil {
		if err == flag.ErrHelp {
			return exitNoFindings
		}
		fmt.Fprintln(stderr, "vuln:", err)
		return exitError
	}

	// Cancel the scan on interrupt so a slow network fetch responds to Ctrl-C.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	src, err := openDatabase(opts)
	if err != nil {
		fmt.Fprintln(stderr, "vuln:", err)
		return exitError
	}

	fmt.Fprintln(stderr, "vuln: loading packages...")
	target, err := vulncheck.Load(ctx, vulncheck.LoadConfig{
		Dir:        opts.dir,
		Patterns:   opts.patterns,
		Tests:      opts.tests,
		BuildFlags: buildFlags(opts.tags),
		GoVersion:  opts.goVer,
	})
	if err != nil {
		fmt.Fprintln(stderr, "vuln:", err)
		return exitError
	}

	fmt.Fprintln(stderr, "vuln: scanning for vulnerabilities...")
	res, err := vulncheck.Scan(ctx, target, src)
	if err != nil {
		fmt.Fprintln(stderr, "vuln:", err)
		return exitError
	}

	res = filterByTier(res, opts.minTier)

	if err := writeReport(stdout, res, opts.format); err != nil {
		fmt.Fprintln(stderr, "vuln:", err)
		return exitError
	}

	if len(res.Findings) > 0 {
		return exitFindings
	}
	return exitNoFindings
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	fs := flag.NewFlagSet("vuln", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
	}

	var opts options
	fs.StringVar(&opts.dir, "C", "", "change to `dir` before scanning")
	fs.StringVar(&opts.format, "format", "text", "output `format`: text, json, or sarif")
	fs.StringVar(&opts.db, "db", vulndb.DefaultBaseURL, "vulnerability database: an https URL or a local directory `path`")
	fs.StringVar(&opts.tags, "tags", "", "comma-separated list of build tags")
	fs.BoolVar(&opts.tests, "test", false, "include test files and packages")
	fs.BoolVar(&opts.noCache, "no-cache", false, "do not cache downloaded advisories on disk")
	fs.StringVar(&opts.minTier, "min", "module", "report findings at or above this `tier`: module, package, symbol, or taint")
	fs.StringVar(&opts.goVer, "go", "", "Go toolchain `version` for stdlib matching (default: the running toolchain)")

	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	opts.patterns = fs.Args()
	return opts, nil
}

// openDatabase resolves the -db flag to a Source: a local directory (an
// unpacked vulndb.zip or a custom mirror) or the HTTP endpoint, wrapped in the
// on-disk cache unless disabled.
func openDatabase(opts options) (vulndb.Source, error) {
	if isLocalPath(opts.db) {
		// Resolve a relative database path against -C, so "-C svc -db ./db"
		// finds svc/db rather than a db under the process working directory.
		dbPath := opts.db
		if opts.dir != "" && !filepath.IsAbs(dbPath) {
			dbPath = filepath.Join(opts.dir, dbPath)
		}
		info, err := os.Stat(dbPath)
		if err != nil {
			return nil, fmt.Errorf("opening database %q: %w", dbPath, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("database path %q is not a directory", dbPath)
		}
		return vulndb.NewFSSource(os.DirFS(dbPath)), nil
	}
	src, err := vulndb.NewHTTPSource(opts.db, nil)
	if err != nil {
		return nil, err
	}
	if opts.noCache {
		return src, nil
	}
	return vulndb.NewCachedSource(src, vulndb.CacheConfig{}), nil
}

func writeReport(w io.Writer, res *vulncheck.Result, format string) error {
	switch format {
	case "", "text":
		return vulncheck.WriteText(w, res)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	case "sarif":
		return writeSARIF(w, res)
	default:
		return fmt.Errorf("unknown format %q (want text, json, or sarif)", format)
	}
}

// writeSARIF renders findings as SARIF 2.1.0, reusing the project's shared
// converter so the output matches the taint detectors' code-scanning uploads.
func writeSARIF(w io.Writer, res *vulncheck.Result) error {
	findings := make([]analyzercmd.Finding, 0, len(res.Findings))
	for _, f := range res.Findings {
		uri, line, col := findingLocation(f)
		findings = append(findings, analyzercmd.Finding{
			RuleID:  f.OSV,
			URI:     uri,
			Line:    line,
			Column:  col,
			Message: sarifMessage(f),
		})
	}
	log := analyzercmd.SARIFLogFromFindings("vuln", "Go vulnerability scanner with taint analysis", findings)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifMessage(f vulncheck.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s", strings.ToUpper(f.Tier.String()), f.OSV)
	if f.Symbol != "" {
		fmt.Fprintf(&b, ": %s", f.Symbol)
	}
	if f.FixedVersion != "" {
		fmt.Fprintf(&b, " (fix: upgrade %s to %s)", f.Module, f.FixedVersion)
	}
	return b.String()
}

// findingLocation extracts a source location for SARIF from the deepest known
// position in a finding's traces.
func findingLocation(f vulncheck.Finding) (uri string, line, col int) {
	for i := len(f.Trace) - 1; i >= 0; i-- {
		if f.Trace[i].Position != "" {
			return splitPosition(f.Trace[i].Position)
		}
	}
	return "", 0, 0
}

// splitPosition parses a token.Position string ("file:line:col", "file:line",
// or "file") into its parts. It scans from the right so a Windows drive letter
// ("C:\path\file.go:12:5") is not mistaken for a field separator: the trailing
// numeric fields are peeled off first, and whatever remains is the path.
func splitPosition(pos string) (path string, line, col int) {
	path = pos
	if rest, n, ok := trimTrailingNumber(path); ok {
		col = n
		path = rest
		if rest, n, ok := trimTrailingNumber(path); ok {
			line = col
			col = n
			path = rest
		} else {
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

func filterByTier(res *vulncheck.Result, min string) *vulncheck.Result {
	threshold, ok := parseTier(min)
	if !ok || threshold == vulncheck.TierModule {
		return res
	}
	kept := res.Findings[:0:0]
	for _, f := range res.Findings {
		if f.Tier >= threshold {
			kept = append(kept, f)
		}
	}
	res.Findings = kept
	return res
}

func parseTier(s string) (vulncheck.Tier, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "module", "":
		return vulncheck.TierModule, true
	case "package":
		return vulncheck.TierPackage, true
	case "symbol":
		return vulncheck.TierSymbol, true
	case "taint":
		return vulncheck.TierTaint, true
	default:
		return 0, false
	}
}

func isLocalPath(db string) bool {
	return !strings.HasPrefix(db, "http://") && !strings.HasPrefix(db, "https://")
}

func buildFlags(tags string) []string {
	if strings.TrimSpace(tags) == "" {
		return nil
	}
	return []string{"-tags=" + tags}
}

const usage = `vuln scans Go code for known vulnerabilities and ranks each by exposure.

Usage:
	vuln [flags] [packages]

Findings are ranked by tier, most exposed first:
	taint    attacker-controlled data reaches the vulnerable symbol
	symbol   a vulnerable symbol is reachable from your code
	package  your build imports a vulnerable package
	module   your build depends on a vulnerable module version

Flags:
	-C dir          change to dir before scanning
	-format fmt     output format: text (default), json, or sarif
	-db path/url    vulnerability database (default https://vuln.go.dev);
	                may be a local directory (an unpacked vulndb.zip)
	-min tier       report findings at or above tier (default module)
	-tags tags      comma-separated build tags
	-test           include test files and packages
	-go version     Go toolchain version for stdlib matching
	-no-cache       do not cache downloaded advisories on disk

Exit status is 0 with no findings, 3 with findings, and 1 on error.

Examples:
	vuln ./...
	vuln -min symbol -C ./service ./...
	vuln -format sarif ./... > vuln.sarif
`
