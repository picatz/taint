package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/picatz/taint/vulncheck"
	"github.com/picatz/taint/vulndb"
)

// builtinCommandVuln scans a module for known vulnerabilities from the Go
// vulnerability database, ranking each by exposure tier. It is self-contained:
// it loads and analyzes the target directory fresh rather than reusing the
// shell's loaded graph, so it works before any load and always reflects the
// path given.
var builtinCommandVuln = &command{
	name: "vuln",
	desc: "scan a module for known vulnerabilities, ranked by taint exposure",
	args: []*commandArg{
		{
			name:     "path",
			desc:     "the module directory to scan (default: current directory)",
			optional: true,
		},
	},
	flags: []*commandFlag{
		{name: "min", desc: "minimum tier: module, package, symbol, or taint"},
		{name: "db", desc: "database URL or local directory (default: https://vuln.go.dev)"},
	},
	fn: func(ctx context.Context, bt *bufio.Writer, args []string, flags map[string]string) error {
		dir := "."
		if len(args) > 0 {
			dir = args[0]
		}

		if _, ok := parseVulnTier(flags["min"]); !ok {
			bt.WriteString(styleWarning.Render(fmt.Sprintf("✗ invalid --min tier %q (want module, package, symbol, or taint)", flags["min"])) + "\n")
			bt.Flush()
			return nil
		}

		src, err := vulnSource(flags["db"])
		if err != nil {
			bt.WriteString(styleWarning.Render("✗ "+err.Error()) + "\n")
			bt.Flush()
			return nil
		}

		bt.WriteString(styleInfo.Render("• loading and analyzing "+dir+"…") + "\n")
		bt.Flush()

		target, err := vulncheck.Load(ctx, vulncheck.LoadConfig{Dir: dir})
		if err != nil {
			bt.WriteString(styleWarning.Render("✗ "+err.Error()) + "\n")
			bt.Flush()
			return nil
		}

		res, err := vulncheck.Scan(ctx, target, src)
		if err != nil {
			bt.WriteString(styleWarning.Render("✗ "+err.Error()) + "\n")
			bt.Flush()
			return nil
		}

		res = filterVulnTier(res, flags["min"])
		writeVulnReport(bt, res)
		bt.Flush()
		return nil
	},
}

// vulnSource resolves the -db flag to a database source, defaulting to the
// cached live endpoint.
func vulnSource(db string) (vulndb.Source, error) {
	if db == "" {
		src, err := vulndb.NewHTTPSource(vulndb.DefaultBaseURL, nil)
		if err != nil {
			return nil, err
		}
		return vulndb.NewCachedSource(src, vulndb.CacheConfig{}), nil
	}
	if !strings.HasPrefix(db, "http://") && !strings.HasPrefix(db, "https://") {
		return vulndb.NewFSSource(os.DirFS(db)), nil
	}
	src, err := vulndb.NewHTTPSource(db, nil)
	if err != nil {
		return nil, err
	}
	return vulndb.NewCachedSource(src, vulndb.CacheConfig{}), nil
}

// writeVulnReport renders findings into the shell buffer with the shell's
// color styles, most-exposed first.
func writeVulnReport(bt *bufio.Writer, res *vulncheck.Result) {
	if len(res.Findings) == 0 {
		bt.WriteString(styleSuccess.Render("✓ no known vulnerabilities found") + "\n")
		return
	}
	bt.WriteString(styleHeader.Render(fmt.Sprintf("found %d finding(s)", len(res.Findings))) + "\n")
	for _, f := range res.Findings {
		entry := res.Entries[f.OSV]
		summary := ""
		if entry != nil {
			summary = entry.Summary
		}
		bt.WriteString(styleNumber.Render(f.OSV) + " " +
			styleFlag.Render("["+f.Tier.String()+"]") + " " + summary + "\n")
		line := "  " + styleSubtle.Render("module") + " " + f.Module
		if f.FoundVersion != "" {
			line += " @ " + f.FoundVersion
		}
		if f.FixedVersion != "" {
			line += styleFaint.Render(" → fix " + f.FixedVersion)
		}
		bt.WriteString(line + "\n")
		if f.Symbol != "" {
			bt.WriteString("  " + styleSubtle.Render("symbol") + " " + f.Package + "." + f.Symbol + "\n")
		}
		for _, step := range f.TaintTrace {
			bt.WriteString("    " + styleFaint.Render(step) + "\n")
		}
	}
}

func filterVulnTier(res *vulncheck.Result, min string) *vulncheck.Result {
	threshold, ok := parseVulnTier(min)
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

func parseVulnTier(s string) (vulncheck.Tier, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "module":
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
