// Command taint-eval is the precision-evaluation harness for the existing
// sqli, logi, and xss analyzers. It runs each analyzer against pinned local
// fixtures and remote repositories listed in testdata/eval/targets.yaml and
// compares their output against committed JSON snapshots so regressions and
// false-positive drift surface as a diff.
//
// Subcommands:
//
//	list            print configured targets and expected finding counts
//	check           run analyzers and fail on snapshot drift
//	update          rewrite snapshots from a fresh run (review the diff)
//
// Flags shared across subcommands:
//
//	-manifest path  manifest file (default testdata/eval/targets.yaml)
//	-snapshots dir  snapshot directory (default testdata/eval/snapshots)
//	-cache dir      cache root for cloned git targets (default .cache/taint-eval
//	                or $TAINT_EVAL_CACHE)
//	-target sel     run only the named target, or "local" / "git" to filter
//	                by kind (default: all targets)
//	-repo dir       repository root used to locate the analyzer commands
//	                (default: the working directory of taint-eval)
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "taint-eval:", err)
		os.Exit(1)
	}
}

func run(parent context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return fmt.Errorf("missing subcommand")
	}
	sub := args[0]
	rest := args[1:]

	flags := flag.NewFlagSet("taint-eval", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", filepath.Join("testdata", "eval", "targets.yaml"), "manifest file")
	snapshotsDir := flags.String("snapshots", filepath.Join("testdata", "eval", "snapshots"), "snapshot directory")
	cacheOverride := flags.String("cache", "", "cache directory for cloned repos")
	targetSel := flags.String("target", "", "target name, \"local\", or \"git\"")
	repoRoot := flags.String("repo", "", "path to the taint repo root (default: working directory)")
	jobs := flags.Int("jobs", defaultJobs(), "max concurrent target evaluations (default: NumCPU/2 capped at target count)")
	if err := flags.Parse(rest); err != nil {
		return err
	}
	if *repoRoot == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("getwd: %w", err)
		}
		*repoRoot = wd
	}
	manifest, err := LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	targets, err := manifest.SelectTargets(*targetSel)
	if err != nil {
		return err
	}
	manifestDir, err := filepath.Abs(filepath.Dir(*manifestPath))
	if err != nil {
		return fmt.Errorf("resolve manifest dir: %w", err)
	}
	snapshotsAbs, err := filepath.Abs(*snapshotsDir)
	if err != nil {
		return fmt.Errorf("resolve snapshots dir: %w", err)
	}

	ctx, cancel := signal.NotifyContext(parent, os.Interrupt)
	defer cancel()

	switch sub {
	case "list":
		return runList(stdout, snapshotsAbs, targets)
	case "check":
		return runCheck(ctx, stdout, stderr, *repoRoot, *cacheOverride, manifestDir, snapshotsAbs, targets, *jobs)
	case "update":
		return runUpdate(ctx, stdout, stderr, *repoRoot, *cacheOverride, manifestDir, snapshotsAbs, targets, *jobs)
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	}
	printUsage(stderr)
	return fmt.Errorf("unknown subcommand %q", sub)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `usage: taint-eval <subcommand> [flags]

subcommands:
  list      show configured targets and expected counts from snapshots
  check     run analyzers and fail on snapshot drift
  update    rewrite snapshots from a fresh run (review diffs first)

flags:
  -manifest path   manifest file (default testdata/eval/targets.yaml)
  -snapshots dir   snapshot directory (default testdata/eval/snapshots)
  -cache dir       cache root for cloned git targets
  -target sel      target name, "local", or "git"
  -repo dir        path to the taint repo (default: working directory)`)
}

func runList(stdout io.Writer, snapshotsDir string, targets []Target) error {
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tKIND\tSOURCE\tCOMMIT\tANALYZERS\tEXPECTED")
	for _, t := range targets {
		snap, _ := LoadSnapshot(SnapshotPath(snapshotsDir, t.Name))
		expected := formatExpected(snap, t.Analyzers)
		commit := t.Commit
		if len(commit) > 12 {
			commit = commit[:12]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			t.Name,
			t.Kind,
			truncate(targetSource(t), 48),
			commit,
			strings.Join(t.Analyzers, ","),
			expected,
		)
	}
	return tw.Flush()
}

func formatExpected(snap *Snapshot, analyzers []string) string {
	if snap == nil {
		return "no-snapshot"
	}
	names := append([]string(nil), analyzers...)
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		res, ok := snap.Analyzers[name]
		if !ok {
			parts = append(parts, name+"=?")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%d", name, res.Count))
	}
	return strings.Join(parts, " ")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// targetRun is one analyzer run's outcome, paired with its target so the
// caller can emit ordered output even when work happened concurrently.
type targetRun struct {
	target Target
	snap   *Snapshot
	err    error
}

// runTargets executes fn on every target with at most jobs concurrent
// workers. Results are returned in the original target order so output is
// stable regardless of scheduling. The first target failure cancels the
// remaining workers; partial results from completed workers are still
// returned for the caller to surface.
func runTargets(ctx context.Context, targets []Target, jobs int, fn func(context.Context, Target) (*Snapshot, error)) []targetRun {
	if jobs < 1 {
		jobs = 1
	}
	if jobs > len(targets) {
		jobs = len(targets)
	}
	results := make([]targetRun, len(targets))
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t Target) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-subCtx.Done():
				results[i] = targetRun{target: t, err: subCtx.Err()}
				return
			}
			defer func() { <-sem }()
			snap, err := fn(subCtx, t)
			results[i] = targetRun{target: t, snap: snap, err: err}
		}(i, t)
	}
	wg.Wait()
	return results
}

func runCheck(ctx context.Context, stdout, stderr io.Writer, repoRoot, cacheOverride, manifestDir, snapshotsDir string, targets []Target, jobs int) error {
	cacheDir, cmdFor, err := prepareRun(ctx, repoRoot, cacheOverride, targets)
	if err != nil {
		return err
	}
	runs := runTargets(ctx, targets, jobs, func(c context.Context, t Target) (*Snapshot, error) {
		root, err := resolveTargetRoot(c, t, cacheDir, manifestDir)
		if err != nil {
			return nil, err
		}
		return RunTarget(c, t, root, cmdFor)
	})
	driftFound := false
	missingSnapshots := 0
	var firstErr error
	for _, r := range runs {
		if r.err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("target %q: %w", r.target.Name, r.err)
			}
			fmt.Fprintf(stdout, "%s: ERROR %v\n", r.target.Name, r.err)
			continue
		}
		expected, err := LoadSnapshot(SnapshotPath(snapshotsDir, r.target.Name))
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			missingSnapshots++
			fmt.Fprintf(stdout, "%s: NO SNAPSHOT (run `taint-eval update -target %s` after review)\n", r.target.Name, r.target.Name)
			fmt.Fprint(stdout, formatActual(r.snap))
			continue
		}
		diffs := DiffSnapshots(r.target.Name, expected, r.snap)
		if len(diffs) == 0 {
			fmt.Fprintf(stdout, "%s: OK\n", r.target.Name)
			continue
		}
		driftFound = true
		fmt.Fprintf(stdout, "%s: DRIFT\n", r.target.Name)
		fmt.Fprint(stdout, FormatDiffs(diffs))
	}
	if firstErr != nil {
		return firstErr
	}
	if driftFound {
		return fmt.Errorf("snapshot drift detected")
	}
	if missingSnapshots > 0 {
		return fmt.Errorf("%d target(s) have no snapshot", missingSnapshots)
	}
	return nil
}

func runUpdate(ctx context.Context, stdout, stderr io.Writer, repoRoot, cacheOverride, manifestDir, snapshotsDir string, targets []Target, jobs int) error {
	cacheDir, cmdFor, err := prepareRun(ctx, repoRoot, cacheOverride, targets)
	if err != nil {
		return err
	}
	runs := runTargets(ctx, targets, jobs, func(c context.Context, t Target) (*Snapshot, error) {
		root, err := resolveTargetRoot(c, t, cacheDir, manifestDir)
		if err != nil {
			return nil, err
		}
		return RunTarget(c, t, root, cmdFor)
	})
	for _, r := range runs {
		if r.err != nil {
			fmt.Fprintf(stdout, "%s: ERROR %v\n", r.target.Name, r.err)
			return fmt.Errorf("target %q: %w", r.target.Name, r.err)
		}
		path := SnapshotPath(snapshotsDir, r.target.Name)
		if err := WriteSnapshot(path, r.snap); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s: wrote %s\n", r.target.Name, mustRel(snapshotsDir, path))
	}
	return nil
}

// defaultJobs returns a sensible default concurrency. Analyzer subprocesses
// are CPU-bound and load a lot of packages into memory, so over-subscribing
// hurts more than it helps; half the cores is a good rule of thumb.
func defaultJobs() int {
	n := runtime.NumCPU() / 2
	if n < 1 {
		return 1
	}
	return n
}

func prepareRun(ctx context.Context, repoRoot, cacheOverride string, targets []Target) (CacheDir, analyzerCommand, error) {
	cacheDir, err := ResolveCacheDir(cacheOverride)
	if err != nil {
		return "", nil, err
	}
	cmdFor, err := buildAnalyzerBinaries(ctx, cacheDir, repoRoot)
	if err != nil {
		return "", nil, err
	}
	return cacheDir, cmdFor, nil
}

func resolveTargetRoot(ctx context.Context, t Target, cacheDir CacheDir, manifestDir string) (string, error) {
	switch t.Kind {
	case KindLocal:
		return ResolveLocalPath(manifestDir, t.Path), nil
	case KindGit:
		return cacheDir.EnsureGitTarget(ctx, t)
	}
	return "", fmt.Errorf("target %q: unsupported kind %q", t.Name, t.Kind)
}

func formatActual(s *Snapshot) string {
	if s == nil {
		return ""
	}
	var b strings.Builder
	names := make([]string, 0, len(s.Analyzers))
	for name := range s.Analyzers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		res := s.Analyzers[name]
		fmt.Fprintf(&b, "  %s: %d finding(s)\n", name, res.Count)
		for _, f := range res.Findings {
			fmt.Fprintf(&b, "    %s:%d:%d %s\n", f.File, f.Line, f.Column, f.Message)
		}
	}
	return b.String()
}

func mustRel(base, p string) string {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return p
	}
	return rel
}
