package taint

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"gopkg.in/yaml.v3"
)

// A Model is a declarative, data-driven description of the taint-relevant
// behavior of a single Go package: which values and calls introduce tainted
// data (sources), which call arguments must not receive it (sinks), which
// calls neutralize it (sanitizers), and which calls carry taint from their
// arguments to their result (summaries).
//
// Models let callers extend the engine's built-in knowledge without changing
// code. They are written as YAML — one package per YAML document, separated by
// "---" — and compiled into the same internal rules the built-in detectors
// use. Load them with [ParseModels] or [LoadModels] and apply them with
// [WithModels]:
//
//	models, err := taint.LoadModels(os.DirFS("models"))
//	diags := taint.CheckDetailed(cg, srcs, sinks, taint.WithModels(models...))
//
// Identifiers (types, funcs, methods) are the fully-qualified strings the
// engine matches against, e.g. "*net/http.Request", "os/exec.Command", or
// "(*database/sql.DB).Query".
type Model struct {
	// Package is the import path the model describes. Matching is by the
	// fully-qualified identifiers in the rules below; Package documents
	// intent and lets the CLIs gate analysis on whether the target imports
	// it.
	Package string `yaml:"package"`

	Sources    []SourceModel    `yaml:"sources,omitempty"`
	Sinks      []SinkModel      `yaml:"sinks,omitempty"`
	Sanitizers []SanitizerModel `yaml:"sanitizers,omitempty"`
	Summaries  []SummaryModel   `yaml:"summaries,omitempty"`
}

// SourceModel marks values or call results as tainted. Exactly one of Type or
// Call must be set.
type SourceModel struct {
	// Type is a fully-qualified type whose values are tainted, e.g.
	// "*net/http.Request".
	Type string `yaml:"type,omitempty"`
	// Call is a fully-qualified function or method whose return value is
	// tainted, e.g. "example.com/x.UserInput".
	Call string `yaml:"call,omitempty"`
	// Kind is an optional, informational label (e.g. "remote").
	Kind string `yaml:"kind,omitempty"`
}

// SinkModel marks a call's arguments as a place tainted data must not reach.
type SinkModel struct {
	// Method is the fully-qualified function or method that is the sink,
	// e.g. "(*database/sql.DB).Query" or "os/exec.Command".
	Method string `yaml:"method"`
	// Args lists the zero-based parameter positions — as written in the
	// source signature, excluding the receiver — that are the injection
	// channel. An empty list treats every parameter as a channel.
	Args []int `yaml:"args,omitempty"`
	// Kind is an optional, informational label (e.g. "sql-injection").
	Kind string `yaml:"kind,omitempty"`
}

// SanitizerModel marks a call that neutralizes taint: when a sink argument is
// the result of this call, the flow is considered safe.
type SanitizerModel struct {
	// Func is the fully-qualified sanitizing function or method, e.g.
	// "html.EscapeString".
	Func string `yaml:"func"`
	// Kind is an optional, informational label.
	Kind string `yaml:"kind,omitempty"`
}

// SummaryModel describes taint flow through a call without analyzing its body
// (a propagator): if any argument named in From is tainted, the call's result
// is tainted.
type SummaryModel struct {
	// Func is the fully-qualified function or method, e.g. "strings.Join".
	Func string `yaml:"func"`
	// From lists the zero-based parameter positions — excluding the receiver —
	// that carry taint into the result. An empty list treats every parameter
	// as carrying taint.
	From []int `yaml:"from,omitempty"`
	// To names the destination of the flow. Only "return" is supported, which
	// is also the default when empty.
	To string `yaml:"to,omitempty"`
	// Kind is an optional, informational label.
	Kind string `yaml:"kind,omitempty"`
}

// ParseModels decodes zero or more [Model] values from YAML. Each YAML document
// (a section separated by "---") describes one package. Every model is
// validated; the first problem found is returned as an error and no models are
// returned.
func ParseModels(r io.Reader) ([]Model, error) {
	dec := yaml.NewDecoder(r)
	var models []Model
	for {
		var m Model
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("taint: decoding model: %w", err)
		}
		if m.isZero() {
			// A blank document (e.g. a trailing "---") is not an error.
			continue
		}
		if err := m.validate(); err != nil {
			return nil, err
		}
		models = append(models, m)
	}
	return models, nil
}

// LoadModels reads and parses every model file in fsys matching the given glob
// patterns. When no patterns are given it uses "*.yaml" and "*.yml". Files are
// processed in sorted path order for deterministic rule ordering. Use
// [os.DirFS] to load from a directory on disk.
func LoadModels(fsys fs.FS, patterns ...string) ([]Model, error) {
	if len(patterns) == 0 {
		patterns = []string{"*.yaml", "*.yml"}
	}
	var paths []string
	for _, p := range patterns {
		matches, err := fs.Glob(fsys, p)
		if err != nil {
			return nil, fmt.Errorf("taint: invalid model pattern %q: %w", p, err)
		}
		paths = append(paths, matches...)
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)

	var models []Model
	for _, path := range paths {
		ms, err := loadModelFile(fsys, path)
		if err != nil {
			return nil, err
		}
		models = append(models, ms...)
	}
	return models, nil
}

func loadModelFile(fsys fs.FS, path string) ([]Model, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("taint: opening model %q: %w", path, err)
	}
	defer f.Close()
	ms, err := ParseModels(f)
	if err != nil {
		return nil, fmt.Errorf("taint: %q: %w", path, err)
	}
	return ms, nil
}

func (m Model) isZero() bool {
	return m.Package == "" &&
		len(m.Sources) == 0 &&
		len(m.Sinks) == 0 &&
		len(m.Sanitizers) == 0 &&
		len(m.Summaries) == 0
}

func (m Model) validate() error {
	if m.Package == "" {
		return errors.New("taint: model is missing required 'package'")
	}
	for i, s := range m.Sources {
		if (s.Type == "") == (s.Call == "") {
			return fmt.Errorf("taint: model %q source #%d must set exactly one of 'type' or 'call'", m.Package, i)
		}
	}
	for i, s := range m.Sinks {
		if s.Method == "" {
			return fmt.Errorf("taint: model %q sink #%d is missing 'method'", m.Package, i)
		}
		if err := validateArgs(m.Package, "sink "+s.Method, s.Args); err != nil {
			return err
		}
	}
	for i, s := range m.Sanitizers {
		if s.Func == "" {
			return fmt.Errorf("taint: model %q sanitizer #%d is missing 'func'", m.Package, i)
		}
	}
	for i, s := range m.Summaries {
		if s.Func == "" {
			return fmt.Errorf("taint: model %q summary #%d is missing 'func'", m.Package, i)
		}
		if s.To != "" && s.To != "return" {
			return fmt.Errorf("taint: model %q summary %q has unsupported 'to: %s' (only 'return' is supported)", m.Package, s.Func, s.To)
		}
		if err := validateArgs(m.Package, "summary "+s.Func, s.From); err != nil {
			return err
		}
	}
	return nil
}

func validateArgs(pkg, what string, args []int) error {
	for _, a := range args {
		if a < 0 {
			return fmt.Errorf("taint: model %q %s has negative argument index %d", pkg, what, a)
		}
	}
	return nil
}

// ModelsFromPath loads models from a filesystem path that is either a single
// YAML file or a directory of YAML files (loaded via [LoadModels]). It is a
// convenience for command-line tools; an empty path returns no models and no
// error.
func ModelsFromPath(path string) ([]Model, error) {
	if path == "" {
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("taint: reading models from %q: %w", path, err)
	}
	if info.IsDir() {
		return LoadModels(os.DirFS(path))
	}
	return loadModelFile(os.DirFS(filepath.Dir(path)), filepath.Base(path))
}

// ModelPackages returns the deduplicated, sorted import paths named by the
// given models. Command-line tools use it to keep import-aware gating aware of
// user-supplied packages.
func ModelPackages(models []Model) []string {
	pkgs := make([]string, 0, len(models))
	for _, m := range models {
		if m.Package != "" {
			pkgs = append(pkgs, m.Package)
		}
	}
	slices.Sort(pkgs)
	return slices.Compact(pkgs)
}

// WithModels adds data-driven [Model] values to a check. Models are additive:
// their sources, sinks, sanitizers, and summaries augment the built-in rules
// and the Sources and Sinks passed to [CheckDetailed]; they never replace them.
func WithModels(models ...Model) Option {
	return func(cfg *checkConfig) {
		cfg.models = append(cfg.models, models...)
	}
}
