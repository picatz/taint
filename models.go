package taint

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ssa"
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
	// Field, when set alongside Type, restricts the source to a single struct
	// field: only accesses to that field of the type are tainted, not the
	// whole value. For example Type "*example.com/x.Request" with Field "Body"
	// taints req.Body but leaves req.Method clean. Requires Type.
	Field string `yaml:"field,omitempty"`
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
	// Args selects the parameters that are the injection channel. An empty
	// list treats every parameter as a channel. Each entry is an
	// [ArgSelector] — an argument index, a range, or "receiver". See its
	// documentation for the accepted syntax.
	Args []ArgSelector `yaml:"args,omitempty"`
	// Select names a built-in argument selector for channels that positional
	// indices cannot express (for example, "only the URL argument, accounting
	// for a bound method value"). It is mutually exclusive with Args. The
	// available names are reported by [SelectorNames].
	Select string `yaml:"select,omitempty"`
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
	// From selects the parameters that carry taint into the result. An empty
	// list treats every parameter as carrying taint. Each entry is an
	// [ArgSelector].
	From []ArgSelector `yaml:"from,omitempty"`
	// To names the destination of the flow. Only the result is supported
	// ("result", or the CodeQL alias "ReturnValue"); "return" and the empty
	// string are accepted as synonyms.
	To string `yaml:"to,omitempty"`
	// Kind is an optional, informational label.
	Kind string `yaml:"kind,omitempty"`
}

// An ArgSelector identifies one or more parameters of a modeled call: a single
// argument, an inclusive range of arguments, or the receiver. Argument
// positions are zero-based and written as they appear in the source signature,
// excluding the receiver.
//
// In YAML a selector is a scalar in any of these forms:
//
//	0                 # a single argument
//	0..2              # arguments 0, 1, and 2 (inclusive)
//	receiver          # the receiver of a method call
//	Argument[1]       # CodeQL-compatible spelling of "1"
//	Argument[0..2]    # CodeQL-compatible range
//	Argument[receiver]
//
// For portability with CodeQL models-as-data, a trailing field or element
// access (e.g. "Argument[0].Field[pkg.T.f]" or "Argument[0].ArrayElement") is
// accepted but interpreted loosely: this engine is not field-sensitive, so the
// selector resolves to the whole argument rather than a sub-value.
type ArgSelector struct {
	raw      string
	receiver bool
	lo, hi   int // inclusive argument range; used when !receiver
}

// Arg selects the argument at the given zero-based position (receiver excluded).
func Arg(index int) ArgSelector {
	return ArgSelector{raw: strconv.Itoa(index), lo: index, hi: index}
}

// ArgRange selects the inclusive range of arguments [lo, hi].
func ArgRange(lo, hi int) ArgSelector {
	return ArgSelector{raw: fmt.Sprintf("%d..%d", lo, hi), lo: lo, hi: hi}
}

// Receiver selects the receiver of a method call.
func Receiver() ArgSelector { return ArgSelector{raw: "receiver", receiver: true} }

// String returns the selector's canonical textual form.
func (a ArgSelector) String() string {
	switch {
	case a.receiver:
		return "receiver"
	case a.lo == a.hi:
		return strconv.Itoa(a.lo)
	default:
		return fmt.Sprintf("%d..%d", a.lo, a.hi)
	}
}

// UnmarshalYAML implements yaml.Unmarshaler, parsing a scalar selector.
func (a *ArgSelector) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("taint: argument selector must be a scalar, got %q", node.Tag)
	}
	return a.parse(node.Value)
}

// MarshalYAML implements yaml.Marshaler, emitting the canonical form.
func (a ArgSelector) MarshalYAML() (any, error) { return a.String(), nil }

func (a *ArgSelector) parse(s string) error {
	a.raw = s
	body := strings.TrimSpace(s)

	// CodeQL "Argument[...]" spelling, with an optional trailing field or
	// element access after the closing bracket that we accept but ignore.
	if rest, ok := strings.CutPrefix(body, "Argument["); ok {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return fmt.Errorf("taint: invalid argument selector %q: missing ']'", s)
		}
		body = strings.TrimSpace(rest[:end])
	}

	if strings.EqualFold(body, "receiver") {
		a.receiver, a.lo, a.hi = true, 0, 0
		return nil
	}

	lo, hi, err := parseArgRange(body)
	if err != nil {
		return fmt.Errorf("taint: invalid argument selector %q: %w", s, err)
	}
	a.receiver, a.lo, a.hi = false, lo, hi
	return nil
}

func parseArgRange(s string) (lo, hi int, err error) {
	if before, after, ok := strings.Cut(s, ".."); ok {
		lo, err = parseIndex(before)
		if err != nil {
			return 0, 0, err
		}
		hi, err = parseIndex(after)
		if err != nil {
			return 0, 0, err
		}
		if hi < lo {
			return 0, 0, fmt.Errorf("range %q is empty", s)
		}
		return lo, hi, nil
	}
	n, err := parseIndex(s)
	if err != nil {
		return 0, 0, err
	}
	return n, n, nil
}

func parseIndex(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%q is not an argument index", strings.TrimSpace(s))
	}
	if n < 0 {
		return 0, fmt.Errorf("argument index %d is negative", n)
	}
	return n, nil
}

// resolve appends the SSA values the selector names to out, given the call's
// receiver-excluded parameters and its receiver (which may be nil).
func (a ArgSelector) resolve(params []ssa.Value, receiver ssa.Value, out []ssa.Value) []ssa.Value {
	if a.receiver {
		if receiver != nil {
			out = append(out, receiver)
		}
		return out
	}
	for i := a.lo; i <= a.hi; i++ {
		if i >= 0 && i < len(params) {
			out = append(out, params[i])
		}
	}
	return out
}

// resolveSelectors resolves a list of selectors to SSA values. An empty list
// selects every parameter, preserving the "no args means all args" default.
func resolveSelectors(sels []ArgSelector, params []ssa.Value, receiver ssa.Value) []ssa.Value {
	if len(sels) == 0 {
		return params
	}
	out := make([]ssa.Value, 0, len(sels))
	for _, s := range sels {
		out = s.resolve(params, receiver, out)
	}
	return out
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
		if s.Field != "" && s.Type == "" {
			return fmt.Errorf("taint: model %q source #%d sets 'field' without 'type'", m.Package, i)
		}
	}
	for i, s := range m.Sinks {
		if s.Method == "" {
			return fmt.Errorf("taint: model %q sink #%d is missing 'method'", m.Package, i)
		}
		if s.Select != "" {
			if len(s.Args) > 0 {
				return fmt.Errorf("taint: model %q sink %q sets both 'select' and 'args'", m.Package, s.Method)
			}
			if !isKnownSelector(s.Select) {
				return fmt.Errorf("taint: model %q sink %q has unknown 'select: %s' (known: %s)",
					m.Package, s.Method, s.Select, strings.Join(SelectorNames(), ", "))
			}
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
		if !isResultDestination(s.To) {
			return fmt.Errorf("taint: model %q summary %q has unsupported 'to: %s' (only 'result' is supported)", m.Package, s.Func, s.To)
		}
	}
	return nil
}

// isResultDestination reports whether a summary's To field names the result.
// Only the result is supported; "return", "result", "ReturnValue", and the
// empty string are accepted as synonyms.
func isResultDestination(to string) bool {
	switch strings.ToLower(strings.TrimSpace(to)) {
	case "", "return", "result", "returnvalue":
		return true
	default:
		return false
	}
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
