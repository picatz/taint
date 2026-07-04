package taint

import (
	"bytes"
	_ "embed"
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

const defaultMaxSummaryDepth = 8

// Option configures CheckDetailed. Options are additive and never mutate the
// Sources or Sinks values passed by the caller.
type Option func(*checkConfig)

type checkConfig struct {
	extraSources    []string
	extraSinks      []string
	sanitizers      []string
	models          []Model
	maxSummaryDepth int
}

func defaultCheckConfig() checkConfig {
	return checkConfig{maxSummaryDepth: defaultMaxSummaryDepth}
}

// WithExtraSources adds source matchers for this check without modifying the
// Sources value passed to CheckDetailed.
func WithExtraSources(sourceTypes ...string) Option {
	return func(cfg *checkConfig) {
		cfg.extraSources = append(cfg.extraSources, sourceTypes...)
	}
}

// WithExtraSinks adds sink matchers for this check without modifying the Sinks
// value passed to CheckDetailed.
func WithExtraSinks(sinkTypes ...string) Option {
	return func(cfg *checkConfig) {
		cfg.extraSinks = append(cfg.extraSinks, sinkTypes...)
	}
}

// WithSanitizers adds value-specific sanitizer calls. A sanitizer only suppresses
// taint when the value passed to the sink is the sanitizer result, possibly
// wrapped by SSA conversions or interface changes.
func WithSanitizers(functions ...string) Option {
	return func(cfg *checkConfig) {
		cfg.sanitizers = append(cfg.sanitizers, functions...)
	}
}

// WithMaxSummaryDepth sets the maximum number of nested return-value summaries
// the engine will inspect when following calls without explicit callgraph
// edges. Non-positive values use the default depth.
func WithMaxSummaryDepth(depth int) Option {
	return func(cfg *checkConfig) {
		cfg.maxSummaryDepth = depth
	}
}

type sourceRule struct {
	id            string
	matchType     func(types.Type) bool
	matchField    func(baseType types.Type, fieldName string) bool
	matchBaseType func(types.Type) bool
	matchCall     func(*ssa.CallCommon) bool
	matchValue    func(ssa.Value) bool
}

// fieldSourceRule builds a field-sensitive source: only accesses to the named
// struct field of the given type are tainted. It deliberately leaves matchType
// and matchValue nil so the whole value, and its other fields, stay clean.
// matchBaseType lets the walk detect that a base type is field-sensitive and
// therefore avoid tainting one field through a sibling.
func fieldSourceRule(typeID, field string) sourceRule {
	id := typeID + "." + field
	return sourceRule{
		id: id,
		matchField: func(baseType types.Type, fieldName string) bool {
			return fieldName == field && typeStringMatches(baseType, typeID)
		},
		matchBaseType: func(baseType types.Type) bool {
			return typeStringMatches(baseType, typeID)
		},
	}
}

type sinkRule struct {
	id        string
	matchEdge func(*callgraph.Edge) bool
	// selectArgs names the whole-value sink channels. selectFieldArgs, when
	// non-nil, supersedes it and names channels that may carry a struct field
	// constraint (a field-sensitive sink). Exactly one is populated.
	selectArgs      func(*callgraph.Edge) []ssa.Value
	selectFieldArgs func(*callgraph.Edge) []sinkArg
}

type sanitizerRule struct {
	id        string
	matchCall func(*ssa.CallCommon) bool
}

type propagatorRule struct {
	id         string
	matchCall  func(*ssa.CallCommon) bool
	selectArgs func(*ssa.CallCommon) []ssa.Value
}

type ruleRegistry struct {
	sources         Sources
	sinks           Sinks
	sourceRules     []sourceRule
	sinkRules       []sinkRule
	sanitizers      []sanitizerRule
	propagators     []propagatorRule
	maxSummaryDepth int
}

func newRuleRegistry(sources Sources, sinks Sinks, cfg checkConfig) *ruleRegistry {
	mergedSources := cloneStringSet(sources)
	for _, source := range cfg.extraSources {
		mergedSources[source] = struct{}{}
	}
	mergedSinks := cloneStringSet(sinks)
	for _, sink := range cfg.extraSinks {
		mergedSinks[sink] = struct{}{}
	}

	// Fold data-driven models into the string-keyed sets they share with the
	// built-in rules. Model sinks and summaries carry positional argument
	// selection the string sets cannot express, so they are compiled into
	// rules directly below.
	sanitizers := slices.Clone(cfg.sanitizers)
	var fieldSources []sourceRule
	for _, m := range cfg.models {
		for _, s := range m.Sources {
			switch {
			case s.Type != "" && s.Field != "":
				fieldSources = append(fieldSources, fieldSourceRule(s.Type, s.Field))
			case s.Type != "":
				mergedSources[s.Type] = struct{}{}
			case s.Call != "":
				mergedSources[s.Call] = struct{}{}
			}
		}
		for _, s := range m.Sanitizers {
			sanitizers = append(sanitizers, s.Func)
		}
	}

	maxSummaryDepth := cfg.maxSummaryDepth
	if maxSummaryDepth <= 0 {
		maxSummaryDepth = defaultMaxSummaryDepth
	}

	registry := &ruleRegistry{
		sources:         Sources(mergedSources),
		sinks:           Sinks(mergedSinks),
		maxSummaryDepth: maxSummaryDepth,
	}
	// Iterate maps in deterministic order so the resulting rule slices have a
	// stable order. Downstream traversal records the first rule that matches
	// a given callsite; without sorting, two runs over the same program can
	// record different SinkType values for the same finding when more than
	// one rule could plausibly match.
	for _, source := range sortedKeys(mergedSources) {
		registry.sourceRules = append(registry.sourceRules, exactSourceRule(source))
	}
	registry.sourceRules = append(registry.sourceRules, fieldSources...)
	for _, sink := range sortedKeys(mergedSinks) {
		registry.sinkRules = append(registry.sinkRules, exactSinkRule(sink))
	}
	for _, sanitizer := range sanitizers {
		registry.sanitizers = append(registry.sanitizers, exactSanitizerRule(sanitizer))
	}

	// Model sinks and summaries are appended after the built-in rules so
	// existing behavior is unchanged when no models are supplied. Cloning
	// defaultPropagators avoids mutating the shared package-level slice.
	registry.propagators = defaultPropagators
	for _, m := range cfg.models {
		for _, sk := range m.Sinks {
			registry.sinkRules = append(registry.sinkRules, modelSinkRule(sk))
		}
		if len(m.Summaries) > 0 {
			registry.propagators = slices.Clip(registry.propagators)
			for _, sm := range m.Summaries {
				registry.propagators = append(registry.propagators, modelPropagatorRule(sm))
			}
		}
	}
	return registry
}

// modelSinkRule compiles a SinkModel into a sinkRule. Args are logical
// parameter positions (receiver excluded); an empty Args list selects every
// argument, matching defaultSinkArguments.
// namedSinkSelectors maps a model sink's `select:` value to a built-in
// argument selector for channels that positional indices cannot express.
// These are reusable from user models as well as the built-in packs.
var namedSinkSelectors = map[string]func(*callgraph.Edge) []ssa.Value{
	// The first argument, or the shell command string of a `sh -c` form.
	"exec-command": execCommandSinkArguments,
	// The URL argument of an HTTP client POST, accounting for bound method
	// values that omit the receiver from the argument list.
	"http-post-url": httpClientPostURLArgument,
	// The SQL text of a (ctx, sql, ...) method — the argument after the
	// context, skipping bound query parameters.
	"sql-query": sqlContextQueryArgument(0),
	// The SQL text of a Prepare-style (ctx, name, sql) method.
	"sql-prepare": sqlContextQueryArgument(1),
}

// SelectorNames returns the sorted names accepted by a sink model's `select`
// field.
func SelectorNames() []string {
	return slices.Sorted(maps.Keys(namedSinkSelectors))
}

// isKnownSelector reports whether name is a valid sink `select` value.
func isKnownSelector(name string) bool {
	_, ok := namedSinkSelectors[name]
	return ok
}

func modelSinkRule(sk SinkModel) sinkRule {
	id := sk.Method
	var selectArgs func(*callgraph.Edge) []ssa.Value
	var selectFieldArgs func(*callgraph.Edge) []sinkArg
	switch {
	case sk.Select != "":
		selectArgs = namedSinkSelectors[sk.Select]
	case len(sk.Args) > 0 && selectorsHaveField(sk.Args):
		// A field-sensitive selector ("Argument[0].Field[Message]") fires only
		// when that field of the argument is the tainted channel.
		selectors := slices.Clone(sk.Args)
		selectFieldArgs = func(edge *callgraph.Edge) []sinkArg {
			params := defaultSinkArguments(edge)
			return resolveSinkSelectors(selectors, params, sinkReceiver(edge))
		}
	case len(sk.Args) > 0:
		selectors := slices.Clone(sk.Args)
		selectArgs = func(edge *callgraph.Edge) []ssa.Value {
			params := defaultSinkArguments(edge)
			return resolveSelectors(selectors, params, sinkReceiver(edge))
		}
	default:
		// No explicit selection: defer to the built-in selector for this
		// method id, so naming a well-known sink yields its precise channel.
		// exactSinkRule falls back to every argument for methods the engine
		// does not specifically model, preserving the "no args means all
		// args" default for user-defined sinks.
		selectArgs = exactSinkRule(id).selectArgs
	}
	return sinkRule{
		id: id,
		matchEdge: func(edge *callgraph.Edge) bool {
			return edgeCallsSink(edge, id)
		},
		selectArgs:      selectArgs,
		selectFieldArgs: selectFieldArgs,
	}
}

// modelPropagatorRule compiles a SummaryModel into a propagatorRule. From
// selects the parameters (or receiver) that carry taint into the result; an
// empty list selects every argument.
func modelPropagatorRule(sm SummaryModel) propagatorRule {
	id := sm.Func
	selectors := slices.Clone(sm.From)
	return propagatorRule{
		id:        id,
		matchCall: exactCallMatcher(id),
		selectArgs: func(call *ssa.CallCommon) []ssa.Value {
			params, receiver := callParams(call)
			return resolveSelectors(selectors, params, receiver)
		},
	}
}

// sinkReceiver returns the receiver value of a sink call site, or nil when the
// call is not a method. For an interface invoke the receiver rides in
// CallCommon.Value; for an ordinary method call it is the first argument.
func sinkReceiver(edge *callgraph.Edge) ssa.Value {
	if edge == nil || edge.Site == nil {
		return nil
	}
	_, receiver := callParams(edge.Site.Common())
	return receiver
}

// callParams splits a call's arguments into its receiver-excluded parameters
// and its receiver (nil when the call is not a method).
func callParams(call *ssa.CallCommon) (params []ssa.Value, receiver ssa.Value) {
	if call == nil {
		return nil, nil
	}
	if call.IsInvoke() {
		// An interface invoke keeps the receiver in Value; Args holds only the
		// declared parameters.
		return call.Args, call.Value
	}
	params = call.Args
	if sig := call.Signature(); sig != nil && sig.Recv() != nil && len(params) > 0 {
		return params[1:], params[0]
	}
	return params, nil
}

func sortedKeys(set stringSet) []string {
	return slices.Sorted(maps.Keys(set))
}

func cloneStringSet(in stringSet) stringSet {
	out := make(stringSet, len(in))
	maps.Copy(out, in)
	return out
}

// typeStringMatches reports whether t's printed form matches the rule id.
// Alias types (`type Alias = http.Request`) print under the alias name, so
// the comparison is repeated against the alias-free form of the type; this
// keeps rules like "*net/http.Request" matching values typed via an alias.
func typeStringMatches(t types.Type, id string) bool {
	if t == nil {
		return false
	}
	if t.String() == id || types.TypeString(t, nil) == id {
		return true
	}
	if u := unaliasDeep(t); u != t {
		return u.String() == id || types.TypeString(u, nil) == id
	}
	return false
}

// unaliasDeep removes alias sugar from t, including the common pointer-to-alias
// shape (`*Alias`), which types.Unalias alone does not unwrap.
func unaliasDeep(t types.Type) types.Type {
	switch u := types.Unalias(t).(type) {
	case *types.Pointer:
		elem := unaliasDeep(u.Elem())
		if elem != u.Elem() {
			return types.NewPointer(elem)
		}
		return u
	default:
		return u
	}
}

func exactSourceRule(id string) sourceRule {
	return sourceRule{
		id: id,
		matchType: func(t types.Type) bool {
			if t == nil {
				return false
			}
			if typeStringMatches(t, id) {
				return true
			}
			switch id {
			case "google.golang.org/protobuf/proto.Message", "github.com/golang/protobuf/proto.Message":
				return hasProtoMessageMethod(t)
			default:
				return false
			}
		},
		matchCall: func(call *ssa.CallCommon) bool {
			return callString(call) == id
		},
		matchValue: func(v ssa.Value) bool {
			if v == nil {
				return false
			}
			return typeStringMatches(v.Type(), id)
		},
	}
}

func exactSinkRule(id string) sinkRule {
	selectArgs := defaultSinkArguments
	switch id {
	case "os/exec.Command", "os/exec.CommandContext":
		selectArgs = execCommandSinkArguments
	case "os.Open", "os.OpenFile", "os.Create", "os.ReadFile", "os.WriteFile",
		"os.Remove", "os.RemoveAll", "os.Mkdir", "os.MkdirAll",
		"io/ioutil.ReadFile", "io/ioutil.WriteFile", "io/ioutil.ReadDir":
		selectArgs = sinkArgAt(0)
	case "net/http.ServeFile":
		selectArgs = sinkArgAt(2)
	case "net/http.Get", "net/http.Post", "net/http.PostForm", "net/http.Head":
		selectArgs = sinkArgAt(0)
	case "net/http.NewRequest":
		selectArgs = sinkArgAt(1)
	case "net/http.NewRequestWithContext":
		selectArgs = sinkArgAt(2)
	case "(*net/http.Client).Post", "(*net/http.Client).PostForm":
		// Only the URL is the SSRF channel; tainted body, form data, or
		// content type is not. Ordinary method calls include the receiver
		// in Args, while bound method values do not.
		selectArgs = httpClientPostURLArgument
	case "net.Dial", "net.DialTimeout":
		selectArgs = sinkArgAt(1)
	case "(*github.com/jackc/pgx/v5.Conn).Query",
		"(*github.com/jackc/pgx/v5.Conn).QueryRow",
		"(*github.com/jackc/pgx/v5.Conn).Exec",
		"(github.com/jackc/pgx/v5.Tx).Query",
		"(github.com/jackc/pgx/v5.Tx).QueryRow",
		"(github.com/jackc/pgx/v5.Tx).Exec",
		"(*github.com/jackc/pgx/v5/pgxpool.Pool).Query",
		"(*github.com/jackc/pgx/v5/pgxpool.Pool).QueryRow",
		"(*github.com/jackc/pgx/v5/pgxpool.Pool).Exec":
		// pgx methods are (ctx, sql, args...): only the SQL text is the
		// injection channel. Bound parameters after it are safe, so select
		// just the argument following the context.
		selectArgs = sqlContextQueryArgument(0)
	case "(*github.com/jackc/pgx/v5.Conn).Prepare",
		"(github.com/jackc/pgx/v5.Tx).Prepare":
		// Prepare is (ctx, name, sql): the SQL text follows the name.
		selectArgs = sqlContextQueryArgument(1)
	case "(github.com/gogf/gf/v2/database/gdb.DB).Query",
		"(github.com/gogf/gf/v2/database/gdb.DB).Exec",
		"(github.com/gogf/gf/v2/database/gdb.DB).GetAll",
		"(github.com/gogf/gf/v2/database/gdb.DB).GetOne",
		"(github.com/beego/beego/v2/client/orm.DML).RawWithCtx":
		// (ctx, sql, args...): only the SQL text is the injection channel.
		selectArgs = sqlContextQueryArgument(0)
	case "(github.com/gogf/gf/v2/database/gdb.DB).Raw",
		"(github.com/beego/beego/v2/client/orm.DML).Raw":
		// (sql, args...): the SQL text is the first argument. These are
		// interface methods (invoke), so Args has no receiver.
		selectArgs = sinkArgAt(0)
	}
	return sinkRule{
		id: id,
		matchEdge: func(edge *callgraph.Edge) bool {
			return edgeCallsSink(edge, id)
		},
		selectArgs: selectArgs,
	}
}

// sinkArgAt returns a sink-argument selector that picks a single positional
// argument by index from the underlying call. Indices are into the SSA call's
// Args slice (which still contains the receiver for method invocations).
func sinkArgAt(index int) func(*callgraph.Edge) []ssa.Value {
	return func(edge *callgraph.Edge) []ssa.Value {
		if edge == nil || edge.Site == nil {
			return nil
		}
		common := edge.Site.Common()
		if common == nil {
			return nil
		}
		args := common.Args
		if index < 0 || index >= len(args) {
			return nil
		}
		return []ssa.Value{args[index]}
	}
}

// sqlContextQueryArgument selects the SQL-text argument of a driver method
// whose signature is (ctx, sql, ...) — the argument immediately after the
// context. extra shifts the selection for methods like Prepare(ctx, name, sql)
// where the SQL text follows an intermediate argument. Bound parameters
// passed after the SQL text are deliberately excluded: they are query
// parameters, not part of the injectable query string.
func sqlContextQueryArgument(extra int) func(*callgraph.Edge) []ssa.Value {
	return func(edge *callgraph.Edge) []ssa.Value {
		if edge == nil || edge.Site == nil || edge.Site.Common() == nil {
			return nil
		}
		args := edge.Site.Common().Args
		ctxIdx := -1
		for i, a := range args {
			if a != nil && isContextType(a.Type()) {
				ctxIdx = i
				break
			}
		}
		if ctxIdx < 0 {
			return nil
		}
		target := ctxIdx + 1 + extra
		if target < 0 || target >= len(args) {
			return nil
		}
		return []ssa.Value{args[target]}
	}
}

// isContextType reports whether t is context.Context.
func isContextType(t types.Type) bool {
	named, ok := unaliasDeep(t).(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Pkg() != nil &&
		obj.Pkg().Path() == "context" && obj.Name() == "Context"
}

func httpClientPostURLArgument(edge *callgraph.Edge) []ssa.Value {
	if edge == nil || edge.Site == nil {
		return nil
	}
	common := edge.Site.Common()
	if common == nil {
		return nil
	}
	args := common.Args
	urlIndex := 0
	if callHasExplicitReceiverArg(common) {
		urlIndex = 1
	}
	if urlIndex >= len(args) {
		return nil
	}
	return []ssa.Value{args[urlIndex]}
}

func callHasExplicitReceiverArg(common *ssa.CallCommon) bool {
	if common == nil || common.IsInvoke() {
		return false
	}
	sig := common.Signature()
	if sig == nil || sig.Recv() == nil {
		return false
	}
	params := sig.Params()
	paramCount := 0
	if params != nil {
		paramCount = params.Len()
	}
	return len(common.Args) == paramCount+1
}

func exactSanitizerRule(id string) sanitizerRule {
	return sanitizerRule{
		id: id,
		matchCall: func(call *ssa.CallCommon) bool {
			return callString(call) == id
		},
	}
}

// builtinPropagatorsYAML holds the engine's taint-propagation summaries as
// data. Each summary passes taint from the listed arguments to the call's
// result. All entries are package functions, so a receiver-excluded selector
// matches the historical "all call arguments" behavior exactly.
//
//go:embed builtin/propagators.yaml
var builtinPropagatorsYAML []byte

var defaultPropagators = mustLoadBuiltinPropagators()

func mustLoadBuiltinPropagators() []propagatorRule {
	models, err := ParseModels(bytes.NewReader(builtinPropagatorsYAML))
	if err != nil {
		panic(fmt.Errorf("taint: loading built-in propagators: %w", err))
	}
	var rules []propagatorRule
	for _, m := range models {
		for _, s := range m.Summaries {
			rules = append(rules, modelPropagatorRule(s))
		}
	}
	return rules
}

func exactCallMatcher(id string) func(*ssa.CallCommon) bool {
	return func(call *ssa.CallCommon) bool {
		return callString(call) == id
	}
}

type sanitizerBindings map[*ssa.Parameter]ssa.Value

func (r *ruleRegistry) sanitizerForValue(v ssa.Value) (sanitizerRule, bool) {
	type seenKey struct {
		value ssa.Value
		bound ssa.Value
	}
	seen := map[seenKey]struct{}{}
	var visit func(ssa.Value, int, sanitizerBindings) (sanitizerRule, bool)
	visit = func(cur ssa.Value, depth int, bindings sanitizerBindings) (sanitizerRule, bool) {
		if cur == nil {
			return sanitizerRule{}, false
		}
		key := seenKey{value: cur}
		if param, ok := cur.(*ssa.Parameter); ok && bindings != nil {
			key.bound = bindings[param]
		}
		if _, ok := seen[key]; ok {
			return sanitizerRule{}, false
		}
		seen[key] = struct{}{}

		if call, ok := cur.(*ssa.Call); ok {
			if rule, ok := r.sanitizerForCall(&call.Call); ok {
				return rule, true
			}
			return r.callReturnSanitized(&call.Call, -1, depth+1, bindings, visit)
		}
		switch value := cur.(type) {
		case *ssa.Const:
			return sanitizerRule{}, true
		case *ssa.Parameter:
			if bindings != nil {
				if actual := bindings[value]; actual != nil {
					return visit(actual, depth, bindings)
				}
			}
		case *ssa.MakeInterface:
			return visit(value.X, depth, bindings)
		case *ssa.ChangeInterface:
			return visit(value.X, depth, bindings)
		case *ssa.ChangeType:
			return visit(value.X, depth, bindings)
		case *ssa.Convert:
			return visit(value.X, depth, bindings)
		case *ssa.TypeAssert:
			return visit(value.X, depth, bindings)
		case *ssa.UnOp:
			if value.Op == token.MUL {
				if effects, hasStores := reachingValuesForLoad(value); hasStores {
					return allSideEffectValuesSanitized(effects, func(effect sideEffectValue) (sanitizerRule, bool) {
						effectBindings := bindings
						if effect.call != nil && effect.callee != nil {
							effectBindings = sanitizerBindingsForCallEffect(bindings, effect.call, effect.callee)
						}
						return visit(effect.value, depth, effectBindings)
					})
				}
				if rule, ok := allStoredValuesSanitized(value.X, func(v ssa.Value) (sanitizerRule, bool) {
					return visit(v, depth, bindings)
				}); ok {
					return rule, true
				}
			}
			return visit(value.X, depth, bindings)
		case *ssa.Alloc:
			return allStoredValuesSanitized(value, func(v ssa.Value) (sanitizerRule, bool) {
				return visit(v, depth, bindings)
			})
		case *ssa.Phi:
			return allValuesSanitized(value.Edges, func(v ssa.Value) (sanitizerRule, bool) {
				return visit(v, depth, bindings)
			})
		case *ssa.Extract:
			if call, ok := value.Tuple.(*ssa.Call); ok {
				return r.callReturnSanitized(&call.Call, value.Index, depth+1, bindings, visit)
			}
			return visit(value.Tuple, depth, bindings)
		}
		return sanitizerRule{}, false
	}
	rule, ok := visit(v, 0, nil)
	return rule, ok && rule.id != ""
}

func (r *ruleRegistry) callReturnSanitized(call *ssa.CallCommon, resultIndex, depth int, bindings sanitizerBindings, visit func(ssa.Value, int, sanitizerBindings) (sanitizerRule, bool)) (sanitizerRule, bool) {
	if call == nil || visit == nil {
		return sanitizerRule{}, false
	}
	maxDepth := r.maxSummaryDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxSummaryDepth
	}
	if depth > maxDepth {
		return sanitizerRule{}, false
	}
	callee := staticCallee(call)
	if callee == nil || len(callee.Blocks) == 0 {
		return sanitizerRule{}, false
	}
	summaryBindings := cloneSanitizerBindings(bindings)
	for i, param := range callee.Params {
		if param == nil {
			continue
		}
		if actual := callArgForParamIndex(call, callee, i); actual != nil {
			summaryBindings[param] = actual
		}
	}
	var matched sanitizerRule
	foundReturn := false
	for _, block := range callee.Blocks {
		for _, instr := range block.Instrs {
			ret, ok := instr.(*ssa.Return)
			if !ok {
				continue
			}
			if resultIndex >= 0 {
				if resultIndex >= len(ret.Results) {
					continue
				}
				rule, ok := visit(ret.Results[resultIndex], depth, summaryBindings)
				if !ok {
					return sanitizerRule{}, false
				}
				if matched.id == "" {
					matched = rule
				}
				foundReturn = true
				continue
			}
			if len(ret.Results) == 0 {
				return sanitizerRule{}, false
			}
			for _, result := range ret.Results {
				rule, ok := visit(result, depth, summaryBindings)
				if !ok {
					return sanitizerRule{}, false
				}
				if matched.id == "" {
					matched = rule
				}
			}
			foundReturn = true
		}
	}
	if !foundReturn {
		return sanitizerRule{}, false
	}
	return matched, matched.id != ""
}

func cloneSanitizerBindings(in sanitizerBindings) sanitizerBindings {
	out := sanitizerBindings{}
	maps.Copy(out, in)
	return out
}

func (r *ruleRegistry) expressionContainsSanitizer(v ssa.Value) (sanitizerRule, bool) {
	return r.expressionContainsSanitizerWithSeen(v, map[ssa.Value]struct{}{})
}

func (r *ruleRegistry) expressionContainsSanitizerWithSeen(v ssa.Value, seen map[ssa.Value]struct{}) (sanitizerRule, bool) {
	if seen == nil {
		seen = map[ssa.Value]struct{}{}
	}
	work := []ssa.Value{v}
	for len(work) > 0 {
		cur := work[len(work)-1]
		work = work[:len(work)-1]
		if cur == nil {
			continue
		}
		if _, ok := seen[cur]; ok {
			continue
		}
		seen[cur] = struct{}{}
		if call, ok := cur.(*ssa.Call); ok {
			if rule, matched := r.sanitizerForCall(&call.Call); matched {
				return rule, true
			}
			if rule, matched := r.callReturnContainsSanitizer(&call.Call, 1, seen); matched {
				return rule, true
			}
		}
		if instr, ok := cur.(ssa.Instruction); ok {
			for _, operand := range instr.Operands(nil) {
				if operand != nil && *operand != nil {
					work = append(work, *operand)
				}
			}
		}
		switch value := cur.(type) {
		case *ssa.MakeInterface:
			work = append(work, value.X)
		case *ssa.ChangeInterface:
			work = append(work, value.X)
		case *ssa.ChangeType:
			work = append(work, value.X)
		case *ssa.Convert:
			work = append(work, value.X)
		case *ssa.TypeAssert:
			work = append(work, value.X)
		case *ssa.UnOp:
			work = append(work, value.X)
			if value.Op == token.MUL {
				if stored, ok := storedValuesForLoad(value); ok {
					work = append(work, stored...)
				}
			}
		case *ssa.Alloc:
			work = append(work, storedValuesFor(value)...)
		case *ssa.Phi:
			work = append(work, value.Edges...)
		case *ssa.Extract:
			work = append(work, value.Tuple)
		case *ssa.BinOp:
			work = append(work, value.X, value.Y)
		case *ssa.Slice:
			work = append(work, value.X)
		case *ssa.FieldAddr:
			work = append(work, value.X)
		case *ssa.IndexAddr:
			work = append(work, value.X, value.Index)
		case *ssa.Lookup:
			work = append(work, value.X, value.Index)
		}
	}
	return sanitizerRule{}, false
}

func (r *ruleRegistry) callReturnContainsSanitizer(call *ssa.CallCommon, depth int, seen map[ssa.Value]struct{}) (sanitizerRule, bool) {
	if call == nil {
		return sanitizerRule{}, false
	}
	maxDepth := r.maxSummaryDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxSummaryDepth
	}
	if depth > maxDepth {
		return sanitizerRule{}, false
	}
	callee := staticCallee(call)
	if callee == nil || len(callee.Blocks) == 0 {
		return sanitizerRule{}, false
	}
	for _, block := range callee.Blocks {
		for _, instr := range block.Instrs {
			ret, ok := instr.(*ssa.Return)
			if !ok {
				continue
			}
			for _, result := range ret.Results {
				if rule, matched := r.expressionContainsSanitizerWithSeen(result, seen); matched {
					return rule, true
				}
			}
		}
	}
	return sanitizerRule{}, false
}

func allStoredValuesSanitized(addr ssa.Value, visit func(ssa.Value) (sanitizerRule, bool)) (sanitizerRule, bool) {
	return allValuesSanitized(storedValuesFor(addr), visit)
}

func allSideEffectValuesSanitized(values []sideEffectValue, visit func(sideEffectValue) (sanitizerRule, bool)) (sanitizerRule, bool) {
	if len(values) == 0 {
		return sanitizerRule{}, false
	}
	var matched sanitizerRule
	for _, value := range values {
		rule, ok := visit(value)
		if !ok {
			return sanitizerRule{}, false
		}
		if matched.id == "" {
			matched = rule
		}
	}
	return matched, true
}

func allValuesSanitized(values []ssa.Value, visit func(ssa.Value) (sanitizerRule, bool)) (sanitizerRule, bool) {
	if len(values) == 0 {
		return sanitizerRule{}, false
	}
	var matched sanitizerRule
	for _, value := range values {
		rule, ok := visit(value)
		if !ok {
			return sanitizerRule{}, false
		}
		if matched.id == "" {
			matched = rule
		}
	}
	return matched, true
}

func sanitizerBindingsForCallEffect(bindings sanitizerBindings, call *ssa.Call, callee *ssa.Function) sanitizerBindings {
	out := cloneSanitizerBindings(bindings)
	if call == nil || callee == nil {
		return out
	}
	for i, param := range callee.Params {
		if param == nil {
			continue
		}
		if actual := callArgForParamIndex(&call.Call, callee, i); actual != nil {
			out[param] = actual
		}
	}
	return out
}

func storedValuesFor(addr ssa.Value) []ssa.Value {
	if addr == nil {
		return nil
	}
	var out []ssa.Value
	if refs := addr.Referrers(); refs != nil {
		for _, ref := range *refs {
			store, ok := ref.(*ssa.Store)
			if !ok || store.Addr != addr || store.Val == nil {
				continue
			}
			out = append(out, store.Val)
		}
	}
	return out
}

func (r *ruleRegistry) sanitizerForCall(call *ssa.CallCommon) (sanitizerRule, bool) {
	for _, rule := range r.sanitizers {
		if rule.matchCall != nil && rule.matchCall(call) {
			return rule, true
		}
	}
	return sanitizerRule{}, false
}

func defaultSinkArguments(edge *callgraph.Edge) []ssa.Value {
	if edge == nil || edge.Site == nil || edge.Site.Common() == nil {
		return nil
	}
	common := edge.Site.Common()
	args := common.Args
	if sig := common.Signature(); !common.IsInvoke() && sig != nil && sig.Recv() != nil && len(args) > 0 {
		args = args[1:]
	}
	return args
}

func execCommandSinkArguments(edge *callgraph.Edge) []ssa.Value {
	if edge == nil || edge.Site == nil || edge.Site.Common() == nil {
		return nil
	}
	args := edge.Site.Common().Args
	nameIndex := 0
	if edgeCallsSink(edge, "os/exec.CommandContext") {
		nameIndex = 1
	}
	if nameIndex >= len(args) {
		return nil
	}

	selected := []ssa.Value{args[nameIndex]}
	if command := shellCommandStringArg(args, nameIndex, edge.Site); command != nil {
		selected = append(selected, command)
	}
	return selected
}

func shellCommandStringArg(args []ssa.Value, nameIndex int, use ssa.Instruction) ssa.Value {
	shell, ok := stringConstant(args[nameIndex])
	if !ok || !isShellExecutable(shell) {
		return nil
	}
	flagValue := execCommandVariadicArg(args, nameIndex, 0, use)
	commandValue := execCommandVariadicArg(args, nameIndex, 1, use)
	if flagValue == nil || commandValue == nil {
		return nil
	}
	flag, ok := stringConstant(flagValue)
	if !ok || !isShellCommandFlag(shell, flag) {
		return nil
	}
	return commandValue
}

func execCommandVariadicArg(args []ssa.Value, nameIndex, offset int, use ssa.Instruction) ssa.Value {
	variadicIndex := nameIndex + 1
	if variadicIndex < len(args) && isStringSlice(args[variadicIndex].Type()) {
		return sliceElementAt(args[variadicIndex], offset, use)
	}
	directIndex := variadicIndex + offset
	if directIndex >= 0 && directIndex < len(args) {
		return args[directIndex]
	}
	return nil
}

func isStringSlice(t types.Type) bool {
	if t == nil {
		return false
	}
	slice, ok := t.Underlying().(*types.Slice)
	if !ok {
		return false
	}
	elem, ok := slice.Elem().Underlying().(*types.Basic)
	return ok && elem.Kind() == types.String
}

func sliceElementAt(v ssa.Value, index int, use ssa.Instruction) ssa.Value {
	type visitKey struct {
		value ssa.Value
		index int
	}
	seen := map[visitKey]struct{}{}
	var visit func(ssa.Value, int) ssa.Value
	visit = func(cur ssa.Value, curIndex int) ssa.Value {
		if cur == nil || curIndex < 0 {
			return nil
		}
		key := visitKey{value: cur, index: curIndex}
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}
		if store := latestSliceElementStore(cur, curIndex, use); store != nil {
			return store.Val
		}
		switch value := cur.(type) {
		case *ssa.Slice:
			low := 0
			if value.Low != nil {
				var ok bool
				low, ok = intConstant(value.Low)
				if !ok {
					return nil
				}
			}
			return visit(value.X, curIndex+low)
		case *ssa.ChangeInterface:
			return visit(value.X, curIndex)
		case *ssa.ChangeType:
			return visit(value.X, curIndex)
		case *ssa.Convert:
			return visit(value.X, curIndex)
		case *ssa.MakeInterface:
			return visit(value.X, curIndex)
		case *ssa.UnOp:
			if value.Op != token.MUL {
				return nil
			}
			stored, ok := storedValuesForLoad(value)
			if !ok || len(stored) != 1 {
				return nil
			}
			return visit(stored[0], curIndex)
		case *ssa.Alloc:
			return storedArrayElement(value, curIndex, use)
		}
		return nil
	}
	return visit(v, index)
}

func storedArrayElement(array ssa.Value, index int, use ssa.Instruction) ssa.Value {
	if store := latestSliceElementStore(array, index, use); store != nil {
		return store.Val
	}
	return nil
}

func latestSliceElementStore(v ssa.Value, index int, use ssa.Instruction) *ssa.Store {
	stores := collectSliceElementStores(v, index, use, map[ssa.Value]struct{}{})
	if len(stores) == 0 {
		return nil
	}
	return latestReachingStore(stores, use)
}

func collectSliceElementStores(v ssa.Value, index int, use ssa.Instruction, seen map[ssa.Value]struct{}) []*ssa.Store {
	if v == nil || index < 0 {
		return nil
	}
	if _, ok := seen[v]; ok {
		return nil
	}
	seen[v] = struct{}{}

	var out []*ssa.Store
	switch value := v.(type) {
	case *ssa.ChangeInterface:
		return collectSliceElementStores(value.X, index, use, seen)
	case *ssa.ChangeType:
		return collectSliceElementStores(value.X, index, use, seen)
	case *ssa.Convert:
		return collectSliceElementStores(value.X, index, use, seen)
	case *ssa.MakeInterface:
		return collectSliceElementStores(value.X, index, use, seen)
	case *ssa.Phi:
		for _, edge := range value.Edges {
			out = append(out, collectSliceElementStores(edge, index, use, seen)...)
		}
		return out
	case *ssa.Slice:
		low := 0
		if value.Low != nil {
			var ok bool
			low, ok = intConstant(value.Low)
			if !ok {
				return directElementStores(value, index, use)
			}
		}
		out = append(out, directElementStores(value, index, use)...)
		out = append(out, collectSliceElementStores(value.X, index+low, use, seen)...)
		return out
	case *ssa.UnOp:
		if value.Op != token.MUL {
			return collectSliceElementStores(value.X, index, use, seen)
		}
		out = append(out, directElementStores(value, index, use)...)
		out = append(out, collectSliceElementStores(value.X, index, use, seen)...)
		for _, store := range storesForAddress(value.X) {
			if store.Val == nil || !instructionMayReachUse(store, use) {
				continue
			}
			out = append(out, collectSliceElementStores(store.Val, index, use, seen)...)
		}
		return out
	case *ssa.Alloc:
		out = append(out, directElementStores(value, index, use)...)
		if refs := value.Referrers(); refs != nil {
			for _, ref := range *refs {
				refValue, ok := ref.(ssa.Value)
				if !ok {
					continue
				}
				out = append(out, collectSliceElementStores(refValue, index, use, seen)...)
			}
		}
		return out
	default:
		return directElementStores(value, index, use)
	}
}

func directElementStores(container ssa.Value, index int, use ssa.Instruction) []*ssa.Store {
	if container == nil || container.Referrers() == nil {
		return nil
	}
	var out []*ssa.Store
	for _, ref := range *container.Referrers() {
		switch ref := ref.(type) {
		case *ssa.Store:
			addr, ok := ref.Addr.(*ssa.IndexAddr)
			if !ok || addr.X != container || !intConstantEquals(addr.Index, index) || !instructionMayReachUse(ref, use) {
				continue
			}
			out = append(out, ref)
		case *ssa.IndexAddr:
			if ref.X != container || !intConstantEquals(ref.Index, index) || ref.Referrers() == nil {
				continue
			}
			for _, indexRef := range *ref.Referrers() {
				store, ok := indexRef.(*ssa.Store)
				if ok && store.Addr == ref && instructionMayReachUse(store, use) {
					out = append(out, store)
				}
			}
		}
	}
	return out
}

func latestReachingStore(stores []*ssa.Store, use ssa.Instruction) *ssa.Store {
	if len(stores) == 0 {
		return nil
	}
	best := stores[0]
	for _, candidate := range stores[1:] {
		if storeIsLater(candidate, best, use) {
			best = candidate
		}
	}
	return best
}

func storeIsLater(candidate, current *ssa.Store, use ssa.Instruction) bool {
	if candidate == nil || current == nil {
		return candidate != nil
	}
	if use != nil && candidate.Block() == use.Block() && current.Block() != use.Block() {
		return true
	}
	if use != nil && candidate.Block() != use.Block() && current.Block() == use.Block() {
		return false
	}
	if before, sameBlock := instructionPrecedesInSameBlock(current, candidate); sameBlock && before {
		return true
	}
	if before, sameBlock := instructionPrecedesInSameBlock(candidate, current); sameBlock && before {
		return false
	}
	if current.Block() != nil && candidate.Block() != nil && blockMayReach(current.Block(), candidate.Block()) {
		return true
	}
	return false
}

func intConstantEquals(v ssa.Value, want int) bool {
	got, ok := intConstant(v)
	return ok && got == want
}

func intConstant(v ssa.Value) (int, bool) {
	c, ok := v.(*ssa.Const)
	if !ok || c.Value == nil {
		return 0, false
	}
	got, exact := constant.Int64Val(c.Value)
	if !exact {
		return 0, false
	}
	out := int(got)
	if int64(out) != got {
		return 0, false
	}
	return out, true
}

func stringConstant(v ssa.Value) (string, bool) {
	return stringConstantValue(v, map[ssa.Value]struct{}{})
}

func constantKey(v ssa.Value) (string, bool) {
	return constantKeyValue(v, map[ssa.Value]struct{}{})
}

func constantKeyValue(v ssa.Value, seen map[ssa.Value]struct{}) (string, bool) {
	if v == nil {
		return "", false
	}
	if _, ok := seen[v]; ok {
		return "", false
	}
	seen[v] = struct{}{}
	switch value := v.(type) {
	case *ssa.Const:
		if value.Value == nil {
			return "", false
		}
		return value.Value.Kind().String() + ":" + value.Value.ExactString(), true
	case *ssa.ChangeInterface:
		return constantKeyValue(value.X, seen)
	case *ssa.ChangeType:
		return constantKeyValue(value.X, seen)
	case *ssa.Convert:
		return constantKeyValue(value.X, seen)
	case *ssa.MakeInterface:
		return constantKeyValue(value.X, seen)
	case *ssa.UnOp:
		if value.Op != token.MUL {
			return "", false
		}
		stored, ok := storedValuesForLoad(value)
		if !ok {
			return "", false
		}
		return commonConstantKey(stored, seen)
	case *ssa.Phi:
		return commonConstantKey(value.Edges, seen)
	}
	return "", false
}

func commonConstantKey(values []ssa.Value, seen map[ssa.Value]struct{}) (string, bool) {
	if len(values) == 0 {
		return "", false
	}
	var out string
	for i, value := range values {
		got, ok := constantKeyValue(value, cloneSSAValueSeen(seen))
		if !ok {
			return "", false
		}
		if i == 0 {
			out = got
			continue
		}
		if got != out {
			return "", false
		}
	}
	return out, true
}

func stringConstantValue(v ssa.Value, seen map[ssa.Value]struct{}) (string, bool) {
	if v == nil {
		return "", false
	}
	if _, ok := seen[v]; ok {
		return "", false
	}
	seen[v] = struct{}{}
	switch value := v.(type) {
	case *ssa.Const:
		if value.Value == nil || value.Value.Kind() != constant.String {
			return "", false
		}
		return constant.StringVal(value.Value), true
	case *ssa.ChangeInterface:
		return stringConstantValue(value.X, seen)
	case *ssa.ChangeType:
		return stringConstantValue(value.X, seen)
	case *ssa.Convert:
		return stringConstantValue(value.X, seen)
	case *ssa.MakeInterface:
		return stringConstantValue(value.X, seen)
	case *ssa.UnOp:
		if value.Op != token.MUL {
			return "", false
		}
		stored, ok := storedValuesForLoad(value)
		if !ok {
			return "", false
		}
		return commonStringConstant(stored, seen)
	case *ssa.Phi:
		return commonStringConstant(value.Edges, seen)
	}
	return "", false
}

func commonStringConstant(values []ssa.Value, seen map[ssa.Value]struct{}) (string, bool) {
	if len(values) == 0 {
		return "", false
	}
	var out string
	for i, value := range values {
		got, ok := stringConstantValue(value, cloneSSAValueSeen(seen))
		if !ok {
			return "", false
		}
		if i == 0 {
			out = got
			continue
		}
		if got != out {
			return "", false
		}
	}
	return out, true
}

func cloneSSAValueSeen(seen map[ssa.Value]struct{}) map[ssa.Value]struct{} {
	out := make(map[ssa.Value]struct{}, len(seen))
	maps.Copy(out, seen)
	return out
}

func isShellExecutable(name string) bool {
	base := shellBaseName(name)
	switch strings.ToLower(base) {
	case "sh", "bash", "dash", "zsh", "ksh", "ash",
		"cmd", "cmd.exe",
		"powershell", "powershell.exe",
		"pwsh", "pwsh.exe":
		return true
	default:
		return false
	}
}

func shellBaseName(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		return name[i+1:]
	}
	return name
}

func isShellCommandFlag(shell, flag string) bool {
	base := strings.ToLower(shellBaseName(shell))
	switch base {
	case "cmd", "cmd.exe":
		return strings.EqualFold(flag, "/c")
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		return strings.EqualFold(flag, "-command") || strings.EqualFold(flag, "-c")
	case "sh", "bash", "dash", "zsh", "ksh", "ash":
		return isPOSIXShellCommandFlag(flag)
	default:
		return false
	}
}

func isPOSIXShellCommandFlag(flag string) bool {
	if flag == "-c" {
		return true
	}
	if len(flag) < 3 || !strings.HasPrefix(flag, "-") || strings.HasPrefix(flag, "--") || flag[len(flag)-1] != 'c' {
		return false
	}
	for _, option := range flag[1 : len(flag)-1] {
		if !isPOSIXShellOption(option) {
			return false
		}
	}
	return true
}

func isPOSIXShellOption(option rune) bool {
	switch option {
	case 'a', 'b', 'C', 'e', 'f', 'h', 'i', 'l', 'm', 'n', 'p', 's', 't', 'u', 'v', 'x':
		return true
	default:
		return false
	}
}
