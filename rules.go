package taint

import (
	"go/token"
	"go/types"
	"sort"

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

type sourceRule struct {
	id         string
	matchType  func(types.Type) bool
	matchCall  func(*ssa.CallCommon) bool
	matchValue func(ssa.Value) bool
}

type sinkRule struct {
	id         string
	matchEdge  func(*callgraph.Edge) bool
	selectArgs func(*callgraph.Edge) []ssa.Value
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

	registry := &ruleRegistry{
		sources:         Sources(mergedSources),
		sinks:           Sinks(mergedSinks),
		maxSummaryDepth: cfg.maxSummaryDepth,
	}
	// Iterate maps in deterministic order so the resulting rule slices have a
	// stable order. Downstream traversal records the first rule that matches
	// a given callsite; without sorting, two runs over the same program can
	// record different SinkType values for the same finding when more than
	// one rule could plausibly match.
	for _, source := range sortedKeys(mergedSources) {
		registry.sourceRules = append(registry.sourceRules, exactSourceRule(source))
	}
	for _, sink := range sortedKeys(mergedSinks) {
		registry.sinkRules = append(registry.sinkRules, exactSinkRule(sink))
	}
	for _, sanitizer := range cfg.sanitizers {
		registry.sanitizers = append(registry.sanitizers, exactSanitizerRule(sanitizer))
	}
	registry.propagators = defaultPropagatorRules()
	return registry
}

func sortedKeys(set stringSet) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func cloneStringSet(in stringSet) stringSet {
	out := stringSet{}
	for value := range in {
		out[value] = struct{}{}
	}
	return out
}

func exactSourceRule(id string) sourceRule {
	return sourceRule{
		id: id,
		matchType: func(t types.Type) bool {
			if t == nil {
				return false
			}
			if t.String() == id || types.TypeString(t, nil) == id {
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
			t := v.Type()
			return t != nil && (t.String() == id || types.TypeString(t, nil) == id)
		},
	}
}

func exactSinkRule(id string) sinkRule {
	return sinkRule{
		id: id,
		matchEdge: func(edge *callgraph.Edge) bool {
			return edgeCallsSink(edge, id)
		},
		selectArgs: defaultSinkArguments,
	}
}

func exactSanitizerRule(id string) sanitizerRule {
	return sanitizerRule{
		id: id,
		matchCall: func(call *ssa.CallCommon) bool {
			return callString(call) == id
		},
	}
}

func defaultPropagatorRules() []propagatorRule {
	allArgs := func(call *ssa.CallCommon) []ssa.Value {
		if call == nil {
			return nil
		}
		return call.Args
	}
	return []propagatorRule{
		{id: "fmt.Sprintf", matchCall: exactCallMatcher("fmt.Sprintf"), selectArgs: allArgs},
		{id: "fmt.Sprint", matchCall: exactCallMatcher("fmt.Sprint"), selectArgs: allArgs},
		{id: "fmt.Sprintln", matchCall: exactCallMatcher("fmt.Sprintln"), selectArgs: allArgs},
		{id: "fmt.Errorf", matchCall: exactCallMatcher("fmt.Errorf"), selectArgs: allArgs},
		{id: "errors.New", matchCall: exactCallMatcher("errors.New"), selectArgs: allArgs},
		{id: "io.ReadAll", matchCall: exactCallMatcher("io.ReadAll"), selectArgs: allArgs},
		{id: "bufio.NewReader", matchCall: exactCallMatcher("bufio.NewReader"), selectArgs: allArgs},
		{id: "bufio.NewReaderSize", matchCall: exactCallMatcher("bufio.NewReaderSize"), selectArgs: allArgs},
		{id: "go.uber.org/zap.String", matchCall: exactCallMatcher("go.uber.org/zap.String"), selectArgs: allArgs},
		{id: "html.EscapeString", matchCall: exactCallMatcher("html.EscapeString"), selectArgs: allArgs},
	}
}

func defaultPropagatorForCall(call *ssa.CallCommon) (propagatorRule, []ssa.Value, bool) {
	for _, rule := range defaultPropagatorRules() {
		if rule.matchCall != nil && rule.matchCall(call) {
			args := call.Args
			if rule.selectArgs != nil {
				args = rule.selectArgs(call)
			}
			return rule, args, true
		}
	}
	return propagatorRule{}, nil, false
}

func exactCallMatcher(id string) func(*ssa.CallCommon) bool {
	return func(call *ssa.CallCommon) bool {
		return callString(call) == id
	}
}

func (r *ruleRegistry) matchSourceType(t types.Type) (string, bool) {
	for _, rule := range r.sourceRules {
		if rule.matchType != nil && rule.matchType(t) {
			return rule.id, true
		}
	}
	return "", false
}

func (r *ruleRegistry) matchSourceCall(call *ssa.CallCommon) (string, bool) {
	for _, rule := range r.sourceRules {
		if rule.matchCall != nil && rule.matchCall(call) {
			return rule.id, true
		}
	}
	return "", false
}

func (r *ruleRegistry) matchSourceValue(v ssa.Value) (string, bool) {
	if v == nil || v.Type() == nil {
		return "", false
	}
	if src, ok := r.matchSourceType(v.Type()); ok {
		return src, true
	}
	for _, rule := range r.sourceRules {
		if rule.matchValue != nil && rule.matchValue(v) {
			return rule.id, true
		}
	}
	return "", false
}

func matchSourceType(sources Sources, t types.Type) (string, bool) {
	for source := range sources {
		rule := exactSourceRule(source)
		if rule.matchType != nil && rule.matchType(t) {
			return source, true
		}
	}
	return "", false
}

func matchSourceCall(sources Sources, call *ssa.CallCommon) (string, bool) {
	for source := range sources {
		rule := exactSourceRule(source)
		if rule.matchCall != nil && rule.matchCall(call) {
			return source, true
		}
	}
	return "", false
}

func matchSourceValue(sources Sources, v ssa.Value) (string, bool) {
	if v == nil {
		return "", false
	}
	return matchSourceType(sources, v.Type())
}

func (r *ruleRegistry) sanitizerForValue(v ssa.Value) (sanitizerRule, bool) {
	seen := map[ssa.Value]struct{}{}
	var visit func(ssa.Value) (sanitizerRule, bool)
	visit = func(cur ssa.Value) (sanitizerRule, bool) {
		if cur == nil {
			return sanitizerRule{}, false
		}
		if _, ok := seen[cur]; ok {
			return sanitizerRule{}, false
		}
		seen[cur] = struct{}{}

		if call, ok := cur.(*ssa.Call); ok {
			return r.sanitizerForCall(&call.Call)
		}
		switch value := cur.(type) {
		case *ssa.MakeInterface:
			return visit(value.X)
		case *ssa.ChangeInterface:
			return visit(value.X)
		case *ssa.ChangeType:
			return visit(value.X)
		case *ssa.Convert:
			return visit(value.X)
		case *ssa.TypeAssert:
			return visit(value.X)
		case *ssa.UnOp:
			if value.Op == token.MUL {
				if rule, ok := allStoredValuesSanitized(value.X, visit); ok {
					return rule, true
				}
			}
			return visit(value.X)
		case *ssa.Alloc:
			return allStoredValuesSanitized(value, visit)
		case *ssa.Phi:
			return allValuesSanitized(value.Edges, visit)
		}
		return sanitizerRule{}, false
	}
	return visit(v)
}

func (r *ruleRegistry) expressionContainsSanitizer(v ssa.Value) (sanitizerRule, bool) {
	seen := map[ssa.Value]struct{}{}
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
		}
		if instr, ok := cur.(ssa.Instruction); ok {
			for _, operand := range instr.Operands(nil) {
				if operand != nil && *operand != nil {
					work = append(work, *operand)
				}
			}
			continue
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
				work = append(work, storedValuesFor(value.X)...)
			}
		case *ssa.Alloc:
			work = append(work, storedValuesFor(value)...)
		case *ssa.Extract:
			work = append(work, value.Tuple)
		case *ssa.BinOp:
			work = append(work, value.X, value.Y)
		case *ssa.Slice:
			work = append(work, value.X)
		}
	}
	return sanitizerRule{}, false
}

func allStoredValuesSanitized(addr ssa.Value, visit func(ssa.Value) (sanitizerRule, bool)) (sanitizerRule, bool) {
	return allValuesSanitized(storedValuesFor(addr), visit)
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

func (r *ruleRegistry) propagatorForCall(call *ssa.CallCommon) (propagatorRule, []ssa.Value, bool) {
	for _, rule := range r.propagators {
		if rule.matchCall != nil && rule.matchCall(call) {
			args := call.Args
			if rule.selectArgs != nil {
				args = rule.selectArgs(call)
			}
			return rule, args, true
		}
	}
	return propagatorRule{}, nil, false
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
