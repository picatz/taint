package taint

// This file isolates the taint checker's memory-state model: how it tracks
// what value(s) a load, map lookup, or buffer read could observe at runtime.
// The checker's question is not "was this object ever tainted?" but rather
// "which value reaches THIS use?", and that requires a per-use SSA-level
// flow analysis distinct from the call-graph walk done in check.go.
//
// Vocabulary used throughout this file:
//
//   - "definite" — the use must observe exactly the value(s) found along this
//     path. A definite store / map update / kill ends the backwards walk
//     because anything earlier on the path is overwritten.
//   - "possible" — the use may observe this value, but earlier writes can
//     still reach if the path is not closed off. Possible values are unioned
//     across paths; they don't terminate the walk.
//
// Helper-mediated effects (a callee writing through a pointer/map parameter)
// are summarized per call site by walking the callee's return paths. A write
// summary is "possible" at the caller (we don't know which return path runs),
// while a kill summary is only emitted when every return path definitely
// kills the relevant slot — i.e. the caller can rely on the kill.

import (
	"go/token"
	"slices"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/picatz/taint/callgraphutil"
)

// -----------------------------------------------------------------------------
// Shared types
// -----------------------------------------------------------------------------

// sideEffectValue records a value that may flow into a use, optionally with
// the helper call/callee that produced it (so taint paths can record the
// summarized hop). `definite` is set when the producing write is the only
// thing that can reach the use along its path.
type sideEffectValue struct {
	value    ssa.Value
	call     *ssa.Call
	callee   *ssa.Function
	definite bool
}

// memoryDef pairs a "write" instruction with the value it wrote and any
// call/callee summary that produced it.
type memoryDef struct {
	instr    ssa.Instruction
	value    ssa.Value
	call     *ssa.Call
	callee   *ssa.Function
	definite bool
}

// memoryDefState groups the defs found along a single CFG path during the
// backwards reaching-definitions walk. `complete` means the path was closed
// by a definite write (no earlier writes need to be considered).
type memoryDefState struct {
	defs     []memoryDef
	complete bool
}

// -----------------------------------------------------------------------------
// Address paths
//
// Field/index precision: helper calls used to be considered as side-effecting
// the entire memory base they reach (any FieldAddr/IndexAddr off it). That
// caused false positives whenever a helper wrote one field and the caller
// later read a different field. We now track an address path — the chain of
// FieldAddr/IndexAddr accesses from the memory base — and only count a helper
// store as reaching the load when the paths are compatible.
// -----------------------------------------------------------------------------

type addrStepKind int

const (
	addrStepField addrStepKind = iota
	addrStepIndex
)

type addrStep struct {
	kind  addrStepKind
	field int
	index ssa.Value
}

// addressPathStepsFromBase peels FieldAddr / IndexAddr / UnOp(MUL) wrappers off
// addr until reaching base, returning the chain of accesses from the base down
// to addr. Returns (steps, true) when the peel ends exactly at base, or
// (nil, false) when the path cannot be reconciled to base.
func addressPathStepsFromBase(addr, base ssa.Value) ([]addrStep, bool) {
	if addr == nil || base == nil {
		return nil, false
	}
	var steps []addrStep
	seen := map[ssa.Value]struct{}{}
	for addr != nil {
		if addr == base {
			return steps, true
		}
		if _, ok := seen[addr]; ok {
			return nil, false
		}
		seen[addr] = struct{}{}
		switch v := addr.(type) {
		case *ssa.FieldAddr:
			steps = append([]addrStep{{kind: addrStepField, field: v.Field}}, steps...)
			addr = v.X
		case *ssa.IndexAddr:
			steps = append([]addrStep{{kind: addrStepIndex, index: v.Index}}, steps...)
			addr = v.X
		case *ssa.UnOp:
			if v.Op != token.MUL {
				return nil, false
			}
			addr = v.X
		case *ssa.ChangeType:
			addr = v.X
		case *ssa.Convert:
			addr = v.X
		case *ssa.MakeInterface:
			addr = v.X
		case *ssa.ChangeInterface:
			addr = v.X
		default:
			return nil, false
		}
	}
	return nil, false
}

// addrStepsMayAlias reports whether two address paths refer to the same
// location. Constant indices that differ rule out aliasing; unknown indices
// conservatively may alias.
func addrStepsMayAlias(a, b []addrStep) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].kind != b[i].kind {
			return false
		}
		switch a[i].kind {
		case addrStepField:
			if a[i].field != b[i].field {
				return false
			}
		case addrStepIndex:
			ai, aOk := intConstant(a[i].index)
			bi, bOk := intConstant(b[i].index)
			if aOk && bOk && ai != bi {
				return false
			}
		}
	}
	return true
}

// storeMatchesLoadPath returns true when the helper's store at storeAddr could
// affect a load whose address path from loadBase is loadSteps. Falls back to
// "may alias" (true) when paths cannot be confidently compared.
func storeMatchesLoadPath(storeAddr ssa.Value, loadSteps []addrStep, paramArgs map[ssa.Value]ssa.Value, loadBase ssa.Value) bool {
	storeBase := memoryBase(storeAddr)
	if storeBase == nil {
		return true
	}
	arg, isParam := paramArgs[storeBase]
	if !isParam {
		return true
	}
	storeSteps, ok := addressPathStepsFromBase(storeAddr, storeBase)
	if !ok {
		return true
	}
	argSteps, ok := addressPathStepsFromBase(arg, loadBase)
	if !ok {
		return true
	}
	total := make([]addrStep, 0, len(argSteps)+len(storeSteps))
	total = append(total, argSteps...)
	total = append(total, storeSteps...)
	return addrStepsMayAlias(loadSteps, total)
}

// -----------------------------------------------------------------------------
// Base / aliasing
// -----------------------------------------------------------------------------

// memoryBase peels off addressing/conversion wrappers (FieldAddr, IndexAddr,
// UnOp(MUL), ChangeType, Convert, MakeInterface, ChangeInterface) and returns
// the underlying SSA value. Useful as a normalized identity for an aggregate.
func memoryBase(v ssa.Value) ssa.Value {
	seen := map[ssa.Value]struct{}{}
	for v != nil {
		if _, ok := seen[v]; ok {
			return v
		}
		seen[v] = struct{}{}
		switch value := v.(type) {
		case *ssa.FieldAddr:
			v = value.X
		case *ssa.IndexAddr:
			v = value.X
		case *ssa.UnOp:
			if value.Op != token.MUL {
				return v
			}
			v = value.X
		case *ssa.ChangeType:
			v = value.X
		case *ssa.Convert:
			v = value.X
		case *ssa.MakeInterface:
			v = value.X
		case *ssa.ChangeInterface:
			v = value.X
		default:
			return v
		}
	}
	return nil
}

// valueMayAliasBase walks v through conversions, phis, and (cautiously) loads
// to decide whether it could be the same location as base.
func valueMayAliasBase(v, base ssa.Value) bool {
	seen := map[ssa.Value]struct{}{}
	var visit func(ssa.Value) bool
	visit = func(cur ssa.Value) bool {
		if cur == nil {
			return false
		}
		if _, ok := seen[cur]; ok {
			return false
		}
		seen[cur] = struct{}{}
		if memoryBase(cur) == base {
			return true
		}
		switch value := cur.(type) {
		case *ssa.ChangeInterface:
			return visit(value.X)
		case *ssa.ChangeType:
			return visit(value.X)
		case *ssa.Convert:
			return visit(value.X)
		case *ssa.MakeInterface:
			return visit(value.X)
		case *ssa.TypeAssert:
			return visit(value.X)
		case *ssa.Phi:
			if slices.ContainsFunc(value.Edges, visit) {
				return true
			}
		case *ssa.UnOp:
			if value.Op != token.MUL {
				return visit(value.X)
			}
			stored, ok := storedLocalValuesForLoad(value)
			if !ok {
				return false
			}
			if slices.ContainsFunc(stored, visit) {
				return true
			}
		}
		return false
	}
	return visit(v)
}

func valueMayAliasAnyBase(v ssa.Value, bases map[ssa.Value]struct{}) bool {
	if len(bases) == 0 {
		return false
	}
	for base := range bases {
		if valueMayAliasBase(v, base) {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// CFG helpers
// -----------------------------------------------------------------------------

func instructionMayReachUse(def, use ssa.Instruction) bool {
	if def == nil || use == nil {
		return true
	}
	if before, sameBlock := instructionPrecedesInSameBlock(def, use); sameBlock {
		return before
	}
	if def.Block() == nil || use.Block() == nil {
		return true
	}
	return blockMayReach(def.Block(), use.Block())
}

func instructionPrecedesInSameBlock(first, second ssa.Instruction) (bool, bool) {
	if first == nil || second == nil || first.Block() == nil || first.Block() != second.Block() {
		return false, false
	}
	for _, instr := range first.Block().Instrs {
		if instr == first {
			return true, true
		}
		if instr == second {
			return false, true
		}
	}
	return false, true
}

func blockMayReach(from, to *ssa.BasicBlock) bool {
	if from == nil || to == nil {
		return true
	}
	seen := map[*ssa.BasicBlock]struct{}{}
	work := []*ssa.BasicBlock{from}
	for len(work) > 0 {
		block := work[len(work)-1]
		work = work[:len(work)-1]
		if block == nil {
			continue
		}
		if block == to {
			return true
		}
		if _, ok := seen[block]; ok {
			continue
		}
		seen[block] = struct{}{}
		work = append(work, block.Succs...)
	}
	return false
}

// blockScanStart returns the index just past `before` in block.Instrs, so a
// reverse loop `for i := blockScanStart(block, before) - 1; i >= 0; i--` walks
// strictly earlier instructions.
func blockScanStart(block *ssa.BasicBlock, before ssa.Instruction) int {
	if block == nil {
		return 0
	}
	if before == nil {
		return len(block.Instrs)
	}
	for i, instr := range block.Instrs {
		if instr == before {
			return i
		}
	}
	return len(block.Instrs)
}

// -----------------------------------------------------------------------------
// Call-site / helper-summary plumbing
// -----------------------------------------------------------------------------

// appendSummaryCallPath extends a callgraph path with a synthetic edge that
// represents "we summarized callee's side effect at this call site." Helper
// summaries use it so the diagnostic trace shows the helper hop.
func appendSummaryCallPath(path callgraphutil.Path, call *ssa.Call, callee *ssa.Function) callgraphutil.Path {
	if call == nil || callee == nil {
		return path
	}
	out := make(callgraphutil.Path, 0, len(path)+1)
	out = append(out, path...)
	out = append(out, &callgraph.Edge{
		Site:   call,
		Callee: &callgraph.Node{Func: callee},
	})
	return out
}

func calleeParamsAliasingBase(call *ssa.Call, targetBase ssa.Value) (*ssa.Function, map[ssa.Value]struct{}) {
	callee, paramArgs := calleeParamArgsAliasingBase(call, targetBase)
	if callee == nil {
		return nil, nil
	}
	params := map[ssa.Value]struct{}{}
	for param := range paramArgs {
		params[param] = struct{}{}
	}
	return callee, params
}

func calleeParamArgsAliasingBase(call *ssa.Call, targetBase ssa.Value) (*ssa.Function, map[ssa.Value]ssa.Value) {
	if call == nil || targetBase == nil {
		return nil, nil
	}
	callee := staticCallee(&call.Call)
	if callee == nil || len(callee.Blocks) == 0 {
		return nil, nil
	}
	paramArgs := map[ssa.Value]ssa.Value{}
	for i, param := range callee.Params {
		actual := callArgForParamIndex(&call.Call, callee, i)
		if actual != nil && valueMayAliasBase(actual, targetBase) {
			paramArgs[param] = actual
		}
	}
	return callee, paramArgs
}

func calleeReturns(fn *ssa.Function) []*ssa.Return {
	if fn == nil {
		return nil
	}
	var out []*ssa.Return
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			if ret, ok := instr.(*ssa.Return); ok {
				out = append(out, ret)
			}
		}
	}
	return out
}

// resolveCalleeValue maps a callee value back to the corresponding caller
// argument when v is a direct parameter of callee called via call. Otherwise
// it returns v unchanged. This lets per-call helper summaries reason about
// callsite-supplied constants.
func resolveCalleeValue(v ssa.Value, callee *ssa.Function, call *ssa.Call) ssa.Value {
	if v == nil || callee == nil || call == nil {
		return v
	}
	param, ok := v.(*ssa.Parameter)
	if !ok {
		return v
	}
	idx := parameterCallArgIndex(callee, param)
	if idx < 0 {
		return v
	}
	if arg := callArgForParamIndex(&call.Call, callee, idx); arg != nil {
		return arg
	}
	return v
}

// -----------------------------------------------------------------------------
// Reaching definitions for ordinary scalar loads
//
// reachingValuesForLoad answers: which values could the load observe? It
// considers both direct stores to the load's address and synthetic stores
// inferred from helper calls (directCalleeStores). The backwards walk
// terminates along a path when it hits a definite store (memoryDefGroupDefinite).
// -----------------------------------------------------------------------------

func reachingValuesForLoad(load *ssa.UnOp) ([]sideEffectValue, bool) {
	defs, ok := reachingMemoryDefsForLoad(load, true)
	if !ok {
		return nil, false
	}
	out := make([]sideEffectValue, 0, len(defs))
	for _, def := range defs {
		if def.value == nil {
			continue
		}
		out = append(out, sideEffectValue{value: def.value, call: def.call, callee: def.callee, definite: def.definite})
	}
	return out, true
}

func storedValuesForLoad(load *ssa.UnOp) ([]ssa.Value, bool) {
	defs, ok := reachingMemoryDefsForLoad(load, true)
	if !ok {
		return nil, false
	}
	out := make([]ssa.Value, 0, len(defs))
	for _, def := range defs {
		if def.value != nil {
			out = append(out, def.value)
		}
	}
	return out, true
}

func storedLocalValuesForLoad(load *ssa.UnOp) ([]ssa.Value, bool) {
	defs, ok := reachingMemoryDefsForLoad(load, false)
	if !ok {
		return nil, false
	}
	out := make([]ssa.Value, 0, len(defs))
	for _, def := range defs {
		if def.value != nil {
			out = append(out, def.value)
		}
	}
	return out, true
}

func reachingMemoryDefsForLoad(load *ssa.UnOp, includeSynthetic bool) ([]memoryDef, bool) {
	if load == nil || load.Op != token.MUL || load.X == nil {
		return nil, false
	}
	defs := memoryDefsForLoad(load, includeSynthetic)
	if len(defs) == 0 {
		return nil, false
	}
	return reachingMemoryDefs(defs, load), true
}

func memoryDefsForLoad(load *ssa.UnOp, includeSynthetic bool) []memoryDef {
	var defs []memoryDef
	for _, store := range storesForAddress(load.X) {
		defs = append(defs, memoryDef{instr: store, value: store.Val, definite: true})
	}
	if !includeSynthetic || load == nil || load.Parent() == nil {
		return defs
	}
	base := memoryBase(load.X)
	if base == nil {
		return defs
	}
	for _, block := range load.Parent().Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			for _, effect := range directCalleeStores(call, load.X) {
				defs = append(defs, memoryDef{
					instr:    call,
					value:    effect.value,
					call:     effect.call,
					callee:   effect.callee,
					definite: effect.definite,
				})
			}
		}
	}
	return defs
}

// reachingMemoryDefs / reachingMemoryDefStates walk the CFG backwards from a
// use, returning every def that could reach it without being shadowed by a
// definite later def on the same path.
func reachingMemoryDefs(defs []memoryDef, use ssa.Instruction) []memoryDef {
	states := reachingMemoryDefStates(defs, use)
	var out []memoryDef
	for _, state := range states {
		out = append(out, state.defs...)
	}
	return dedupeMemoryDefs(out)
}

func reachingMemoryDefStates(defs []memoryDef, use ssa.Instruction) []memoryDefState {
	if len(defs) == 0 {
		return nil
	}
	if use == nil || use.Block() == nil {
		reaching := memoryDefsReachingUse(defs, use)
		if len(reaching) == 0 {
			return nil
		}
		return []memoryDefState{{defs: reaching, complete: memoryDefGroupDefinite(reaching)}}
	}
	type cursorKey struct {
		block  *ssa.BasicBlock
		before ssa.Instruction
	}
	var visit func(*ssa.BasicBlock, ssa.Instruction, []memoryDef, map[cursorKey]struct{}) []memoryDefState
	visit = func(block *ssa.BasicBlock, before ssa.Instruction, found []memoryDef, seen map[cursorKey]struct{}) []memoryDefState {
		if block == nil {
			return []memoryDefState{{defs: found}}
		}
		key := cursorKey{block: block, before: before}
		if _, ok := seen[key]; ok {
			return []memoryDefState{{defs: found}}
		}
		nextSeen := make(map[cursorKey]struct{}, len(seen)+1)
		for seenKey := range seen {
			nextSeen[seenKey] = struct{}{}
		}
		nextSeen[key] = struct{}{}
		for i := blockScanStart(block, before) - 1; i >= 0; i-- {
			group := memoryDefsAt(defs, block.Instrs[i])
			if len(group) == 0 {
				continue
			}
			nextFound := append(append([]memoryDef(nil), found...), group...)
			if memoryDefGroupDefinite(group) {
				return []memoryDefState{{defs: nextFound, complete: true}}
			}
			found = nextFound
		}
		if len(block.Preds) == 0 {
			return []memoryDefState{{defs: found}}
		}
		var out []memoryDefState
		for _, pred := range block.Preds {
			predFound := append([]memoryDef(nil), found...)
			out = append(out, visit(pred, nil, predFound, nextSeen)...)
		}
		return out
	}
	return visit(use.Block(), use, nil, nil)
}

func memoryDefsReachingUse(defs []memoryDef, use ssa.Instruction) []memoryDef {
	out := make([]memoryDef, 0, len(defs))
	for _, def := range defs {
		if instructionMayReachUse(def.instr, use) {
			out = append(out, def)
		}
	}
	return dedupeMemoryDefs(out)
}

func memoryDefsAt(defs []memoryDef, instr ssa.Instruction) []memoryDef {
	var out []memoryDef
	for _, def := range defs {
		if def.instr == instr {
			out = append(out, def)
		}
	}
	return out
}

func memoryDefGroupDefinite(defs []memoryDef) bool {
	if len(defs) == 0 {
		return false
	}
	for _, def := range defs {
		if !def.definite {
			return false
		}
	}
	return true
}

func dedupeMemoryDefs(defs []memoryDef) []memoryDef {
	if len(defs) < 2 {
		return defs
	}
	type defKey struct {
		instr    ssa.Instruction
		value    ssa.Value
		call     *ssa.Call
		callee   *ssa.Function
		definite bool
	}
	seen := map[defKey]struct{}{}
	out := make([]memoryDef, 0, len(defs))
	for _, def := range defs {
		key := defKey{instr: def.instr, value: def.value, call: def.call, callee: def.callee, definite: def.definite}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, def)
	}
	return out
}

func storesForAddress(addr ssa.Value) []*ssa.Store {
	if addr == nil {
		return nil
	}
	var out []*ssa.Store
	if refs := addr.Referrers(); refs != nil {
		for _, ref := range *refs {
			store, ok := ref.(*ssa.Store)
			if !ok || store.Addr != addr || store.Val == nil {
				continue
			}
			out = append(out, store)
		}
	}
	return out
}

// directCalleeStores summarizes a helper call as a (possibly empty) set of
// stores that may reach loadAddr in the caller. Field/index precision is
// applied when storeMatchesLoadPath can prove the helper writes a different
// slot than the load reads; otherwise the result falls back to coarse base-
// level aliasing to stay sound.
func directCalleeStores(call *ssa.Call, loadAddr ssa.Value) []sideEffectValue {
	targetBase := memoryBase(loadAddr)
	if targetBase == nil {
		return nil
	}
	callee, paramArgs := calleeParamArgsAliasingBase(call, targetBase)
	if callee == nil || len(paramArgs) == 0 {
		return nil
	}
	params := map[ssa.Value]struct{}{}
	for param := range paramArgs {
		params[param] = struct{}{}
	}
	returns := calleeReturns(callee)
	loadSteps, loadPathOK := addressPathStepsFromBase(loadAddr, targetBase)
	var defs []memoryDef
	for _, block := range callee.Blocks {
		for _, instr := range block.Instrs {
			store, ok := instr.(*ssa.Store)
			if !ok || store.Val == nil || !valueMayAliasAnyBase(store.Addr, params) {
				continue
			}
			if loadPathOK && !storeMatchesLoadPath(store.Addr, loadSteps, paramArgs, targetBase) {
				continue
			}
			defs = append(defs, memoryDef{instr: store, value: store.Val, definite: true})
		}
	}
	var states []memoryDefState
	for _, ret := range returns {
		states = append(states, reachingMemoryDefStates(defs, ret)...)
	}
	definite := len(states) > 0
	for _, state := range states {
		if !state.complete {
			definite = false
			break
		}
	}
	var out []sideEffectValue
	seen := map[ssa.Value]struct{}{}
	for _, state := range states {
		for _, def := range state.defs {
			if def.value == nil {
				continue
			}
			if _, ok := seen[def.value]; ok {
				continue
			}
			seen[def.value] = struct{}{}
			out = append(out, sideEffectValue{value: def.value, call: call, callee: callee, definite: definite})
		}
	}
	return out
}

func dedupeSideEffectValues(values []sideEffectValue) []sideEffectValue {
	if len(values) < 2 {
		return values
	}
	type effectKey struct {
		value    ssa.Value
		call     *ssa.Call
		callee   *ssa.Function
		definite bool
	}
	seen := map[effectKey]struct{}{}
	out := make([]sideEffectValue, 0, len(values))
	for _, value := range values {
		key := effectKey{value: value.value, call: value.call, callee: value.callee, definite: value.definite}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

// -----------------------------------------------------------------------------
// Buffer model (strings.Builder / bytes.Buffer / io.WriteString / fmt.Fprint*)
//
// Writes append to the buffer; Reset / Truncate(0) "kill" prior contents.
// A reader like .String() / .Bytes() / .Next() observes the union of writes
// that survive the kills along each path back from the read.
// -----------------------------------------------------------------------------

type bufferEventKind int

const (
	bufferWriteEvent bufferEventKind = iota
	bufferClearEvent
)

type bufferEvent struct {
	kind   bufferEventKind
	instr  ssa.Instruction
	values []ssa.Value
	call   *ssa.Call
	callee *ssa.Function
}

type bufferPathState struct {
	writes []sideEffectValue
	killed bool
}

func bufferReadCall(call *ssa.CallCommon) bool {
	switch callString(call) {
	case "(*strings.Builder).String",
		"(*bytes.Buffer).String",
		"(*bytes.Buffer).Bytes",
		"(*bytes.Buffer).Next",
		"(*bytes.Buffer).ReadString",
		"(*bytes.Buffer).ReadBytes":
		return true
	default:
		return false
	}
}

func bufferWriteDataArgs(call *ssa.CallCommon) (ssa.Value, []ssa.Value, bool) {
	switch callString(call) {
	case "(*strings.Builder).Write",
		"(*strings.Builder).WriteString",
		"(*strings.Builder).WriteByte",
		"(*strings.Builder).WriteRune",
		"(*bytes.Buffer).Write",
		"(*bytes.Buffer).WriteString",
		"(*bytes.Buffer).WriteByte",
		"(*bytes.Buffer).WriteRune",
		"(*bytes.Buffer).ReadFrom":
		dest := receiverArg(call)
		if dest == nil {
			return nil, nil, false
		}
		args := call.Args
		if len(args) > 0 && dest == args[0] {
			args = args[1:]
		}
		return dest, args, true
	case "fmt.Fprint",
		"fmt.Fprintf",
		"fmt.Fprintln",
		"io.WriteString":
		if call == nil || len(call.Args) == 0 {
			return nil, nil, false
		}
		return call.Args[0], call.Args[1:], true
	default:
		return nil, nil, false
	}
}

func bufferClearCall(call *ssa.CallCommon) (ssa.Value, bool) {
	switch callString(call) {
	case "(*strings.Builder).Reset",
		"(*bytes.Buffer).Reset":
		dest := receiverArg(call)
		return dest, dest != nil
	case "(*bytes.Buffer).Truncate":
		dest := receiverArg(call)
		if dest == nil || call == nil || len(call.Args) < 2 {
			return nil, false
		}
		n := call.Args[len(call.Args)-1]
		truncateTo, ok := intConstant(n)
		return dest, ok && truncateTo == 0
	default:
		return nil, false
	}
}

func receiverArg(call *ssa.CallCommon) ssa.Value {
	if call == nil {
		return nil
	}
	if call.IsInvoke() {
		return call.Value
	}
	if call.Signature() != nil && call.Signature().Recv() != nil && len(call.Args) > 0 {
		return call.Args[0]
	}
	return nil
}

// priorBufferedWriteEffects gathers the writes that survive any intervening
// Reset/Truncate(0) along all paths from `read` back to function entry.
func priorBufferedWriteEffects(recv ssa.Value, read ssa.Instruction) []sideEffectValue {
	base := memoryBase(recv)
	if base == nil || read == nil || read.Parent() == nil || read.Block() == nil {
		return nil
	}
	events := bufferEventsForBase(base, read.Parent())
	if len(events) == 0 {
		return nil
	}
	states := collectBufferPathStates(events, read)
	var out []sideEffectValue
	for _, state := range states {
		out = append(out, state.writes...)
	}
	return dedupeSideEffectValues(out)
}

func bufferEventsForBase(base ssa.Value, fn *ssa.Function) []bufferEvent {
	if base == nil || fn == nil {
		return nil
	}
	var out []bufferEvent
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			if dest, args, ok := bufferWriteDataArgs(&call.Call); ok && valueMayAliasBase(dest, base) {
				out = append(out, bufferEvent{kind: bufferWriteEvent, instr: call, values: args})
			}
			if dest, ok := bufferClearCall(&call.Call); ok && valueMayAliasBase(dest, base) {
				out = append(out, bufferEvent{kind: bufferClearEvent, instr: call})
			}
			out = append(out, directCalleeBufferedEvents(call, base)...)
		}
	}
	return out
}

// collectBufferPathStates traverses the CFG backwards from `use`. Along each
// path it accumulates write values; a clear/reset terminates the path with
// `killed=true` so callers can tell that earlier writes can't reach.
func collectBufferPathStates(events []bufferEvent, use ssa.Instruction) []bufferPathState {
	if len(events) == 0 || use == nil || use.Block() == nil {
		return nil
	}
	type cursorKey struct {
		block  *ssa.BasicBlock
		before ssa.Instruction
	}
	var visit func(*ssa.BasicBlock, ssa.Instruction, []sideEffectValue, map[cursorKey]struct{}) []bufferPathState
	visit = func(block *ssa.BasicBlock, before ssa.Instruction, writes []sideEffectValue, seen map[cursorKey]struct{}) []bufferPathState {
		if block == nil {
			return []bufferPathState{{writes: writes}}
		}
		key := cursorKey{block: block, before: before}
		if _, ok := seen[key]; ok {
			return []bufferPathState{{writes: writes}}
		}
		nextSeen := make(map[cursorKey]struct{}, len(seen)+1)
		for seenKey := range seen {
			nextSeen[seenKey] = struct{}{}
		}
		nextSeen[key] = struct{}{}

		for i := blockScanStart(block, before) - 1; i >= 0; i-- {
			group := bufferEventsAt(events, block.Instrs[i])
			if len(group) == 0 {
				continue
			}
			var killed bool
			for _, event := range group {
				if event.kind == bufferWriteEvent {
					for _, value := range event.values {
						writes = append(writes, sideEffectValue{value: value, call: event.call, callee: event.callee})
					}
				}
			}
			for _, event := range group {
				if event.kind == bufferClearEvent {
					killed = true
					break
				}
			}
			if killed {
				return []bufferPathState{{writes: writes, killed: true}}
			}
		}
		if len(block.Preds) == 0 {
			return []bufferPathState{{writes: writes}}
		}
		var out []bufferPathState
		for _, pred := range block.Preds {
			predWrites := append([]sideEffectValue(nil), writes...)
			out = append(out, visit(pred, nil, predWrites, nextSeen)...)
		}
		return out
	}
	return visit(use.Block(), use, nil, nil)
}

func bufferEventsAt(events []bufferEvent, instr ssa.Instruction) []bufferEvent {
	var out []bufferEvent
	for _, event := range events {
		if event.instr == instr {
			out = append(out, event)
		}
	}
	return out
}

// directCalleeBufferedEvents summarizes a helper call as up to one write event
// (union of all writes the helper can perform) and up to one clear event
// (only when EVERY return path ends with a clear). This is the buffer-shaped
// analog of directCalleeStores / directCalleeMapEvents.
func directCalleeBufferedEvents(call *ssa.Call, targetBase ssa.Value) []bufferEvent {
	callee, params := calleeParamsAliasingBase(call, targetBase)
	if callee == nil || len(params) == 0 {
		return nil
	}
	var calleeEvents []bufferEvent
	for _, block := range callee.Blocks {
		for _, instr := range block.Instrs {
			write, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			if dest, args, ok := bufferWriteDataArgs(&write.Call); ok && valueMayAliasAnyBase(dest, params) {
				calleeEvents = append(calleeEvents, bufferEvent{kind: bufferWriteEvent, instr: write, values: args, call: call, callee: callee})
			}
			if dest, ok := bufferClearCall(&write.Call); ok && valueMayAliasAnyBase(dest, params) {
				calleeEvents = append(calleeEvents, bufferEvent{kind: bufferClearEvent, instr: write, call: call, callee: callee})
			}
		}
	}
	returns := calleeReturns(callee)
	if len(calleeEvents) == 0 || len(returns) == 0 {
		return nil
	}
	clearAll := true
	var writes []sideEffectValue
	for _, ret := range returns {
		states := collectBufferPathStates(calleeEvents, ret)
		if len(states) == 0 {
			clearAll = false
			continue
		}
		for _, state := range states {
			if !state.killed {
				clearAll = false
			}
			writes = append(writes, state.writes...)
		}
	}
	writes = dedupeSideEffectValues(writes)
	var out []bufferEvent
	if len(writes) > 0 {
		values := make([]ssa.Value, 0, len(writes))
		for _, write := range writes {
			values = append(values, write.value)
		}
		out = append(out, bufferEvent{kind: bufferWriteEvent, instr: call, values: values, call: call, callee: callee})
	}
	if clearAll {
		out = append(out, bufferEvent{kind: bufferClearEvent, instr: call, call: call, callee: callee})
	}
	return out
}

// -----------------------------------------------------------------------------
// Map model (m[k] = v, m[k], delete(m, k), clear(m))
//
// Writes are MapUpdate instructions; kills are delete/clear builtins or
// helpers that summarize to a definite kill on every return path. A lookup
// observes the union of writes that survive all kills on each path back.
// -----------------------------------------------------------------------------

type mapEventKind int

const (
	mapEventWrite mapEventKind = iota
	mapEventKill
)

type mapEvent struct {
	kind     mapEventKind
	instr    ssa.Instruction
	values   []sideEffectValue
	matches  bool
	definite bool
}

type mapPathState struct {
	writes []sideEffectValue
	killed bool
}

func reachingMapLookupValues(lookup *ssa.Lookup) []sideEffectValue {
	if lookup == nil || lookup.X == nil || lookup.Parent() == nil || lookup.Block() == nil {
		return nil
	}
	events := mapEventsForLookup(lookup)
	if len(events) == 0 {
		return nil
	}
	type cursorKey struct {
		block  *ssa.BasicBlock
		before ssa.Instruction
	}
	seen := map[cursorKey]struct{}{}
	var out []sideEffectValue
	var visit func(*ssa.BasicBlock, ssa.Instruction)
	visit = func(block *ssa.BasicBlock, before ssa.Instruction) {
		if block == nil {
			return
		}
		key := cursorKey{block: block, before: before}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		for i := blockScanStart(block, before) - 1; i >= 0; i-- {
			instr := block.Instrs[i]
			stop := false
			for _, ev := range events {
				if ev.instr != instr || !ev.matches {
					continue
				}
				switch ev.kind {
				case mapEventWrite:
					out = append(out, ev.values...)
					if ev.definite {
						stop = true
					}
				case mapEventKill:
					if ev.definite {
						stop = true
					}
				}
			}
			if stop {
				return
			}
		}
		for _, pred := range block.Preds {
			visit(pred, nil)
		}
	}
	visit(lookup.Block(), lookup)
	return dedupeSideEffectValues(out)
}

func mapEventsForLookup(lookup *ssa.Lookup) []mapEvent {
	if lookup == nil || lookup.X == nil || lookup.Parent() == nil {
		return nil
	}
	var out []mapEvent
	for _, block := range lookup.Parent().Blocks {
		for _, instr := range block.Instrs {
			switch v := instr.(type) {
			case *ssa.MapUpdate:
				if v.Value == nil || !sameMapValue(v.Map, lookup.X) {
					continue
				}
				matches, definite := mapUpdateMatchesLookup(v, lookup)
				if !matches {
					continue
				}
				out = append(out, mapEvent{
					kind:     mapEventWrite,
					instr:    v,
					values:   []sideEffectValue{{value: v.Value, definite: definite}},
					matches:  true,
					definite: definite,
				})
			case *ssa.Call:
				if events := mapBuiltinEventsForCall(v, lookup); len(events) > 0 {
					out = append(out, events...)
				}
				if events := directCalleeMapEvents(v, lookup); len(events) > 0 {
					out = append(out, events...)
				}
			}
		}
	}
	return out
}

func mapBuiltinEventsForCall(call *ssa.Call, lookup *ssa.Lookup) []mapEvent {
	if call == nil || lookup == nil {
		return nil
	}
	common := &call.Call
	builtin, ok := common.Value.(*ssa.Builtin)
	if !ok {
		return nil
	}
	switch builtin.Name() {
	case "delete":
		if len(common.Args) < 2 {
			return nil
		}
		if !sameMapValue(common.Args[0], lookup.X) {
			return nil
		}
		matches, definite := mapKeysMayMatch(common.Args[1], lookup.Index)
		if !matches {
			return nil
		}
		return []mapEvent{{
			kind:     mapEventKill,
			instr:    call,
			matches:  true,
			definite: definite,
		}}
	case "clear":
		if len(common.Args) == 0 {
			return nil
		}
		if !sameMapValue(common.Args[0], lookup.X) {
			return nil
		}
		return []mapEvent{{
			kind:     mapEventKill,
			instr:    call,
			matches:  true,
			definite: true,
		}}
	}
	return nil
}

func mapKeysMayMatch(a, b ssa.Value) (bool, bool) {
	ka, aOK := constantKey(a)
	kb, bOK := constantKey(b)
	if aOK && bOK {
		eq := ka == kb
		return eq, eq
	}
	return true, false
}

// directCalleeMapEvents derives a per-call summary of map writes/kills that a
// helper performs on map parameters aliasing the lookup's map. It returns at
// most one write event (with the union of possibly-written values) and one
// kill event (only when all return paths end with a definite kill).
func directCalleeMapEvents(call *ssa.Call, lookup *ssa.Lookup) []mapEvent {
	if call == nil || lookup == nil {
		return nil
	}
	callee := staticCallee(&call.Call)
	if callee == nil || len(callee.Blocks) == 0 {
		return nil
	}
	params := map[ssa.Value]struct{}{}
	for i, param := range callee.Params {
		actual := callArgForParamIndex(&call.Call, callee, i)
		if actual != nil && sameMapValue(actual, lookup.X) {
			params[param] = struct{}{}
		}
	}
	if len(params) == 0 {
		return nil
	}
	resolve := func(v ssa.Value) ssa.Value { return resolveCalleeValue(v, callee, call) }
	var helperEvents []mapEvent
	for _, block := range callee.Blocks {
		for _, instr := range block.Instrs {
			switch v := instr.(type) {
			case *ssa.MapUpdate:
				if v.Value == nil {
					continue
				}
				if _, ok := params[v.Map]; !ok {
					continue
				}
				matches, definite := mapKeysMayMatch(resolve(v.Key), lookup.Index)
				if !matches {
					continue
				}
				helperEvents = append(helperEvents, mapEvent{
					kind:     mapEventWrite,
					instr:    v,
					values:   []sideEffectValue{{value: v.Value, definite: definite}},
					matches:  true,
					definite: definite,
				})
			case *ssa.Call:
				common := &v.Call
				builtin, ok := common.Value.(*ssa.Builtin)
				if !ok {
					continue
				}
				switch builtin.Name() {
				case "delete":
					if len(common.Args) < 2 {
						continue
					}
					if _, ok := params[common.Args[0]]; !ok {
						continue
					}
					matches, definite := mapKeysMayMatch(resolve(common.Args[1]), lookup.Index)
					if !matches {
						continue
					}
					helperEvents = append(helperEvents, mapEvent{
						kind:     mapEventKill,
						instr:    v,
						matches:  true,
						definite: definite,
					})
				case "clear":
					if len(common.Args) == 0 {
						continue
					}
					if _, ok := params[common.Args[0]]; !ok {
						continue
					}
					helperEvents = append(helperEvents, mapEvent{
						kind:     mapEventKill,
						instr:    v,
						matches:  true,
						definite: true,
					})
				}
			}
		}
	}
	if len(helperEvents) == 0 {
		return nil
	}
	returns := calleeReturns(callee)
	if len(returns) == 0 {
		return nil
	}
	var allWrites []sideEffectValue
	killOnAllPaths := true
	for _, ret := range returns {
		states := collectMapPathStates(helperEvents, ret)
		if len(states) == 0 {
			killOnAllPaths = false
			continue
		}
		for _, state := range states {
			if !state.killed {
				killOnAllPaths = false
			}
			allWrites = append(allWrites, state.writes...)
		}
	}
	allWrites = dedupeSideEffectValues(allWrites)
	for i := range allWrites {
		allWrites[i].call = call
		allWrites[i].callee = callee
		allWrites[i].definite = false
	}
	var out []mapEvent
	if len(allWrites) > 0 {
		out = append(out, mapEvent{
			kind:     mapEventWrite,
			instr:    call,
			values:   allWrites,
			matches:  true,
			definite: false,
		})
	}
	if killOnAllPaths {
		out = append(out, mapEvent{
			kind:     mapEventKill,
			instr:    call,
			matches:  true,
			definite: true,
		})
	}
	return out
}

// collectMapPathStates walks events backwards from `use` through the callee's
// CFG, accumulating writes seen along each path. A definite kill ends the
// walk along that path. Mirrors collectBufferPathStates.
func collectMapPathStates(events []mapEvent, use ssa.Instruction) []mapPathState {
	if len(events) == 0 || use == nil || use.Block() == nil {
		return nil
	}
	type cursorKey struct {
		block  *ssa.BasicBlock
		before ssa.Instruction
	}
	var visit func(*ssa.BasicBlock, ssa.Instruction, []sideEffectValue, map[cursorKey]struct{}) []mapPathState
	visit = func(block *ssa.BasicBlock, before ssa.Instruction, writes []sideEffectValue, seen map[cursorKey]struct{}) []mapPathState {
		if block == nil {
			return []mapPathState{{writes: writes}}
		}
		key := cursorKey{block: block, before: before}
		if _, ok := seen[key]; ok {
			return []mapPathState{{writes: writes}}
		}
		nextSeen := make(map[cursorKey]struct{}, len(seen)+1)
		for seenKey := range seen {
			nextSeen[seenKey] = struct{}{}
		}
		nextSeen[key] = struct{}{}
		for i := blockScanStart(block, before) - 1; i >= 0; i-- {
			instr := block.Instrs[i]
			var killed bool
			for _, ev := range events {
				if ev.instr != instr {
					continue
				}
				switch ev.kind {
				case mapEventWrite:
					writes = append(writes, ev.values...)
				case mapEventKill:
					if ev.definite {
						killed = true
					}
				}
			}
			if killed {
				return []mapPathState{{writes: writes, killed: true}}
			}
		}
		if len(block.Preds) == 0 {
			return []mapPathState{{writes: writes}}
		}
		var out []mapPathState
		for _, pred := range block.Preds {
			predWrites := append([]sideEffectValue(nil), writes...)
			out = append(out, visit(pred, nil, predWrites, nextSeen)...)
		}
		return out
	}
	return visit(use.Block(), use, nil, nil)
}

func sameMapValue(candidate, target ssa.Value) bool {
	if candidate == nil || target == nil {
		return false
	}
	if candidate == target {
		return true
	}
	if base := memoryBase(target); base != nil && valueMayAliasBase(candidate, base) {
		return true
	}
	if base := memoryBase(candidate); base != nil && valueMayAliasBase(target, base) {
		return true
	}
	return false
}

func mapUpdateMatchesLookup(update *ssa.MapUpdate, lookup *ssa.Lookup) (bool, bool) {
	if update == nil || lookup == nil {
		return false, false
	}
	updateKey, updateKnown := constantKey(update.Key)
	lookupKey, lookupKnown := constantKey(lookup.Index)
	if updateKnown && lookupKnown {
		return updateKey == lookupKey, updateKey == lookupKey
	}
	return true, false
}
