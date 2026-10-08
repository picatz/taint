package taint

import (
	"go/token"
	"go/types"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/ssa"
)

// isArrayValueType proves that a value is an array, including a type parameter
// whose entire type set has one array underlying type. A mixed array/slice
// constraint must not acquire array-copy semantics.
func isArrayValueType(t types.Type) bool {
	t = types.Unalias(t)
	if _, ok := t.Underlying().(*types.Array); ok {
		return true
	}
	p, ok := t.(*types.TypeParam)
	if !ok {
		return false
	}
	var candidates []*types.Array
	seen := map[types.Type]bool{}
	var visit func(types.Type)
	visit = func(t types.Type) {
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Array:
			candidates = append(candidates, u)
		case *types.Interface:
			for i := 0; i < u.NumEmbeddeds(); i++ {
				visit(u.EmbeddedType(i))
			}
		case *types.Union:
			for i := 0; i < u.Len(); i++ {
				visit(u.Term(i).Type())
			}
		}
	}
	visit(p.Constraint())
	for _, a := range candidates {
		constraint := types.NewInterfaceType(nil, []types.Type{types.NewUnion([]*types.Term{types.NewTerm(true, a)})}).Complete()
		if types.Satisfies(p, constraint) {
			return true
		}
	}
	return false
}

// checkArrayElement follows a value-copy's selected element, never its index's
// taint. Loads are resolved at the original copy instruction, so later writes
// to the source array cannot change the copied value.
func checkArrayElement(path callgraphutil.Path, ctx taintContext, value, index ssa.Value, visited valueSet) (bool, string, ssa.Value) {
	if value == nil || visited.includes(value) {
		return false, "", nil
	}
	next := visited.clone()
	next.add(value)
	switch v := value.(type) {
	case *ssa.ChangeType:
		return checkArrayElement(path, ctx, v.X, index, next)
	case *ssa.Convert:
		if isArrayValueType(v.X.Type()) {
			return checkArrayElement(path, ctx, v.X, index, next)
		}
	case *ssa.Phi:
		for _, edge := range v.Edges {
			if t, s, x := checkArrayElement(path, ctx, edge, index, next); t {
				return t, s, x
			}
		}
		return false, "", nil
	case *ssa.Parameter:
		if arg, _, ok := callArgForParameterOnPath(path, v); ok {
			return checkArrayElement(path, ctx, arg, index, next)
		}
	case *ssa.UnOp:
		if v.Op == token.MUL {
			if handled, t, s, x := checkAddressedArrayElement(path, ctx, v.X, index, v, next); handled {
				return t, s, x
			}
		}
	case *ssa.Call:
		// Explicit summaries describe return taint even when an available body
		// looks clean. Preserve their contract through the regular call walk.
		if _, _, modeled := ctx.propagatorForCall(&v.Call); modeled {
			return checkSSAValueWithContext(path, ctx, v, visited.clone())
		}
		if src, ok := ctx.matchSourceCall(&v.Call); ok {
			return true, src, v.Call.Value
		}
		if handled, t, s, x := checkArrayCallElement(path, ctx, v, index, -1, next); handled {
			return t, s, x
		}
	case *ssa.Extract:
		if call, ok := v.Tuple.(*ssa.Call); ok {
			if _, _, modeled := ctx.propagatorForCall(&call.Call); modeled {
				return checkSSAValueWithContext(path, ctx, call, visited.clone())
			}
			if src, ok := ctx.matchSourceCall(&call.Call); ok {
				return true, src, call.Call.Value
			}
			if handled, t, s, x := checkArrayCallElement(path, ctx, call, index, v.Index, next); handled {
				return t, s, x
			}
		}
	}
	// Unknown/escaped memory retains the existing conservative whole-value walk.
	return checkSSAValueWithContext(path, ctx, value, visited.clone())
}

func checkArrayCallElement(path callgraphutil.Path, ctx taintContext, call *ssa.Call, index ssa.Value, resultIndex int, visited valueSet) (bool, bool, string, ssa.Value) {
	callee, summaryPath, ok := calleeSummaryPath(path, ctx, call)
	if !ok {
		return false, false, "", nil
	}
	for _, ret := range calleeReturns(callee) {
		slot := resultIndex
		if slot < 0 {
			if len(ret.Results) != 1 {
				continue
			}
			slot = 0
		}
		if slot >= len(ret.Results) {
			continue
		}
		if t, s, x := checkArrayElement(summaryPath, ctx, ret.Results[slot], index, visited); t {
			return true, t, s, x
		}
	}
	return true, false, "", nil
}

// checkAddressedArrayElement handles non-escaping local arrays only. Whole-array
// stores and selected-element stores participate in the same CFG walk so that
// either kind of overwrite can kill an earlier definition. Unknown indices may
// alias every element, but never definitely overwrite a selected slot.
func checkAddressedArrayElement(path callgraphutil.Path, ctx taintContext, base, index ssa.Value, use ssa.Instruction, visited valueSet) (bool, bool, string, ssa.Value) {
	alloc, ok := base.(*ssa.Alloc)
	if !ok {
		return false, false, "", nil
	}
	ptr, ok := types.Unalias(alloc.Type()).Underlying().(*types.Pointer)
	if !ok || !isArrayValueType(ptr.Elem()) {
		return false, false, "", nil
	}
	refs := base.Referrers()
	if refs == nil {
		return false, false, "", nil
	}
	var defs []memoryDef
	whole := map[ssa.Instruction]bool{}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.Store:
			if r.Addr != base || r.Val == base {
				return false, false, "", nil
			}
			defs = append(defs, memoryDef{instr: r, value: r.Val, definite: true})
			whole[r] = true
		case *ssa.IndexAddr:
			// Check all uses even when this is a different constant element: leaking
			// an element address can expose the array through aliases we do not model.
			if r.Referrers() == nil {
				return false, false, "", nil
			}
			for _, elementRef := range *r.Referrers() {
				switch e := elementRef.(type) {
				case *ssa.Store:
					if e.Addr != r || e.Val == r {
						return false, false, "", nil
					}
					selected, knownSelected := intConstant(index)
					written, knownWritten := intConstant(r.Index)
					if knownSelected && knownWritten && selected != written {
						continue
					}
					defs = append(defs, memoryDef{instr: e, value: e.Val, definite: knownSelected && knownWritten})
				case *ssa.UnOp:
					if e.Op != token.MUL {
						return false, false, "", nil
					}
				case *ssa.DebugRef:
				default:
					return false, false, "", nil
				}
			}
		case *ssa.UnOp:
			if r.Op != token.MUL {
				return false, false, "", nil
			}
		case *ssa.DebugRef:
		default:
			return false, false, "", nil
		}
	}
	for _, def := range reachingMemoryDefs(defs, use) {
		var t bool
		var s string
		var x ssa.Value
		if whole[def.instr] {
			t, s, x = checkArrayElement(path, ctx, def.value, index, visited.clone())
		} else {
			t, s, x = checkSSAValueWithContext(path, ctx, def.value, visited.clone())
		}
		if t {
			return true, t, s, x
		}
	}
	return true, false, "", nil
}
