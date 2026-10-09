package taint

import (
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// mapRangeEvent keeps keys and values separate. A range evaluates the map
// identity once, but reads its contents at each Next, not at Range or the sink.
// Looking through all map referrers would conflate components, resurrect dead
// entries, and let later writes taint already-extracted scalar copies.
type mapRangeEvent struct {
	instr       ssa.Instruction
	index       int
	mapv        ssa.Value
	key         ssa.Value
	value       ssa.Value // nil for delete, clear, or allocation
	clear       bool
	constantKey string
	keyKnown    bool
	keyType     types.Type
}

type mapRangeCursor struct {
	block      *ssa.BasicBlock
	index      int
	keyChanged bool
	mapChanged bool
}

func reachingMapRangeValues(mapv ssa.Value, use ssa.Instruction, component int) []ssa.Value {
	if mapv == nil || use == nil || use.Parent() == nil || use.Block() == nil || (component != 1 && component != 2) {
		return nil
	}
	// The event index is local to this read. No process-wide SSA caches or
	// execution-path enumeration are needed, including for loop backedges.
	events := make(map[ssa.Instruction]mapRangeEvent)
	var writes []mapRangeEvent
	for _, block := range use.Parent().Blocks {
		for index, instr := range block.Instrs {
			var event mapRangeEvent
			switch v := instr.(type) {
			case *ssa.MapUpdate:
				event = mapRangeEvent{instr: instr, mapv: v.Map, key: v.Key, value: v.Value}
			case *ssa.MakeMap:
				// Reexecuting a loop-local allocation creates a new map; writes
				// to its previous dynamic instance cannot survive that point.
				if !mapRangeMustAlias(v, mapv) {
					// A Phi may retain an older dynamic instance even when
					// this allocation executes again (for example a saved map).
					continue
				}
				event = mapRangeEvent{instr: instr, mapv: v, clear: true}
			case *ssa.Call:
				builtin, ok := v.Call.Value.(*ssa.Builtin)
				if !ok || len(v.Call.Args) == 0 {
					continue
				}
				switch builtin.Name() {
				case "delete":
					if len(v.Call.Args) != 2 {
						continue
					}
					event = mapRangeEvent{instr: instr, mapv: v.Call.Args[0], key: v.Call.Args[1]}
				case "clear":
					event = mapRangeEvent{instr: instr, mapv: v.Call.Args[0], clear: true}
				default:
					continue
				}
			default:
				continue
			}
			if !mapRangeMayAlias(event.mapv, mapv) {
				continue
			}
			event.mapv = mapRangeIdentity(event.mapv)
			event.index = index
			event.constantKey, event.keyType, event.keyKnown = mapRangeConstantKey(event.key)
			events[instr] = event
			if event.value != nil {
				writes = append(writes, event)
			}
		}
	}
	var out []ssa.Value
	seenValues := make(map[ssa.Value]bool)
	scratch := mapRangeWork{seen: make([]uint8, len(use.Parent().Blocks))}
	for _, write := range writes {
		if !scratch.reaches(write, use, events) {
			continue
		}
		value := write.value
		if component == 1 {
			value = write.key
		}
		if value != nil && !seenValues[value] {
			seenValues[value] = true
			out = append(out, value)
		}
	}
	return out
}

// mapRangeWork.reaches is a may-flow query: any finite CFG path from this
// write to the read without a definite kill suffices. A visited instruction
// cursor, rather than a visited execution path, bounds work to O(I + E) per
// candidate and O(W * (I + E)) per read. The initial partial block and a later
// whole-block visit are distinct, so textually later loop writes are included.
type mapRangeWork struct {
	seen    []uint8
	cursors []mapRangeCursor
}

func (scratch *mapRangeWork) reaches(write mapRangeEvent, use ssa.Instruction, events map[ssa.Instruction]mapRangeEvent) bool {
	clear(scratch.seen)
	scratch.cursors = append(scratch.cursors[:0], mapRangeCursor{block: write.instr.Block(), index: write.index + 1})
	// Successor cursors always enter at instruction zero. The single
	// initial partial block needs no visited slot; four bits per full block
	// cover the key/map dynamic-identity states without per-state maps.
	seen := scratch.seen
	keyInstr, _ := write.key.(ssa.Instruction)
	mapInstr, _ := mapRangeIdentity(write.mapv).(ssa.Instruction)
	reflexiveKey := write.key != nil && mapRangeReflexiveKey(write.key.Type())
	for len(scratch.cursors) > 0 {
		cursor := scratch.cursors[len(scratch.cursors)-1]
		scratch.cursors = scratch.cursors[:len(scratch.cursors)-1]
		if cursor.block == nil {
			continue
		}
		if cursor.index == 0 {
			state := uint8(0)
			if cursor.keyChanged {
				state |= 1
			}
			if cursor.mapChanged {
				state |= 2
			}
			mask := uint8(1 << state)
			if seen[cursor.block.Index]&mask != 0 {
				continue
			}
			seen[cursor.block.Index] |= mask
		}
		killed := false
		for _, instr := range cursor.block.Instrs[cursor.index:] {
			if instr == use {
				return true
			}
			if instr == keyInstr {
				// The same SSA key can denote a different runtime value on
				// the next loop iteration. Constant keys remain comparable.
				cursor.keyChanged = true
			}
			if instr == mapInstr {
				cursor.mapChanged = true
			}
			event, ok := events[instr]
			_, allocation := instr.(*ssa.MakeMap)
			if !ok || (cursor.mapChanged && !allocation) || !mapRangeMustAlias(event.mapv, write.mapv) {
				continue
			}
			sameKey := event.keyKnown && write.keyKnown && event.constantKey == write.constantKey && types.Identical(event.keyType, write.keyType)
			if !cursor.keyChanged && event.key == write.key && reflexiveKey {
				sameKey = true
			}
			if event.clear || sameKey {
				killed = true
				break
			}
		}
		if !killed {
			for i := len(cursor.block.Succs) - 1; i >= 0; i-- {
				scratch.cursors = append(scratch.cursors, mapRangeCursor{block: cursor.block.Succs[i], keyChanged: cursor.keyChanged, mapChanged: cursor.mapChanged})
			}
		}
	}
	return false
}

// Only representation-preserving wrappers establish definite map identity.
// Do not peel loads/fields to their allocation: distinct map-valued fields in
// one object are not the same map. Different Phi alternatives only may alias;
// identical Phi values name the same runtime map until their definition is
// reexecuted, which the candidate worklist tracks separately.
func mapRangeIdentity(value ssa.Value) ssa.Value {
	for {
		switch v := value.(type) {
		case *ssa.ChangeType:
			value = v.X
		case *ssa.Convert:
			value = v.X
		case *ssa.MakeInterface:
			value = v.X
		case *ssa.ChangeInterface:
			value = v.X
		case *ssa.TypeAssert:
			value = v.X
		case *ssa.Extract:
			if assertion, ok := v.Tuple.(*ssa.TypeAssert); ok && v.Index == 0 {
				value = assertion.X
				continue
			}
			return value
		default:
			return value
		}
	}
}

func mapRangeMustAlias(a, b ssa.Value) bool {
	a, b = mapRangeIdentity(a), mapRangeIdentity(b)
	if a == nil || a != b {
		return false
	}
	return true
}

func mapRangeMayAlias(a, b ssa.Value) bool {
	a, b = mapRangeIdentity(a), mapRangeIdentity(b)
	if a == b {
		return a != nil
	}
	_, aPhi := a.(*ssa.Phi)
	_, bPhi := b.(*ssa.Phi)
	if !aPhi && !bPhi {
		return false
	}
	roots := func(value ssa.Value) map[ssa.Value]bool {
		seen := make(map[ssa.Value]bool)
		var work = []ssa.Value{value}
		for len(work) > 0 {
			v := mapRangeIdentity(work[len(work)-1])
			work = work[:len(work)-1]
			if v == nil || seen[v] {
				continue
			}
			seen[v] = true
			if phi, ok := v.(*ssa.Phi); ok {
				work = append(work, phi.Edges...)
			}
		}
		return seen
	}
	aroots := roots(a)
	for root := range roots(b) {
		if aroots[root] {
			return true
		}
	}
	return false
}

// Identity proves equality only for reflexive types. Floating-point NaNs also
// make enclosing arrays/structs and interfaces potentially unequal to themselves.
func mapRangeReflexiveKey(t types.Type) bool {
	switch t := t.Underlying().(type) {
	case *types.Basic:
		return t.Info()&(types.IsBoolean|types.IsInteger|types.IsString) != 0
	case *types.Pointer, *types.Chan:
		return true
	case *types.Array:
		return mapRangeReflexiveKey(t.Elem())
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if !mapRangeReflexiveKey(t.Field(i).Type()) {
				return false
			}
		}
		return true
	}
	return false
}

// A range copies a pointer, not its pointee. Preserve the actual dereference
// position when following a directly extracted pointer to a local allocation.
// Falling back to allocation referrers would include stores after this load and
// miss intervening clean overwrites. General heap/helper pointees retain the
// existing engine's limitations; no synthetic SSA load is manufactured here.
func reachingMapRangePointeeValues(load *ssa.UnOp) ([]ssa.Value, bool) {
	extract, ok := mapRangeIdentity(load.X).(*ssa.Extract)
	if !ok {
		return nil, false
	}
	next, ok := extract.Tuple.(*ssa.Next)
	if !ok || next.IsString {
		return nil, false
	}
	iter, ok := next.Iter.(*ssa.Range)
	if !ok {
		return nil, false
	}
	pointers := reachingMapRangeValues(iter.X, next, extract.Index)
	for _, pointer := range pointers {
		if alloc, ok := mapRangeIdentity(pointer).(*ssa.Alloc); !ok || alloc.Parent() != load.Parent() || alloc.Block() != load.Parent().Blocks[0] {
			return nil, false
		}
	}
	if mapRangePointeeEscapes(append(append([]ssa.Value(nil), pointers...), extract), extract) {
		return nil, false
	}
	var values []ssa.Value
	seenValues := make(map[ssa.Value]bool)
	for _, pointer := range pointers {
		pointer = mapRangeIdentity(pointer)
		work := []mapRangeCursor{{block: load.Block(), index: blockScanStart(load.Block(), load)}}
		seen := make(map[mapRangeCursor]bool)
		for len(work) > 0 {
			cursor := work[len(work)-1]
			work = work[:len(work)-1]
			if cursor.block == nil || seen[cursor] {
				continue
			}
			seen[cursor] = true
			stop := false
			for i := cursor.index - 1; i >= 0; i-- {
				instr := cursor.block.Instrs[i]
				if instr == extract {
					cursor.keyChanged = true
				}
				if instr == pointer.(ssa.Instruction) {
					stop = true
					break
				}
				store, ok := instr.(*ssa.Store)
				if !ok {
					continue
				}
				addr := mapRangeIdentity(store.Addr)
				if addr != pointer && addr != extract {
					continue
				}
				if !seenValues[store.Val] {
					seenValues[store.Val] = true
					values = append(values, store.Val)
				}
				// Before crossing its definition, a store through this
				// extraction definitely overwrites this exact dereference.
				// Older iterations may have extracted a different pointer.
				if addr == pointer || !cursor.keyChanged {
					stop = true
					break
				}
			}
			if !stop {
				for _, pred := range cursor.block.Preds {
					work = append(work, mapRangeCursor{block: pred, index: len(pred.Instrs), keyChanged: cursor.keyChanged})
				}
			}
		}
	}
	return values, true
}

// Keep dynamic interface key types: int(1), int64(1), and a named int are
// distinct entries even though their constant values print identically. Do not
// invoke the general constant resolver here: its loads/helper/Phi traversal is
// outside this local model and would lose both identity and the work bound.
func mapRangeConstantKey(value ssa.Value) (string, types.Type, bool) {
	for {
		switch v := value.(type) {
		case *ssa.MakeInterface:
			value = v.X
		case *ssa.ChangeInterface:
			value = v.X
		case *ssa.Const:
			if v.Value != nil {
				return v.Value.Kind().String() + ":" + v.Value.ExactString(), v.Type(), true
			}
			return "", nil, false
		default:
			return "", nil, false
		}
	}
}

// Limit the pointee fast path to a closed set of local uses. In particular,
// storing pointers in maps must not hide escapes through another alias, helper,
// closure, or container. On an unknown use retain the existing pointer walk.
func mapRangePointeeEscapes(work []ssa.Value, extract *ssa.Extract) bool {
	seen := make(map[ssa.Value]bool)
	for len(work) > 0 {
		value := work[len(work)-1]
		work = work[:len(work)-1]
		if value == nil || seen[value] {
			continue
		}
		seen[value] = true
		refs := value.Referrers()
		if refs == nil {
			continue
		}
		for _, ref := range *refs {
			switch v := ref.(type) {
			case *ssa.DebugRef:
			case *ssa.Store:
				if v.Addr != value {
					return true
				}
			case *ssa.UnOp:
				// Reading a scalar pointee does not expose its address.
				switch v.Type().Underlying().(type) {
				case *types.Basic:
				default:
					return true
				}
			case *ssa.MapUpdate:
				work = append(work, v.Map)
			case *ssa.ChangeType:
				work = append(work, v)
			case *ssa.MakeInterface:
				work = append(work, v)
			case *ssa.ChangeInterface:
				work = append(work, v)
			case *ssa.TypeAssert:
				work = append(work, v)
			case *ssa.Range:
				work = append(work, v)
			case *ssa.Next:
				work = append(work, v)
			case *ssa.Extract:
				if _, pointer := v.Type().Underlying().(*types.Pointer); pointer {
					if v != extract {
						return true
					}
					work = append(work, v)
				}
			case *ssa.Call:
				builtin, ok := v.Call.Value.(*ssa.Builtin)
				if !ok {
					return true
				}
				switch builtin.Name() {
				case "delete", "clear", "len":
				default:
					return true
				}
			default:
				return true
			}
		}
	}
	return false
}
