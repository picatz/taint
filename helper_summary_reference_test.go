package taint

import "golang.org/x/tools/go/ssa"

// Legacy path materialization is retained only as a bounded test oracle.
type mapPathState struct {
	writes []sideEffectValue
	killed bool
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
