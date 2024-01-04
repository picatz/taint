package callgraphutil

import (
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// InstructionsFor returns the ssa.Instruction for the given ssa.Value using
// the given node as the root of the call graph that is searched.
func InstructionsFor(root *callgraph.Node, v ssa.Value) (si ssa.Instruction) {
	PathsSearch(root, func(n *callgraph.Node) bool {
		for _, b := range root.Func.Blocks {
			for _, instr := range b.Instrs {
				if instr.Pos() == v.Pos() {
					si = instr
					return true
				}
			}
		}
		return false
	})
	return
}
