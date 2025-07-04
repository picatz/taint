package taint

import (
	"fmt"

	"golang.org/x/tools/go/ssa"
)

var ErrStopWalk = fmt.Errorf("taint: stop walk")

// WalkSSA walks the SSA IR recursively with a visitor function that
// can be used to inspect each node in the graph. The visitor function
// should return an error if it wants to stop the walk.
func WalkSSA(v ssa.Value, visit func(v ssa.Value) error) error {
	visited := make(valueSet)

	return walkSSA(v, visit, visited)
}

func walkSSA(v ssa.Value, visit func(v ssa.Value) error, visited valueSet) error {
	if v == nil {
		return nil
	}

	if visited == nil {
		visited = make(valueSet)
	}

	if visited.includes(v) {
		return nil
	}

	visited.add(v)

	// fmt.Printf("walk SSA: %s: %[1]T\n", v)

	if err := visit(v); err != nil {
		return err
	}

	switch v := v.(type) {
	case *ssa.Call:
		// Check the operands of the call instruction.
		for _, opr := range v.Operands(nil) {
			if err := walkSSA(*opr, visit, visited); err != nil {
				return err
			}
		}

		// Check the arguments of the call instruction.
		for _, arg := range v.Common().Args {
			if err := walkSSA(arg, visit, visited); err != nil {
				return err
			}
		}

		// Check the function being called.
		if err := walkSSA(v.Call.Value, visit, visited); err != nil {
			return err
		}

		// Check the return value of the call instruction.
		if v.Common().IsInvoke() {
			if err := walkSSA(v.Common().Value, visit, visited); err != nil {
				return err
			}
		}

		// Check the return value of the call instruction.
		if err := walkSSA(v.Common().Value, visit, visited); err != nil {
			return err
		}
	case *ssa.ChangeInterface:
		if err := walkSSA(v.X, visit, visited); err != nil {
			return err
		}
	case *ssa.Convert:
		if err := walkSSA(v.X, visit, visited); err != nil {
			return err
		}
	case *ssa.MakeInterface:
		if err := walkSSA(v.X, visit, visited); err != nil {
			return err
		}
	case *ssa.Phi:
		for _, edge := range v.Edges {
			if err := walkSSA(edge, visit, visited); err != nil {
				return err
			}
		}
	case *ssa.UnOp:
		if err := walkSSA(v.X, visit, visited); err != nil {
			return err
		}
	case *ssa.Function:
		for _, block := range v.Blocks {
			for _, instr := range block.Instrs {
				for _, opr := range instr.Operands(nil) {
					if err := walkSSA(*opr, visit, visited); err != nil {
						return err
					}
				}
			}
		}
	default:
		// fmt.Printf("? walk SSA %s: %[1]T\n", v)
	}

	refs := v.Referrers()
	if refs == nil {
		return nil
	}

	for _, instr := range *refs {
		switch instr := instr.(type) {
		case *ssa.Store:
			// Store instructions need to be checked for both the value being stored,
			// and the address being stored to.
			if err := walkSSA(instr.Val, visit, visited); err != nil {
				return err
			}

			if err := walkSSA(instr.Addr, visit, visited); err != nil {
				return err
			}
		case *ssa.Call:
			// Check the operands of the call instruction.
			for _, opr := range instr.Operands(nil) {
				if err := walkSSA(*opr, visit, visited); err != nil {
					return err
				}
			}

			// Check the arguments of the call instruction.
			for _, arg := range instr.Common().Args {
				if err := walkSSA(arg, visit, visited); err != nil {
					return err
				}
			}

			// Check the function being called.
			if err := walkSSA(instr.Call.Value, visit, visited); err != nil {
				return err
			}

			// Check the return value of the call instruction.
			if instr.Common().IsInvoke() {
				if err := walkSSA(instr.Common().Value, visit, visited); err != nil {
					return err
				}
			}

			// Check the return value of the call instruction.
			if err := walkSSA(instr.Common().Value, visit, visited); err != nil {
				return err
			}
		default:
			// fmt.Printf("? check SSA instr %s: %[1]T\n", i)
			continue
		}
	}

	return nil
}
