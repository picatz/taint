package taint

import (
	"fmt"
	"go/constant"
	"go/types"
	"math/rand/v2"
	"reflect"
	"testing"

	"golang.org/x/tools/go/ssa"
)

func helperSummaryFiniteReduce(events []mapEvent, use ssa.Instruction) ([]sideEffectValue, bool) {
	ret, _ := use.(*ssa.Return)
	return summarizeMapPaths(events, []*ssa.Return{ret})
}

func helperSummaryLegacyReduce(events []mapEvent, use ssa.Instruction) ([]sideEffectValue, bool) {
	states := collectMapPathStates(events, use)
	killed := len(states) > 0
	var writes []sideEffectValue
	for _, s := range states {
		writes = append(writes, s.writes...)
		killed = killed && s.killed
	}
	return dedupeSideEffectValues(writes), killed
}

func TestHelperMapFiniteReductionDifferential(t *testing.T) {
	cg, _ := detailedGraphForSource(t, helperSummaryProgram("Diamonds", 2))
	fn, _, _ := helperSummaryQueries(cg)
	ret := calleeReturns(fn)[0]
	random := rand.New(rand.NewPCG(69, 10000))
	// These tiny abstract CFGs deliberately include joins, self-loops, cycles,
	// duplicate edges, multiple effects at an instruction and kill/write ties.
	// They exercise collector semantics only; do not execute or reanalyze them.
	values := []ssa.Value{fn.Params[1], ssa.NewConst(constant.MakeString("a"), types.Typ[types.String]), ssa.NewConst(constant.MakeString("b"), types.Typ[types.String])}
	calls := []*ssa.Call{nil, {}, {}}
	callees := []*ssa.Function{nil, fn, {}}
	values = append(values, nil)
	for n := 0; n < 10000; n++ {
		var events []mapEvent
		for _, block := range fn.Blocks {
			block.Preds = nil
			for j := 0; j < random.IntN(3); j++ {
				block.Preds = append(block.Preds, fn.Blocks[random.IntN(len(fn.Blocks))])
			}
			for _, instr := range block.Instrs {
				for j := 0; j < random.IntN(3); j++ {
					event := mapEvent{instr: instr, matches: random.IntN(2) == 0, definite: random.IntN(2) == 0}
					if random.IntN(4) == 0 {
						event.kind = mapEventKill
					} else {
						event.kind = mapEventWrite
						for k := 0; k < random.IntN(4); k++ {
							event.values = append(event.values, sideEffectValue{value: values[random.IntN(len(values))], call: calls[random.IntN(len(calls))], callee: callees[random.IntN(len(callees))], definite: random.IntN(2) == 0})
						}
					}
					events = append(events, event)
				}
			}
		}
		wantWrites, wantKill := helperSummaryLegacyReduce(events, ret)
		gotWrites, gotKill := helperSummaryFiniteReduce(events, ret)
		if !reflect.DeepEqual(wantWrites, gotWrites) || wantKill != gotKill {
			t.Fatalf("case %d: legacy (%#v,%v) finite (%#v,%v)", n, wantWrites, wantKill, gotWrites, gotKill)
		}
	}
	t.Log("10000 bounded, fixed-seed abstract CFG/event combinations match legacy ordered effects and all-path kill")
}

var helperSummaryReductionWrites []sideEffectValue
var helperSummaryReductionKill bool

func BenchmarkHelperMapCollectorReduction(b *testing.B) {
	for _, n := range []int{2, 4, 8, 12} {
		for _, method := range []string{"Legacy", "Finite"} {
			b.Run(fmt.Sprintf("%s/%d", method, n), func(b *testing.B) {
				cg, _ := buildBenchCallGraph(b, helperSummaryProgram("Diamonds", n))
				fn, call, lookup := helperSummaryQueries(cg)
				events := helperSummaryEvents(fn, call, lookup)
				ret := calleeReturns(fn)[0]
				wantWrites, wantKill := helperSummaryLegacyReduce(events, ret)
				reduce := helperSummaryLegacyReduce
				if method == "Finite" {
					reduce = helperSummaryFiniteReduce
				}
				b.ReportAllocs()
				for b.Loop() {
					helperSummaryReductionWrites, helperSummaryReductionKill = reduce(events, ret)
				}
				if !reflect.DeepEqual(wantWrites, helperSummaryReductionWrites) || wantKill != helperSummaryReductionKill {
					b.Fatal("reduction differs")
				}
			})
		}
	}
}

func helperSummaryLegacyReturns(events []mapEvent, returns []*ssa.Return) ([]sideEffectValue, bool) {
	var writes []sideEffectValue
	killed := len(returns) > 0
	for _, ret := range returns {
		if ret == nil {
			killed = false
			continue
		}
		values, kill := helperSummaryLegacyReduce(events, ret)
		writes = append(writes, values...)
		killed = killed && kill
	}
	return dedupeSideEffectValues(writes), killed
}

func TestHelperMapValidSSADifferential(t *testing.T) {
	for _, body := range []string{
		`m["q"] = value`,
		`m["q"] = value; m["q"] = "safe"`,
		`if flag() { m["q"] = value } else { m["q"] = "safe" }`,
		`if flag() { m["q"] = value; return }; m["q"] = "safe"`,
		`if flag() { clear(m); return }; delete(m, "q")`,
		`if flag() { clear(m); return }; m["q"] = value`,
		`m["q"] = value; if flag() { delete(m, "q") }`,
		`m["q"] = value; if flag() { delete(m, "other") }`,
		`for flag() { m["q"] = value }`,
		`for flag() { m["q"] = value; if flag() { break }; clear(m) }`,
		`m["q"] = value; for flag() { if flag() { continue }; clear(m) }`,
		`for flag() { if flag() { m["q"] = value; return }; clear(m) }; delete(m, "q")`,
		`for flag() { for flag() { m["q"] = value }; if flag() { return } }`,
		`m["q"] = value; switch { case flag(): clear(m); case flag(): delete(m, "q"); default: return }`,
		`again: m["q"] = value; if flag() { goto again }; if flag() { clear(m) }`,
		`inner(m, value); if flag() { clear(m); return }; m["q"] = "safe"`,
		`inner(m, value); inner(m, "safe")`,
	} {
		t.Run(body, func(t *testing.T) {
			src := `package main
func source() string { return "user" }; func sink(string) {}; var unknown bool; func flag() bool { return unknown }
func inner(m map[string]string, value string) { if flag() { m["q"] = value } else { clear(m) } }
func helper(m map[string]string, value string) { ` + body + ` }
func main() { m := make(map[string]string); helper(m, source()); sink(m["q"]) }`
			cg, pkg := detailedGraphForSource(t, src)
			fn, call, lookup := helperSummaryQueries(cg)
			events, returns := helperSummaryEvents(fn, call, lookup), calleeReturns(fn)
			want, wantKill := helperSummaryLegacyReturns(events, returns)
			got, gotKill := summarizeMapPaths(events, returns)
			if !reflect.DeepEqual(want, got) || wantKill != gotKill {
				t.Fatalf("legacy (%#v,%v), finite (%#v,%v)", want, wantKill, got, gotKill)
			}
			// Compare the complete caller-facing projection as well. Values
			// with distinct metadata are deduped before weakening/remapping.
			for i := range want {
				want[i].call = call
				want[i].callee = fn
				want[i].definite = false
			}
			var expected []mapEvent
			if len(want) > 0 {
				expected = append(expected, mapEvent{kind: mapEventWrite, instr: call, values: want, matches: true})
			}
			if wantKill {
				expected = append(expected, mapEvent{kind: mapEventKill, instr: call, matches: true, definite: true})
			}
			if actual := directCalleeMapEventsWithLimit(call, lookup, 8); !reflect.DeepEqual(expected, actual) {
				t.Fatalf("caller projection: want %#v, got %#v", expected, actual)
			}
			diagnostics := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"))
			if !reflect.DeepEqual(diagnostics, CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"))) {
				t.Fatal("diagnostics/evidence changed on repeated query")
			}
		})
	}
}

func TestHelperMapEmptyReduction(t *testing.T) {
	for _, returns := range [][]*ssa.Return{nil, {nil}, {{}}} {
		if writes, killed := summarizeMapPaths(nil, returns); len(writes) != 0 || killed {
			t.Fatal("empty reduction should be un-killed")
		}
		if writes, killed := summarizeMapPaths([]mapEvent{{kind: mapEventKill, definite: true}}, returns); len(writes) != 0 || killed {
			t.Fatal("missing return block should be un-killed")
		}
	}
}

// These intentionally abstract cursor graphs isolate boundaries that random
// cases also cover. They are never executed or passed back to SSA analysis.
func TestHelperMapCursorBoundaries(t *testing.T) {
	cg, _ := detailedGraphForSource(t, helperSummaryProgram("Diamonds", 0))
	fn, call, _ := helperSummaryQueries(cg)
	ret := calleeReturns(fn)[0]
	root := ret.Block()
	for _, name := range []string{"killed_shared_join", "cycle", "killed_cycle", "weak_kill", "nil_predecessor", "kill_then_write_tie", "write_then_kill_tie", "before_and_end", "multiple_repeated_returns", "metadata_before_remapping"} {
		t.Run(name, func(t *testing.T) {
			pre, post := &ssa.Call{}, &ssa.Call{}
			root.Instrs = []ssa.Instruction{pre, ret, post}
			a, b, c := &ssa.BasicBlock{}, &ssa.BasicBlock{}, &ssa.BasicBlock{}
			ai, bi, ci := &ssa.Call{}, &ssa.Call{}, &ssa.Call{}
			a.Instrs, b.Instrs, c.Instrs = []ssa.Instruction{ai}, []ssa.Instruction{bi}, []ssa.Instruction{ci}
			root.Preds, a.Preds, b.Preds = []*ssa.BasicBlock{a, b}, []*ssa.BasicBlock{c}, []*ssa.BasicBlock{c}
			value := sideEffectValue{value: fn.Params[1]}
			write := func(instr ssa.Instruction) mapEvent {
				return mapEvent{kind: mapEventWrite, instr: instr, values: []sideEffectValue{value}}
			}
			kill := func(instr ssa.Instruction, definite bool) mapEvent {
				return mapEvent{kind: mapEventKill, instr: instr, definite: definite}
			}
			events := []mapEvent{write(pre), write(ai), write(bi), write(ci)}
			returns := []*ssa.Return{ret}
			wantKill := false
			switch name {
			case "killed_shared_join":
				events = append(events, kill(ci, true))
				wantKill = true
			case "cycle", "killed_cycle":
				root.Preds, a.Preds, b.Preds = []*ssa.BasicBlock{a}, []*ssa.BasicBlock{b}, []*ssa.BasicBlock{a}
				if name == "killed_cycle" {
					events = append(events, kill(bi, true))
					wantKill = true
				}
			case "weak_kill":
				events = append(events, kill(ci, false))
			case "nil_predecessor":
				root.Preds = []*ssa.BasicBlock{nil}
			case "kill_then_write_tie":
				events = []mapEvent{kill(pre, true), write(pre)}
				wantKill = true
			case "write_then_kill_tie":
				events = []mapEvent{write(pre), kill(pre, true)}
				wantKill = true
			case "before_and_end":
				root.Preds = []*ssa.BasicBlock{root}
				events = []mapEvent{write(pre), {kind: mapEventWrite, instr: post, values: []sideEffectValue{{value: nil}}}, kill(post, true)}
				wantKill = true
			case "multiple_repeated_returns":
				returns = []*ssa.Return{ret, ret, ret}
			case "metadata_before_remapping":
				events = []mapEvent{{kind: mapEventWrite, instr: pre, values: []sideEffectValue{value, {value: value.value, call: call}, {value: value.value, callee: fn}, {value: value.value, definite: true}, value}}}
			}
			want, legacyKill := helperSummaryLegacyReturns(events, returns)
			got, gotKill := summarizeMapPaths(events, returns)
			if legacyKill != wantKill {
				t.Fatalf("bad fixture: kill %v, want %v", legacyKill, wantKill)
			}
			if !reflect.DeepEqual(want, got) || gotKill != wantKill {
				t.Fatalf("want (%#v,%v), got (%#v,%v)", want, wantKill, got, gotKill)
			}
			if name == "metadata_before_remapping" && len(got) != 4 {
				t.Fatalf("lost metadata distinctions: %#v", got)
			}
			if (name == "kill_then_write_tie" || name == "write_then_kill_tie") && len(got) != 1 {
				t.Fatal("lost tied write")
			}
			if name == "before_and_end" && len(got) != 2 {
				t.Fatal("lost end-cursor write")
			}
		})
	}
}
