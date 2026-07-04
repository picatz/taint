package vulncheck

import (
	"fmt"

	"github.com/picatz/taint"
	"golang.org/x/tools/go/ssa"
)

// taintTrace renders a taint diagnostic's evidence into a concise, ordered list
// of the decision points that matter to a reader: where the tainted value
// entered (the source), any sanitizer that did or did not cover it, and the
// sink it reached. The intermediate propagation steps are intentionally
// omitted here because the finding's call stack already shows the path; this
// keeps the data-flow summary to a few meaningful lines rather than every
// internal edge the engine crossed.
func taintTrace(d taint.Diagnostic) []string {
	var steps []string
	for _, ev := range d.Evidence {
		if !meaningfulEvidence(ev.Kind) {
			continue
		}
		if line := evidenceLine(ev); line != "" {
			steps = append(steps, line)
		}
	}
	if len(steps) == 0 {
		// Fall back to a minimal source-to-sink summary when the evidence chain
		// carries no headline steps (defensive; CheckDetailed normally does).
		steps = append(steps,
			fmt.Sprintf("tainted by source %s", d.Result.SourceType),
			fmt.Sprintf("reaches sink %s", d.Result.SinkType),
		)
	}
	return steps
}

// meaningfulEvidence reports whether an evidence kind is a headline step worth
// showing in the condensed data-flow summary.
func meaningfulEvidence(kind taint.EvidenceKind) bool {
	switch kind {
	case taint.EvidenceSourceMatch,
		taint.EvidenceSanitizerApplied,
		taint.EvidenceSanitizerRejected,
		taint.EvidenceSinkMatch:
		return true
	default:
		return false
	}
}

// evidenceLine renders one evidence entry, prefixing the source position when
// available so a reader can jump to the location.
func evidenceLine(ev taint.Evidence) string {
	msg := ev.Message
	if msg == "" {
		msg = string(ev.Kind)
	}
	if pos := evidencePosition(ev); pos != "" {
		return pos + ": " + msg
	}
	return msg
}

// evidencePosition extracts the best source position from an evidence entry,
// preferring the instruction, then the value, then the call edge.
func evidencePosition(ev taint.Evidence) string {
	switch {
	case ev.Instruction != nil:
		return instrPos(ev.Instruction)
	case ev.Value != nil:
		return valuePos(ev.Value)
	case ev.Edge != nil && ev.Edge.Site != nil:
		return instrPos(ev.Edge.Site)
	}
	return ""
}

func instrPos(instr ssa.Instruction) string {
	if instr == nil || instr.Parent() == nil {
		return ""
	}
	pos := instr.Pos()
	if !pos.IsValid() {
		return ""
	}
	return instr.Parent().Prog.Fset.Position(pos).String()
}

func valuePos(v ssa.Value) string {
	if v == nil {
		return ""
	}
	instr, ok := v.(ssa.Instruction)
	if !ok || instr.Parent() == nil {
		return ""
	}
	pos := v.Pos()
	if !pos.IsValid() {
		return ""
	}
	return instr.Parent().Prog.Fset.Position(pos).String()
}
