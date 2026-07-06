package taint

import (
	"go/token"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// EvidenceKind identifies one step in a diagnostic explanation.
type EvidenceKind string

const (
	// EvidenceSourceMatch records where tainted data matched a configured source.
	EvidenceSourceMatch EvidenceKind = "source_match"
	// EvidenceParameterMapping records caller argument to callee parameter flow.
	EvidenceParameterMapping EvidenceKind = "parameter_mapping"
	// EvidencePropagationStep records a modeled propagation step.
	EvidencePropagationStep EvidenceKind = "propagation_step"
	// EvidenceSanitizerApplied records a value-specific sanitizer match.
	EvidenceSanitizerApplied EvidenceKind = "sanitizer_applied"
	// EvidenceSanitizerRejected records a sanitizer that did not cover the tainted value.
	EvidenceSanitizerRejected EvidenceKind = "sanitizer_rejected"
	// EvidenceSinkMatch records the dangerous callsite matched by a sink rule.
	EvidenceSinkMatch EvidenceKind = "sink_match"
	// EvidenceUnknown records conservative or unresolved modeling.
	EvidenceUnknown EvidenceKind = "unknown"
)

// Evidence is a single explainability entry for a Diagnostic.
type Evidence struct {
	Kind        EvidenceKind
	Message     string
	Rule        string
	Value       ssa.Value
	Instruction ssa.Instruction
	Edge        *callgraph.Edge
	Function    *ssa.Function
}

// Diagnostic is a taint finding plus an ordered evidence trace explaining it.
type Diagnostic struct {
	Result   Result
	Evidence []Evidence
}

// Diagnostics is a collection of detailed taint findings.
type Diagnostics []Diagnostic

// Finding is a located detector result: a source position and a message. It is
// the unit a detector reports, whether from a per-package go/analysis pass or a
// whole-program driver, so both surface identical findings.
type Finding struct {
	Pos     token.Pos
	Message string
}

// Findings turns diagnostics into located findings at each result's report
// position, dropping any without a valid position, all carrying message.
// Detectors with no result-specific suppression build their findings with it.
func (d Diagnostics) Findings(message string) []Finding {
	var out []Finding
	for _, diagnostic := range d {
		if pos := diagnostic.Result.ReportPos(); pos.IsValid() {
			out = append(out, Finding{Pos: pos, Message: message})
		}
	}
	return out
}

// Results returns the compatibility Result values from the diagnostics.
func (d Diagnostics) Results() Results {
	results := make(Results, 0, len(d))
	for _, diagnostic := range d {
		results = append(results, diagnostic.Result)
	}
	return results
}

type traceRecorder struct {
	evidence []Evidence
}

func (t *traceRecorder) add(e Evidence) {
	if t == nil {
		return
	}
	t.evidence = append(t.evidence, e)
}

func (t *traceRecorder) addAll(evidence []Evidence) {
	if t == nil || len(evidence) == 0 {
		return
	}
	t.evidence = append(t.evidence, evidence...)
}
