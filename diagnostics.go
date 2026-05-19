package taint

import (
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
