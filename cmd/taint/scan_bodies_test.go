package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/picatz/taint/internal/wholeprogram"
)

func TestScanBodiesValidationBeforeLoad(t *testing.T) {
	cases := []struct {
		name  string
		flags []string
		want  string
	}{
		{"unknown", []string{"-bodies=all"}, "unknown -bodies"},
		{"implicit legacy", []string{"-bodies=same-module", "-max-body-packages=1", "-max-body-syntax-bytes=110"}, "requires -scope=selected"},
		{"explicit legacy", []string{"-scope=legacy", "-bodies=same-module"}, "requires -scope=selected"},
		{"missing limits", []string{"-scope=selected", "-bodies=same-module"}, "requires explicit positive"},
		{"missing bytes", []string{"-scope=selected", "-bodies=same-module", "-max-body-packages=1"}, "requires explicit positive"},
		{"missing packages", []string{"-scope=selected", "-bodies=same-module", "-max-body-syntax-bytes=110"}, "requires explicit positive"},
		{"negative packages", []string{"-scope=selected", "-bodies=same-module", "-max-body-packages=-1", "-max-body-syntax-bytes=110"}, "requires explicit positive"},
		{"negative bytes", []string{"-scope=selected", "-bodies=same-module", "-max-body-packages=1", "-max-body-syntax-bytes=-1"}, "requires explicit positive"},
		{"zero packages", []string{"-scope=selected", "-bodies=same-module", "-max-body-packages=0", "-max-body-syntax-bytes=110"}, "requires explicit positive"},
		{"zero bytes", []string{"-scope=selected", "-bodies=same-module", "-max-body-packages=1", "-max-body-syntax-bytes=0"}, "requires explicit positive"},
		{"ineffective packages", []string{"-max-body-packages=1"}, "requires zero"},
		{"ineffective bytes", []string{"-bodies=selected", "-max-body-syntax-bytes=110"}, "requires zero"},
		{"negative selected limit", []string{"-max-body-packages=-1"}, "requires zero"},
		{"malformed packages", []string{"-max-body-packages=oops"}, "invalid value"},
		{"overflow bytes", []string{"-max-body-syntax-bytes=9223372036854775808"}, "invalid value"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			args := append(append([]string(nil), tt.flags...), "-C=/does/not/exist")
			code := runScan(context.Background(), args, &out, &stderr)
			if code != scanExitError || out.Len() != 0 || !strings.Contains(stderr.String(), tt.want) || strings.Contains(stderr.String(), "loading packages") {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, &out, &stderr)
			}
		})
	}
}

func TestWriteSelectedBodyCoverageUnchanged(t *testing.T) {
	var out bytes.Buffer
	writeBodyCoverage(&out, wholeprogram.BodyCoverage{
		SelectedPackages:              []string{"example.com/a/caller"},
		SameModuleDependencies:        []string{"example.com/a/helper"},
		SelectedWithoutModuleIdentity: []string{"example.com/a/caller"},
		OtherDependencies:             3,
	})
	want := "taint scan: SSA bodies are built only for 1 selected package(s); 1 same-module dependency package(s) have no source bodies built.\n" +
		"taint scan: cannot classify same-module dependencies for 1 selected package(s) without complete module identity.\n" +
		"  unbuilt same-module dependency: example.com/a/helper\n" +
		"taint scan: 3 other dependency package(s) (including standard library or unknown module identity); dependency bodies are not built. This is package coverage, not a completeness guarantee.\n"
	if out.String() != want {
		t.Fatalf("coverage changed:\n%s", &out)
	}
}

func TestWriteSameModuleBodyCoverage(t *testing.T) {
	var out bytes.Buffer
	writeSameModuleBodyCoverage(&out, wholeprogram.BodyCoverage{
		SelectedPackages:            []string{"example.com/a/caller"},
		SameModuleDependencies:      []string{"example.com/a/helper"},
		BuiltSameModuleDependencies: []string{"example.com/a/helper"},
		AdditionalSyntaxBytes:       110, OtherDependencies: 3,
	}, wholeprogram.BodyLimits{MaxAdditionalPackages: 1, MaxAdditionalSyntaxBytes: 110})
	for _, want := range []string{"scope=selected; bodies=same-module", "1 selected package(s), 1 built", "0 omitted eligible", "packages=1/1; parsed syntax bytes=110/110", "selected body input: example.com/a/caller", "built same-module dependency: example.com/a/helper", "3 other dependency package(s) excluded", "not a completeness guarantee", "not RSS", "cancellation cannot promptly interrupt"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q: %s", want, &out)
		}
	}
	if strings.Contains(out.String(), "unbuilt same-module") {
		t.Fatal(out.String())
	}
}

func TestScanSameModuleCoverageDoesNotChangeFindings(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir, err := filepath.Abs("../../internal/wholeprogram/testdata/bodycoverage")
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"text", "json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			args := []string{"-C", dir, "-scope=selected", "-bodies=same-module", "-max-body-packages=1", "-max-body-syntax-bytes=110", "-analyzers=sqli", "-format=" + format}
			var plain, covered, plainErr, coveredErr bytes.Buffer
			code := runScan(context.Background(), append(append([]string(nil), args...), "./caller"), &plain, &plainErr)
			coveredCode := runScan(context.Background(), append(args, "-coverage", "./caller"), &covered, &coveredErr)
			if code != scanExitFindings || coveredCode != code || plain.String() != covered.String() {
				t.Fatalf("code=%d/%d stdout=%s/%s stderr=%s/%s", code, coveredCode, &plain, &covered, &plainErr, &coveredErr)
			}
			if format != "text" && !json.Valid(plain.Bytes()) {
				t.Fatalf("invalid JSON: %s", &plain)
			}
			if strings.Contains(plainErr.String(), "bodies=same-module") || !strings.Contains(coveredErr.String(), "built same-module dependency: example.com/bodycoverage/helper") || !strings.Contains(coveredErr.String(), "parsed syntax bytes=110/110") {
				t.Fatalf("bad coverage diagnostics: %s / %s", &plainErr, &coveredErr)
			}
			var rejected, rejectedErr bytes.Buffer
			under := append(append([]string(nil), args...), "-max-body-syntax-bytes=109", "./caller")
			if rejectedCode := runScan(context.Background(), under, &rejected, &rejectedErr); rejectedCode != scanExitError || rejected.Len() != 0 {
				t.Fatalf("under-budget code=%d stdout=%s stderr=%s", rejectedCode, &rejected, &rejectedErr)
			}
		})
	}
}
