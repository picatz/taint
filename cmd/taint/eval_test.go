package main

import (
	"bufio"
	"bytes"
	"context"
	"strings"
	"testing"
)

// fakeEvalCommand returns a commands list with one command that records the
// positional args and flags it was invoked with, for testing eval's parsing.
func fakeEvalCommand(invoked *bool, gotArgs *[]string, gotFlags *map[string]string) commands {
	return commands{{
		name: "fake",
		desc: "test command",
		args: []*commandArg{{name: "target", desc: "a target"}},
		flags: []*commandFlag{
			{name: "min", desc: "a string flag"},
			{name: "full", desc: "a boolean flag", boolean: true},
		},
		fn: func(_ context.Context, _ *bufio.Writer, args []string, flags map[string]string) error {
			*invoked = true
			*gotArgs = args
			*gotFlags = flags
			return nil
		},
	}}
}

// TestEvalRegistersDeclaredFlags pins the fix for command flags that were
// never registered on the FlagSet: any flag either killed the shell (before
// the positional args) or was silently ignored (after them).
func TestEvalRegistersDeclaredFlags(t *testing.T) {
	tests := []struct {
		input    string
		wantArgs []string
		wantMin  string
		wantFull string
	}{
		{"fake --min taint ./x", []string{"./x"}, "taint", ""},
		{"fake ./x --min taint", []string{"./x"}, "taint", ""},
		{"fake --min=taint ./x", []string{"./x"}, "taint", ""},
		{"fake --full ./x", []string{"./x"}, "", "true"},
		{"fake ./x --full", []string{"./x"}, "", "true"},
		{"fake ./x --full --min taint", []string{"./x"}, "taint", "true"},
	}
	for _, tt := range tests {
		var (
			invoked  bool
			gotArgs  []string
			gotFlags map[string]string
		)
		cmds := fakeEvalCommand(&invoked, &gotArgs, &gotFlags)
		var out bytes.Buffer
		bt := bufio.NewWriter(&out)

		if err := cmds.eval(context.Background(), bt, tt.input); err != nil {
			t.Errorf("eval(%q) returned error: %v", tt.input, err)
			continue
		}
		if !invoked {
			t.Errorf("eval(%q) did not invoke the command; output: %s", tt.input, out.String())
			continue
		}
		if len(gotArgs) != len(tt.wantArgs) || (len(gotArgs) > 0 && gotArgs[0] != tt.wantArgs[0]) {
			t.Errorf("eval(%q) args = %v, want %v", tt.input, gotArgs, tt.wantArgs)
		}
		if gotFlags["min"] != tt.wantMin {
			t.Errorf("eval(%q) flags[min] = %q, want %q", tt.input, gotFlags["min"], tt.wantMin)
		}
		if gotFlags["full"] != tt.wantFull {
			t.Errorf("eval(%q) flags[full] = %q, want %q", tt.input, gotFlags["full"], tt.wantFull)
		}
	}
}

// TestEvalDashDashTerminator pins that tokens after "--" stay positional.
func TestEvalDashDashTerminator(t *testing.T) {
	var (
		invoked  bool
		gotArgs  []string
		gotFlags map[string]string
	)
	cmds := fakeEvalCommand(&invoked, &gotArgs, &gotFlags)
	var out bytes.Buffer
	bt := bufio.NewWriter(&out)

	if err := cmds.eval(context.Background(), bt, "fake -- --full ./x"); err != nil {
		t.Fatalf("eval returned error: %v", err)
	}
	if !invoked {
		t.Fatalf("command not invoked; output: %s", out.String())
	}
	if len(gotArgs) != 2 || gotArgs[0] != "--full" || gotArgs[1] != "./x" {
		t.Errorf("args = %v, want [--full ./x] (everything after -- is positional)", gotArgs)
	}
	if gotFlags["full"] != "" {
		t.Errorf("flags[full] = %q, want unset", gotFlags["full"])
	}
}

// TestEvalTrailingValuelessFlag pins that a string flag with no value errors
// like the flag package instead of consuming a preceding positional.
func TestEvalTrailingValuelessFlag(t *testing.T) {
	var (
		invoked  bool
		gotArgs  []string
		gotFlags map[string]string
	)
	cmds := fakeEvalCommand(&invoked, &gotArgs, &gotFlags)
	var out bytes.Buffer
	bt := bufio.NewWriter(&out)

	if err := cmds.eval(context.Background(), bt, "fake ./x --min"); err != nil {
		t.Fatalf("eval returned error (shell-fatal): %v", err)
	}
	if invoked {
		t.Errorf("command invoked despite valueless --min; args=%v flags=%v", gotArgs, gotFlags)
	}
	if !strings.Contains(out.String(), "flag needs an argument") {
		t.Errorf("missing flag-needs-argument message; output: %s", out.String())
	}
}

// TestEvalBadFlagDoesNotKillShell pins that a mistyped flag reports an error
// to the terminal and returns nil, rather than propagating a parse error the
// shell treats as fatal.
func TestEvalBadFlagDoesNotKillShell(t *testing.T) {
	for _, input := range []string{
		"fake --bogus ./x",
		"fake ./x --bogus",
	} {
		var (
			invoked  bool
			gotArgs  []string
			gotFlags map[string]string
		)
		cmds := fakeEvalCommand(&invoked, &gotArgs, &gotFlags)
		var out bytes.Buffer
		bt := bufio.NewWriter(&out)

		if err := cmds.eval(context.Background(), bt, input); err != nil {
			t.Errorf("eval(%q) returned error (shell-fatal): %v", input, err)
		}
		if invoked {
			t.Errorf("eval(%q) invoked the command despite a bad flag", input)
		}
		if !strings.Contains(out.String(), "bogus") {
			t.Errorf("eval(%q) did not report the bad flag; output: %s", input, out.String())
		}
	}
}

func TestEvalUnknownCommand(t *testing.T) {
	var (
		invoked  bool
		gotArgs  []string
		gotFlags map[string]string
	)
	cmds := fakeEvalCommand(&invoked, &gotArgs, &gotFlags)
	var out bytes.Buffer
	bt := bufio.NewWriter(&out)

	if err := cmds.eval(context.Background(), bt, "nope"); err != nil {
		t.Errorf("eval returned error for unknown command: %v", err)
	}
	if !strings.Contains(out.String(), "unknown command") {
		t.Errorf("missing unknown-command message; output: %s", out.String())
	}
}

func TestEvalMissingArgsShowsUsage(t *testing.T) {
	var (
		invoked  bool
		gotArgs  []string
		gotFlags map[string]string
	)
	cmds := fakeEvalCommand(&invoked, &gotArgs, &gotFlags)
	var out bytes.Buffer
	bt := bufio.NewWriter(&out)

	if err := cmds.eval(context.Background(), bt, "fake --min taint"); err != nil {
		t.Errorf("eval returned error: %v", err)
	}
	if invoked {
		t.Error("command invoked without its required argument")
	}
	if !strings.Contains(out.String(), "not enough arguments") {
		t.Errorf("missing not-enough-arguments message; output: %s", out.String())
	}
}
