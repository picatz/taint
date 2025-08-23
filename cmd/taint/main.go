package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/go-git/go-git/v5"
	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/term"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Pastel / adaptive lipgloss styles. Users may disable color with NO_COLOR or
// TAINT_THEME=plain. Initialized via initStyles() in main.
var (
	styleBold     lipgloss.Style
	styleFaint    lipgloss.Style
	styleNumber   lipgloss.Style
	styleArgument lipgloss.Style
	styleFlag     lipgloss.Style
	styleCommand  lipgloss.Style
	styleFunc     lipgloss.Style
	styleHeader   lipgloss.Style
	styleInfo     lipgloss.Style
	styleSuccess  lipgloss.Style
	styleWarning  lipgloss.Style
	styleError    lipgloss.Style
	styleSubtle   lipgloss.Style
	styleArrow    lipgloss.Style
	stylePkg      lipgloss.Style
	styleRecv     lipgloss.Style
	styleMethod   lipgloss.Style
	stylePointer  lipgloss.Style
)

func initStyles() {
	plain := os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TAINT_THEME"), "plain")
	if plain {
		styleBold = lipgloss.NewStyle().Bold(true)
		reset := lipgloss.NewStyle()
		styleFaint = reset
		styleNumber = reset
		styleArgument = reset
		styleFlag = reset
		styleCommand = lipgloss.NewStyle().Bold(true)
		styleFunc = reset
		styleHeader = lipgloss.NewStyle().Bold(true)
		styleInfo = reset
		styleSuccess = reset
		styleWarning = reset
		styleError = reset
		styleSubtle = reset
		styleArrow = reset
		stylePkg = reset
		styleRecv = reset
		styleMethod = reset
		stylePointer = reset
		return
	}

	pastelBlue := lipgloss.AdaptiveColor{Light: "#3366cc", Dark: "#8fb3ff"}
	pastelTeal := lipgloss.AdaptiveColor{Light: "#2b7a78", Dark: "#7ad1c4"}
	pastelLav := lipgloss.AdaptiveColor{Light: "#6d5fa6", Dark: "#b7a9ff"}
	pastelRose := lipgloss.AdaptiveColor{Light: "#ad5d7d", Dark: "#ffb3c9"}
	pastelGold := lipgloss.AdaptiveColor{Light: "#b58b00", Dark: "#ffd666"}
	pastelGreen := lipgloss.AdaptiveColor{Light: "#2f7d32", Dark: "#9ada9f"}
	pastelGray := lipgloss.AdaptiveColor{Light: "#6b6f76", Dark: "#9aa0aa"}
	pastelEdge := lipgloss.AdaptiveColor{Light: "#7a7f88", Dark: "#aab2bd"}
	pastelPkg := lipgloss.AdaptiveColor{Light: "#4a6892", Dark: "#87a7d9"}
	pastelRecv := lipgloss.AdaptiveColor{Light: "#7b5d8e", Dark: "#bfa3d6"}
	pastelMethod := lipgloss.AdaptiveColor{Light: "#2b7a78", Dark: "#7ad1c4"}
	pastelPtr := lipgloss.AdaptiveColor{Light: "#9d7a00", Dark: "#d8b74a"}

	styleBold = lipgloss.NewStyle().Bold(true)
	styleFaint = lipgloss.NewStyle().Foreground(pastelGray)
	styleSubtle = lipgloss.NewStyle().Foreground(pastelGray)
	styleNumber = lipgloss.NewStyle().Foreground(pastelGold).Bold(true)
	styleArgument = lipgloss.NewStyle().Foreground(pastelTeal)
	styleFlag = lipgloss.NewStyle().Foreground(pastelLav)
	styleCommand = lipgloss.NewStyle().Foreground(pastelBlue).Bold(true)
	styleFunc = lipgloss.NewStyle().Foreground(pastelLav)
	styleHeader = lipgloss.NewStyle().Foreground(pastelBlue).Bold(true)
	styleInfo = lipgloss.NewStyle().Foreground(pastelTeal)
	styleSuccess = lipgloss.NewStyle().Foreground(pastelGreen)
	styleWarning = lipgloss.NewStyle().Foreground(pastelGold).Bold(true)
	styleError = lipgloss.NewStyle().Foreground(pastelRose).Bold(true)
	styleArrow = lipgloss.NewStyle().Foreground(pastelEdge)
	stylePkg = lipgloss.NewStyle().Foreground(pastelPkg)
	styleRecv = lipgloss.NewStyle().Foreground(pastelRecv)
	styleMethod = lipgloss.NewStyle().Foreground(pastelMethod).Bold(true)
	stylePointer = lipgloss.NewStyle().Foreground(pastelPtr)
}

// semanticColorFunc colors a function string semantically (pkg, receiver, method).
func semanticColorFunc(full string) string {
	if full == "" {
		return full
	}
	lastDot := strings.LastIndex(full, ".")
	if lastDot == -1 {
		return styleMethod.Render(full)
	}
	pkgPath := full[:lastDot]
	rest := full[lastDot+1:]
	if strings.Contains(rest, ")") && strings.Contains(rest, "(") {
		parts := strings.Split(rest, ")")
		if len(parts) >= 2 {
			recvPart := parts[0] + ")"
			methodPart := strings.TrimPrefix(parts[1], ".")
			coloredRecv := colorReceiver(recvPart)
			return stylePkg.Render(pkgPath) + "." + coloredRecv + "." + styleMethod.Render(methodPart)
		}
	}
	return stylePkg.Render(pkgPath) + "." + styleMethod.Render(rest)
}

func colorReceiver(recv string) string {
	inner := strings.TrimSuffix(strings.TrimPrefix(recv, "("), ")")
	ptr := false
	if strings.HasPrefix(inner, "*") {
		ptr = true
		inner = strings.TrimPrefix(inner, "*")
	}
	var colored string
	if strings.Contains(inner, "/") {
		lastSlash := strings.LastIndex(inner, "/")
		pathPart := inner[:lastSlash]
		typePart := inner[lastSlash+1:]
		colored = stylePkg.Render(pathPart) + "/" + styleRecv.Render(typePart)
	} else if strings.Contains(inner, ".") {
		lastDot := strings.LastIndex(inner, ".")
		pkg := inner[:lastDot]
		typ := inner[lastDot+1:]
		colored = stylePkg.Render(pkg) + "." + styleRecv.Render(typ)
	} else {
		colored = styleRecv.Render(inner)
	}
	if ptr {
		return "(" + stylePointer.Render("*") + colored + ")"
	}
	return "(" + colored + ")"
}

var (
	pkgs    []*packages.Package
	ssaProg *ssa.Program
	ssaPkgs []*ssa.Package
	cg      *callgraph.Graph
)

// highlightNode returns a string with the node highlighted, such that
// `n4:(net/http.ResponseWriter).Write` has the `n4` highlighted as a number,
func highlightNode(node string) string {
	parts := strings.SplitN(node, ":", 2)
	if len(parts) != 2 {
		return styleFunc.Render(node)
	}
	id := parts[0]
	body := parts[1]
	return styleNumber.Render(id) + ":" + semanticColorFunc(body)
}

// getAllFunctionNames returns a sorted list of all function names in the callgraph
func getAllFunctionNames(cg *callgraph.Graph) []string {
	var names []string
	seen := make(map[string]bool)

	for _, node := range cg.Nodes {
		if node == nil || node.Func == nil {
			continue
		}
		name := node.Func.String()
		if !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}

	sort.Strings(names)
	return names
}

// makeRawTerminal returns a raw terminal and a function to restore the
// terminal to its previous state, which should be called when the terminal
// is no longer needed (typically in a defer).
func makeRawTerminal() (*term.Terminal, func(), error) {
	// Set the terminal to raw mode.
	oldState, err := term.MakeRaw(0)
	if err != nil {
		return nil, nil, fmt.Errorf("%w", err)
	}

	termWidth, termHeight, err := term.GetSize(0)
	if err != nil {
		return nil, nil, fmt.Errorf("%w", err)
	}

	termReadWriter := struct {
		io.Reader
		io.Writer
	}{os.Stdin, os.Stdout}

	t := term.NewTerminal(termReadWriter, "") // Will set the prompt later.

	err = t.SetSize(termWidth, termHeight)
	if err != nil {
		return nil, nil, fmt.Errorf("%w", err)
	}

	return t, func() { term.Restore(0, oldState) }, nil
}

func clearScreen(bt *bufio.Writer) error {
	// Clear the screen.
	_, err := bt.Write([]byte("\033[2J"))
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	// Move to the top left.
	_, err = bt.Write([]byte("\033[H"))
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	// Flush the buffer to the terminal.
	err = bt.Flush()
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

type commandArg struct {
	name     string
	desc     string
	optional bool
}

type commandFlag struct {
	name string
	desc string
}

type command struct {
	name  string
	desc  string
	args  []*commandArg
	flags []*commandFlag
	fn    commandFn
}

func (c *command) nRequiredArgs() int {
	var n int
	for _, arg := range c.args {
		if arg.optional {
			continue
		}
		n++
	}
	return n
}

func (c *command) help() string {
	var help strings.Builder

	help.WriteString(styleCommand.Render(c.name) + " ")

	for _, arg := range c.args {
		if arg.optional {
			help.WriteString(styleArgument.Render("[") + styleFaint.Render(fmt.Sprintf("<%s>", arg.name)) + styleArgument.Render("] "))
			continue
		}
		help.WriteString(styleArgument.Render(fmt.Sprintf("<%s> ", arg.name)))
	}

	for _, flag := range c.flags {
		help.WriteString(styleFlag.Render(fmt.Sprintf("--%s ", flag.name) + styleFaint.Render(flag.desc)))
	}

	help.WriteString(styleFaint.Render(c.desc) + "\n")

	return help.String()
}

type commandFn func(
	ctx context.Context,
	bt *bufio.Writer,
	args []string,
	flags map[string]string,
) error

func errorCommandFn(err error) commandFn {
	return func(
		_ context.Context,
		_ *bufio.Writer,
		_ []string,
		_ map[string]string,
	) error {
		return err
	}
}

func terminalWriteFn(fn func(bt *bufio.Writer) error) commandFn {
	return func(
		_ context.Context,
		bt *bufio.Writer,
		_ []string,
		_ map[string]string,
	) error {
		return fn(bt)
	}
}

type commands []*command

func (c commands) help() string {
	var help strings.Builder
	for _, cmd := range c {
		help.WriteString(styleFaint.Render("- ") + styleCommand.Render(cmd.name) + " ")

		for _, arg := range cmd.args {
			if arg.optional {
				help.WriteString(styleArgument.Render("[") + styleFaint.Render(arg.name) + styleArgument.Render("] "))
				continue
			}
			help.WriteString(styleArgument.Render(fmt.Sprintf("<%s> ", arg.name)))
		}

		help.WriteString(styleFaint.Render(cmd.desc) + "\n")
	}

	help.WriteString("\n")

	return help.String()
}

func (c commands) eval(ctx context.Context, bt *bufio.Writer, input string) error {
	fields := strings.Fields(input)
	if len(fields) == 0 {
		return nil
	}

	cmdName := fields[0]

	argsAndFlags := fields[1:]

	// Parse flags with Go's flag package.
	flagSet := flag.NewFlagSet(cmdName, flag.ContinueOnError)

	flagSet.SetOutput(bt)

	flagSet.Usage = func() {
		// Print command help.
		bt.WriteString(c.help())
		bt.Flush()
	}

	// Parse the flags.
	err := flagSet.Parse(argsAndFlags)
	if err != nil {
		return err
	}

	// Get the flags.
	flags := make(map[string]string)
	flagSet.Visit(func(f *flag.Flag) {
		flags[f.Name] = f.Value.String()
	})

	for _, cmd := range c {
		if cmd.name == cmdName {
			// Check there are enough arguments.
			if len(flagSet.Args()) < cmd.nRequiredArgs() {
				bt.WriteString("not enough arguments, expected " + styleNumber.Render(fmt.Sprintf("%d", cmd.nRequiredArgs())) + " but got " + styleNumber.Render(fmt.Sprintf("%d", len(flagSet.Args()))) + "\n")
				bt.WriteString("usage: " + cmd.help())
				bt.Flush()
				return nil
			}

			return cmd.fn(ctx, bt, flagSet.Args(), flags)
		}
	}

	bt.WriteString("unknown command: " + cmdName + "\n")
	bt.Flush()

	return nil
}

var builtinCommandExit = &command{
	name: "exit",
	desc: "exit the shell",
	fn:   errorCommandFn(io.EOF),
}

var builtinCommandClear = &command{
	name: "clear",
	desc: "clear the screen",
	fn: terminalWriteFn(func(bt *bufio.Writer) error {
		return clearScreen(bt)
	}),
}

var builtinCommandLoad = &command{
	name: "load",
	desc: "load a program",
	args: []*commandArg{
		{
			name: "target",
			desc: "the target to load (directory or GitHub repository; repository URLs may include a subdirectory or file path)",
		},
		{
			name:     "pattern",
			desc:     "the pattern(s) to load. Accepts comma-separated list. Default: ./... (local) or '.' (bare GitHub repo). Use --full to force ./... for GitHub.",
			optional: true,
		},
	},
	fn: func(ctx context.Context, bt *bufio.Writer, args []string, flags map[string]string) error {
		arg := args[0]

		var (
			pattern             string = "./..." // local default
			userPatternSupplied bool
			dir                 string
			head                string
			err                 error
			loadSubpath         string // subdirectory within cloned repo
			forceFull           bool   // --full flag
		)

		// Detect flags in args (simple parse before patterns) e.g. --full
		var cleanedArgs []string
		for _, a := range args {
			if a == "--full" || a == "-full" || a == "--all" {
				forceFull = true
				continue
			}
			cleanedArgs = append(cleanedArgs, a)
		}
		args = cleanedArgs

		if len(args) > 1 {
			pattern = args[1]
			userPatternSupplied = true
		}

		// If loading from GitHub, allow including an optional subdirectory or file path.
		if strings.HasPrefix(arg, "https://github.com/") {
			// Parse the URL so we can separate owner/repo from any nested path.
			u, parseErr := url.Parse(arg)
			if parseErr != nil {
				bt.WriteString(parseErr.Error() + "\n")
				bt.Flush()
				return nil
			}
			segments := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
			if len(segments) < 2 { // need at least owner/repo
				bt.WriteString("invalid GitHub URL: " + arg + "\n")
				bt.Flush()
				return nil
			}
			ownerRepo := segments[0] + "/" + segments[1]
			// Determine subpath semantics.
			if len(segments) > 2 {
				// Handle blob/<branch>/ style (e.g., .../blob/main/cmd/foo/main.go)
				if segments[2] == "blob" && len(segments) >= 5 {
					// segments[3] is the branch name
					loadSubpath = filepath.Join(segments[4:]...)
				} else {
					loadSubpath = filepath.Join(segments[2:]...)
				}
			}
			cloneURL := "https://github.com/" + ownerRepo
			// Clone (or reuse cached clone).
			dir, head, err = cloneRepository(ctx, cloneURL)
			if err != nil {
				bt.WriteString(err.Error() + "\n")
				bt.Flush()
				return nil
			}
			// Adjust directory if subpath provided.
			if loadSubpath != "" {
				dir = filepath.Join(dir, loadSubpath)
			}
			// Default pattern for GitHub loads is '.' (single package) unless user overrode or --full provided.
			if forceFull && !userPatternSupplied {
				pattern = "./..."
			} else if !userPatternSupplied {
				pattern = "."
			}
			// If a file was specified (ends with .go), strip to its directory.
			if strings.HasSuffix(dir, ".go") {
				dir = filepath.Dir(dir)
			}
			// Report clone + selected path.
			cloneMsg := "cloned " + styleNumber.Render(cloneURL) + " to " + styleNumber.Render(dir) + " at " + styleNumber.Render(head)
			if loadSubpath != "" {
				cloneMsg += styleSubtle.Render(" (subpath)")
			}
			bt.WriteString(cloneMsg + "\n")
			bt.Flush()
		} else {
			dir = arg
		}

		// Check if the directory exists.
		_, err = os.Stat(dir)
		if os.IsNotExist(err) {
			fmt.Fprintf(bt, "directory %q does not exist\n", dir)
			bt.Flush()
			return nil
		}

		loadMode :=
			packages.NeedName |
				packages.NeedDeps |
				packages.NeedFiles |
				packages.NeedModule |
				packages.NeedTypes |
				packages.NeedImports |
				packages.NeedSyntax |
				packages.NeedTypesInfo
			// packages.NeedTypesSizes |
			// packages.NeedCompiledGoFiles |
			// packages.NeedExportFile |
			// packages.NeedEmbedPatterns

		// parseMode := parser.ParseComments
		parseMode := parser.SkipObjectResolution

		// If the pattern is '.' and we loaded from GitHub, we intentionally
		// avoid loading the entire repository (./...) for performance and
		// to reduce noise when large repositories contain many main packages.
		// Support comma-separated patterns: e.g. ".,./cmd/vault,./internal/server"
		var patterns []string
		for _, p := range strings.Split(pattern, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			patterns = append(patterns, p)
		}
		if len(patterns) == 0 {
			patterns = []string{"."}
		}
		// patterns := []string{"all"}

		// fmt.Fprintf(bt, "• loading packages with patterns: %s\n", strings.Join(patterns, ", "))
		// bt.Flush()

		pkgs, err = packages.Load(&packages.Config{
			Mode:    loadMode,
			Context: ctx,
			Env:     os.Environ(),
			Dir:     dir,
			Tests:   false,
			ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
				return parser.ParseFile(fset, filename, src, parseMode)
			},
			// Logf: func(format string, args ...any) {
			// 	fmt.Fprintf(bt, format+"\n", args...)
			// 	bt.Flush()
			// },
		}, patterns...)
		if err != nil {
			bt.WriteString(err.Error() + "\n")
			bt.Flush()
			return nil
		}

		ssaBuildMode := ssa.InstantiateGenerics // ssa.SanityCheckFunctions | ssa.GlobalDebug

		attemptFallback := false

		buildSSA := func() {
			ssaProg, ssaPkgs = ssautil.Packages(pkgs, ssaBuildMode)
			// Identify if all SSA packages are nil
			allNil := true
			for _, sp := range ssaPkgs {
				if sp != nil {
					allNil = false
					break
				}
			}
			// Print per-package load errors (first attempt only or when verbose?)
			for _, p := range pkgs {
				for _, perr := range p.Errors {
					bt.WriteString("✗ " + styleWarning.Render("package load error:") + styleSubtle.Render(" ") + perr.Error() + "\n")
				}
			}
			if allNil {
				// Conditions to fallback: not user supplied, not forced full, initial pattern not ./...
				if !userPatternSupplied && !forceFull && pattern != "./..." {
					attemptFallback = true
					bt.WriteString("• " + styleInfo.Render("no concrete SSA packages built") + styleSubtle.Render(", retrying with ") + styleArgument.Render("./...") + styleSubtle.Render(" pattern") + "\n")
				}
			}
			bt.WriteString("✓ " + styleSuccess.Render(fmt.Sprintf("loaded %d packages", len(pkgs))) + styleSubtle.Render(", creating ") + styleNumber.Render(fmt.Sprintf("%d", len(ssaPkgs))) + styleSubtle.Render(" SSA packages") + "\n")
		}

		buildSSA()

		if attemptFallback {
			// Re-load with ./...
			pattern = "./..."
			pkgs, err = packages.Load(&packages.Config{
				Mode:    loadMode,
				Context: ctx,
				Env:     os.Environ(),
				Dir:     dir,
				Tests:   false,
				ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
					return parser.ParseFile(fset, filename, src, parseMode)
				},
			}, pattern)
			if err != nil {
				bt.WriteString(err.Error() + "\n")
				bt.Flush()
				return nil
			}
			buildSSA()
		}

		ssaProg.Build()

		// Count how many 'main' packages we have so we only add directory hints
		// when there is ambiguity (i.e., more than one main package).
		mainCount := 0
		for _, mp := range ssaPkgs {
			if mp != nil && mp.Pkg != nil && mp.Pkg.Name() == "main" {
				mainCount++
			}
		}

		for i, pkg := range ssaPkgs {
			if pkg == nil {
				bt.WriteString(styleWarning.Render(fmt.Sprintf("⚠ warning: SSA package %d is nil", i)) + "\n")
				continue
			}
			dirHint := pkgDirForSSAPkg(pkg, pkgs)
			label := pkg.Pkg.Name()
			if label == "main" && dirHint != "" && mainCount > 1 {
				label = label + styleSubtle.Render(" ("+dirHint+")")
			}
			// bt.WriteString(styleSubtle.Render("  building SSA package ") + styleNumber.Render(fmt.Sprintf("%d", i)) + styleSubtle.Render(": ") + styleInfo.Render(label) + "\n")
			pkg.Build()
		}

		// Collect all source functions first
		var srcFns []*ssa.Function

		for _, pkg := range ssaPkgs {
			if pkg == nil {
				continue
			}
			for _, fn := range pkg.Members {
				if fn.Object() == nil {
					continue
				}

				if fn.Object().Name() == "_" {
					continue
				}

				pkgFn := pkg.Func(fn.Object().Name())
				if pkgFn == nil {
					continue
				}

				var addAnons func(f *ssa.Function)
				addAnons = func(f *ssa.Function) {
					srcFns = append(srcFns, f)
					for _, anon := range f.AnonFuncs {
						addAnons(anon)
					}
				}
				addAnons(pkgFn)
			}
		}

		// Try to find a main function first
		// Filter out nil or incomplete packages before passing to ssautil.MainPackages
		var nonNilSSAPkgs []*ssa.Package
		for _, p := range ssaPkgs {
			if p == nil || p.Pkg == nil { // protect against nil dereference inside ssautil.MainPackages
				continue
			}
			nonNilSSAPkgs = append(nonNilSSAPkgs, p)
		}

		mainPkgs := ssautil.MainPackages(nonNilSSAPkgs)
		var mainFn *ssa.Function

		if len(mainPkgs) > 0 {
			// Safely retrieve the main function; avoid assuming presence/type.
			if mf := mainPkgs[0].Func("main"); mf != nil {
				mainFn = mf
				dirHint := pkgDirForSSAPkg(mainPkgs[0], pkgs)
				if dirHint != "" && len(mainPkgs) > 1 {
					bt.WriteString("✓ " + styleSuccess.Render("found main function") + styleSubtle.Render(" in ") + styleInfo.Render(dirHint) + styleSubtle.Render(", using as callgraph root") + "\n")
				} else {
					bt.WriteString("✓ " + styleSuccess.Render("found main function") + styleSubtle.Render(", using as callgraph root") + "\n")
				}
			} else {
				bt.WriteString("• " + styleInfo.Render("main package lacks main() function") + styleSubtle.Render(", falling back to multi-root analysis") + "\n")
			}
		} else {
			// No main function found, create a multi-root callgraph
			bt.WriteString("• " + styleInfo.Render("no main function found") + styleSubtle.Render(", creating multi-root analysis") + "\n")
			cg, mainFn, err = callgraphutil.CreateMultiRootCallGraph(ssaProg, srcFns)
			if err != nil {
				bt.WriteString("✗ " + styleWarning.Render("failed to create multi-root callgraph: ") + err.Error() + "\n")
				bt.Flush()
				return nil
			}
			bt.WriteString("✓ " + styleSuccess.Render("created multi-root callgraph") + styleSubtle.Render(" with ") + styleNumber.Render(fmt.Sprintf("%d", len(srcFns))) + styleSubtle.Render(" potential roots") + "\n")
		}

		if mainFn == nil {
			bt.WriteString("✗ " + styleWarning.Render("no analysis root available") + "\n")
			bt.Flush()
			return nil
		}

		// fmt.Fprintf(bt, "• creating callgraph with root: %s\n", mainFn.String())
		bt.Flush()

		cg, err = callgraphutil.NewGraph(mainFn, srcFns...)
		if err != nil {
			bt.WriteString("✗ " + styleWarning.Render("failed to create callgraph: ") + err.Error() + "\n")
			bt.Flush()
			return nil
		}

		bt.WriteString("✓ " + styleSuccess.Render("loaded ") + styleNumber.Render(fmt.Sprintf("%d", len(pkgs))) + styleSuccess.Render(" packages") + "\n")
		bt.Flush()
		return nil
	},
}

var builtinCommandPkgs = &command{
	name: "pkgs",
	desc: "list loaded packages",
	fn: func(ctx context.Context, bt *bufio.Writer, args []string, flags map[string]string) error {
		if len(pkgs) == 0 {
			bt.WriteString("no packages are loaded\n")
			bt.Flush()
			return nil
		}

		var pkgsStr strings.Builder

		for _, pkg := range pkgs {
			var ssaPkg *ssa.Package
			for _, p := range ssaPkgs {
				if p.Pkg.Path() == pkg.PkgPath {
					ssaPkg = p
					break
				}
			}

			if ssaPkg == nil {
				continue
			}

			pkgsStr.WriteString(pkg.PkgPath + " " + styleFaint.Render(fmt.Sprintf("%d imports", len(ssaPkg.Pkg.Imports()))) + "\n")
		}

		bt.WriteString(pkgsStr.String())

		bt.Flush()
		return nil
	},
}

var builtinCommandCG = &command{
	name: "cg",
	desc: "print the callgraph",
	fn: func(ctx context.Context, bt *bufio.Writer, args []string, flags map[string]string) error {
		if cg == nil {
			bt.WriteString("no callgraph is loaded\n")
			bt.Flush()
			return nil
		}

		type nodeLine struct {
			id   string
			text string
			outs []string
		}
		lines := make([]nodeLine, 0, len(cg.Nodes))
		for _, node := range cg.Nodes {
			if node == nil || node.Func == nil {
				continue
			}
			id := strings.SplitN(node.String(), ":", 2)[0]
			base := highlightNode(node.String())
			var outs []string
			for _, e := range node.Out {
				outs = append(outs, highlightNode(e.Callee.String()))
			}
			lines = append(lines, nodeLine{id: id, text: base, outs: outs})
		}
		sort.Slice(lines, func(i, j int) bool {
			ai, _ := strconv.Atoi(strings.TrimPrefix(lines[i].id, "n"))
			aj, _ := strconv.Atoi(strings.TrimPrefix(lines[j].id, "n"))
			return ai < aj
		})

		arrow := styleArrow.Render(" → ")
		for idx, ln := range lines {
			bt.WriteString(ln.text + "\n")
			for _, o := range ln.outs {
				bt.WriteString("  " + arrow + o + "\n")
			}
			// Always put a blank line after each node block for consistent spacing.
			bt.WriteString("\n")
			// Optional: extra separation after root (first) block.
			if idx == 0 && len(lines) > 1 {
				// keep just single blank already added
			}
		}
		bt.Flush()
		return nil
	},
}

var builtinCommandRoot = &command{
	name: "root",
	desc: "print the callgraph's root",
	fn: func(ctx context.Context, bt *bufio.Writer, args []string, flags map[string]string) error {
		if cg == nil {
			bt.WriteString("no callgraph is loaded\n")
			bt.Flush()
			return nil
		}

		bt.WriteString(cg.Root.String() + "\n")
		bt.Flush()
		return nil
	},
}

var builtinCommandNodes = &command{
	name: "nodes",
	desc: "print the callgraph nodes",
	fn: func(ctx context.Context, bt *bufio.Writer, args []string, flags map[string]string) error {
		if cg == nil {
			bt.WriteString("no callgraph is loaded\n")
			bt.Flush()
			return nil
		}

		var nodesStr strings.Builder

		nodesStrs := make([]string, 0, len(cg.Nodes))

		for _, node := range cg.Nodes {
			nodesStrs = append(nodesStrs, node.String())
		}

		sort.SliceStable(nodesStrs, func(i, j int) bool {
			// Parse node ID to int.
			iID := strings.Split(nodesStrs[i], ":")[0]
			jID := strings.Split(nodesStrs[j], ":")[0]

			// Trim the leading "n" prefix.
			iID = strings.TrimPrefix(iID, "n")
			jID = strings.TrimPrefix(jID, "n")

			// Parse node ID to int.
			iN, err := strconv.Atoi(iID)
			if err != nil {
				return false
			}

			jN, err := strconv.Atoi(jID)
			if err != nil {
				return false
			}

			// Compare node IDs.
			return iN < jN
		})

		for _, nodeStr := range nodesStrs {
			nodesStr.WriteString(highlightNode(nodeStr) + "\n")
		}

		bt.WriteString(nodesStr.String())
		bt.Flush()
		return nil
	},
}

var builtinCommandsCallpath = &command{
	name: "callpath",
	desc: "find callpaths to a function",
	args: []*commandArg{
		{
			name: "function",
			desc: "the function to find callpaths to (supports fuzzy, glob, and regex matching)",
		},
	},
	fn: func(ctx context.Context, bt *bufio.Writer, args []string, flags map[string]string) error {
		if cg == nil {
			bt.WriteString("no callgraph is loaded\n")
			bt.Flush()
			return nil
		}

		if len(args) != 1 {
			bt.WriteString("usage: " + styleCommand.Render("callpath") + " " + styleArgument.Render("<function>") + "\n\n")
			bt.WriteString(styleBold.Render("Matching strategies:") + "\n")
			bt.WriteString("  " + styleArgument.Render("function") + "            - exact string match (default)\n")
			bt.WriteString("  " + styleArgument.Render("fuzzy:pattern") + "      - substring/fuzzy match\n")
			bt.WriteString("  " + styleArgument.Render("glob:pattern") + "       - shell-style patterns " + styleFaint.Render("(* ? [])") + "\n")
			bt.WriteString("  " + styleArgument.Render("regex:pattern") + "      - regular expressions\n\n")
			bt.WriteString(styleBold.Render("Examples:") + "\n")
			bt.WriteString("  " + styleCommand.Render("callpath") + " " + styleArgument.Render("fmt.Printf") + "                    " + styleFaint.Render("# exact match") + "\n")
			bt.WriteString("  " + styleCommand.Render("callpath") + " " + styleArgument.Render("fuzzy:Printf") + "               " + styleFaint.Render("# fuzzy match") + "\n")
			bt.WriteString("  " + styleCommand.Render("callpath") + " " + styleArgument.Render("glob:fmt.*") + "                 " + styleFaint.Render("# glob match") + "\n")
			bt.WriteString("  " + styleCommand.Render("callpath") + " " + styleArgument.Render("regex:.*\\.(Exec|Query)$") + "      " + styleFaint.Render("# regex match") + "\n")
			bt.Flush()
			return nil
		}

		pattern := args[0]

		// Use the new advanced matching that handles disconnected callgraphs
		paths, strategy, err := callgraphutil.PathsSearchCallToAdvancedAllNodes(cg, pattern)
		if err != nil {
			bt.WriteString("invalid pattern: " + err.Error() + "\n")
			bt.Flush()
			return nil
		}

		if len(paths) == 0 {
			bt.WriteString("✗ " + styleWarning.Render("no calls found") + styleSubtle.Render(" using ") + styleInfo.Render(strategy.String()) + styleSubtle.Render(" matching for: ") + styleArgument.Render(pattern) + "\n")
			bt.WriteString(styleSubtle.Render("available functions:") + "\n")
			// Show available function names to help the user
			functionNames := getAllFunctionNames(cg)
			for i, name := range functionNames {
				if i >= 10 { // Limit to first 10 to avoid overwhelming output
					bt.WriteString(styleSubtle.Render("  ... and ") + styleNumber.Render(fmt.Sprintf("%d", len(functionNames)-10)) + styleSubtle.Render(" more") + "\n")
					break
				}
				bt.WriteString(styleSubtle.Render("  ") + name + "\n")
			}
			bt.Flush()
			return nil
		}

		bt.WriteString("✓ " + styleSuccess.Render(fmt.Sprintf("found %d path(s)", len(paths))) + styleSubtle.Render(" using ") + styleInfo.Render(strategy.String()) + styleSubtle.Render(" matching for: ") + styleArgument.Render(pattern) + "\n")
		for i, path := range paths {
			pathStr := path.String()

			if pathStr == "" { // direct match (node itself), not necessarily root
				matchedName := pattern
				if strings.Contains(pattern, ":") {
					parts := strings.SplitN(pattern, ":", 2)
					if len(parts) == 2 {
						matchedName = parts[1]
					}
				}
				printed := false
				for _, n := range cg.Nodes {
					if n == nil || n.Func == nil {
						continue
					}
					fnStr := n.Func.String()
					if (strategy.String() == "exact" && fnStr == matchedName) || (strategy.String() != "exact" && strings.Contains(fnStr, matchedName)) {
						bt.WriteString(styleNumber.Render(fmt.Sprintf("%d", i+1)) + ": " + highlightNode(n.String()) + styleSubtle.Render(" (direct match)") + "\n")
						printed = true
						break
					}
				}
				if !printed {
					if cg.Root != nil && cg.Root.Func != nil {
						bt.WriteString(styleNumber.Render(fmt.Sprintf("%d", i+1)) + ": " + highlightNode(cg.Root.String()) + styleSubtle.Render(" (root match)") + "\n")
					} else {
						bt.WriteString(styleNumber.Render(fmt.Sprintf("%d", i+1)) + ": " + styleSubtle.Render("(match)") + "\n")
					}
				}
				bt.Flush()
				continue
			}

			parts := strings.Split(pathStr, " → ")
			for j, part := range parts {
				parts[j] = highlightNode(part)
			}
			pathStr = strings.Join(parts, styleSubtle.Render(" → "))
			bt.WriteString(styleNumber.Render(fmt.Sprintf("%d", i+1)) + ": " + pathStr + "\n")
			bt.Flush()
		}
		return nil
	},
}

var builtinCommandCheck = &command{
	name: "check",
	desc: "perform a taint analysis check",
	args: []*commandArg{
		{
			name: "source",
			desc: "the source to check",
		},
		{
			name: "sink",
			desc: "the sink to check",
		},
	},
	fn: func(ctx context.Context, bt *bufio.Writer, args []string, flags map[string]string) error {
		if cg == nil {
			bt.WriteString("no callgraph is loaded\n")
			bt.Flush()
			return nil
		}

		if len(args) != 2 {
			bt.WriteString("usage: check <source> <sink>\n")
			bt.Flush()
			return nil
		}

		source := args[0]

		sink := args[1]

		results := taint.Check(cg, taint.NewSources(source), taint.NewSinks(sink))

		var resultsStr strings.Builder

		for _, result := range results {
			resultPathStr := result.Path.String()

			parts := strings.Split(resultPathStr, " → ")

			for i, part := range parts {
				parts[i] = highlightNode(part)
			}

			resultPathStr = strings.Join(parts, styleFaint.Render(" → "))

			resultsStr.WriteString(resultPathStr + "\n")
		}

		bt.WriteString(resultsStr.String())
		bt.Flush()
		return nil
	},
}

var builtinCommands = commands{
	builtinCommandExit,
	builtinCommandClear,
	builtinCommandLoad,
	builtinCommandPkgs,
	builtinCommandCG,
	builtinCommandRoot,
	builtinCommandNodes,
	builtinCommandsCallpath,
	builtinCommandCheck,
}

func startShell(ctx context.Context) error {
	// Get a raw terminal.
	t, restore, err := makeRawTerminal()
	if err != nil {
		return err
	}

	// Restore the terminal on exit.
	defer restore()

	// Use buffered terminal writer.
	bt := bufio.NewWriter(t)

	// Autocomplete for commands.
	t.AutoCompleteCallback = func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
		// If the user presses tab, then autocomplete the command.
		if key == '\t' {
			for _, cmd := range builtinCommands {
				// If line is using the load command, then autocomplete the
				// directory name.
				if strings.HasPrefix(line, "load ") {
					// Get the directory name.
					dir := strings.TrimPrefix(line, "load ")

					// Check if the directory exists.
					_, err := os.Stat(dir)
					if os.IsNotExist(err) {
						// If the directory does not exist, check if there is a
						// directory with the same prefix.
						dirPrefix := strings.TrimSuffix(dir, "/")

						// Get the parent directory.
						parentDir := filepath.Dir(dirPrefix)

						// Get the directory name.
						dirName := filepath.Base(dirPrefix)

						// Open the parent directory.
						f, err := os.Open(parentDir)
						if err != nil {
							continue
						}

						// Get the directory entries.
						entries, err := f.Readdir(-1)
						if err != nil {
							// Close the parent directory.
							_ = f.Close()
							continue
						}

						// Close the parent directory.
						err = f.Close()
						if err != nil {
							continue
						}

						// Check if any of the directory entries match the
						// directory name prefix.
						for _, entry := range entries {
							if strings.HasPrefix(entry.Name(), dirName) {
								// If so, we'll autocomplete the directory name.
								loadCmd := "load " + filepath.Join(parentDir, entry.Name())

								return loadCmd, len(loadCmd), true
							}
						}

						return line, pos, false
					}

					// Otherwise, we'll autocomplete the directory name.
					return "load " + dir, len("load " + dir), true
				}

				if strings.HasPrefix(cmd.name, line) {
					// Return the new line and position, which must come after the
					// command.
					return cmd.name, len(cmd.name), true
				}
			}
		}

		// Otherwise, we'll just return the line.
		return line, pos, false
	}

	// Print welcome message.
	bt.WriteString(styleHeader.Render("Commands") + styleSubtle.Render(" (tab complete)") + "\n\n")

	// Print the commands.
	bt.WriteString(builtinCommands.help())

	// Flush the buffer to the terminal.
	bt.Flush()

	for {
		// Move to left edge.
		bt.WriteString("\033[0G")

		// Set the prompt.
		bt.WriteString(styleBold.Render("> "))

		// Flush the buffer to the terminal.
		bt.Flush()

		// Read up to line from STDIN.
		input, err := t.ReadLine()
		if err != nil {
			return err
		}

		// Evaluate the input.
		err = builtinCommands.eval(ctx, bt, input)
		if err != nil {
			return err
		}

		// Flush the buffer to the terminal.
		bt.Flush()
	}
}

func main() {
	initStyles()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := startShell(ctx); err != nil {
		if err == io.EOF {
			os.Exit(0)
		}

		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// cloneRepository clones a repository and returns the directory it was cloned
// to using go-git under the hood, which is a pure Go implementation of Git.
func cloneRepository(ctx context.Context, repoURL string) (string, string, error) {
	// Parse the repository URL (e.g. https://github.com/picatz/taint).
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", "", fmt.Errorf("%w", err)
	}

	// Split the path into segments.
	pathSegments := strings.Split(u.Path, "/")

	// Ensure there are at least 2 segments for owner and repo.
	if len(pathSegments) < 3 {
		return "", "", fmt.Errorf("invalid GitHub URL: %s", repoURL)
	}

	// Get the owner and repo part of the URL.
	ownerAndRepo := pathSegments[1] + "/" + pathSegments[2]

	// Get the directory path.
	dir := filepath.Join(os.TempDir(), "taint", "github", ownerAndRepo)

	// Check if the directory exists.
	_, err = os.Stat(dir)
	if err == nil {
		// If the directory exists, we'll assume it's a valid repository,
		// and return the directory. Open the directory to
		repo, err := git.PlainOpen(dir)
		if err != nil {
			return dir, "", fmt.Errorf("%w", err)
		}

		// Get the repository's HEAD.
		head, err := repo.Head()
		if err != nil {
			return dir, "", fmt.Errorf("%w", err)
		}

		return dir, head.Hash().String(), nil
	}

	// Clone the repository.
	repo, err := git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
		URL:          repoURL,
		Depth:        1,
		Tags:         git.NoTags,
		SingleBranch: true,
	})
	if err != nil {
		return dir, "", fmt.Errorf("%w", err)
	}

	// Get the repository's HEAD.
	head, err := repo.Head()
	if err != nil {
		return dir, "", fmt.Errorf("%w", err)
	}

	return dir, head.Hash().String(), nil
}

func pkgDirForSSAPkg(p *ssa.Package, loaded []*packages.Package) string {
	if p == nil || p.Pkg == nil {
		return ""
	}
	path := p.Pkg.Path()
	for _, lp := range loaded {
		if lp == nil {
			continue
		}
		if lp.PkgPath == path {
			if len(lp.GoFiles) > 0 {
				return filepath.Dir(lp.GoFiles[0])
			}
			if len(lp.OtherFiles) > 0 {
				return filepath.Dir(lp.OtherFiles[0])
			}
		}
	}
	return ""
}
