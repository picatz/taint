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
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraph"
	"golang.org/x/term"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

var (
	styleBold     = lipgloss.NewStyle().Bold(true)
	styleFaint    = lipgloss.NewStyle().Faint(true)
	styleNumber   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("69"))
	styleArgument = lipgloss.NewStyle().Foreground(lipgloss.Color("68"))
	styleFlag     = lipgloss.NewStyle().Foreground(lipgloss.Color("66"))
	styleCommand  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62"))
)

var (
	pkgs    []*packages.Package
	ssaProg *ssa.Program
	ssaPkgs []*ssa.Package
	cg      *callgraph.Graph
)

// highlightNode returns a string with the node highlighted, such that
// `n4:(net/http.ResponseWriter).Write` has the `n4` highlighted as a number,
// and the rest of the string highlighted as a typical Go identifier.
func highlightNode(node string) string {
	// Split the node string on the colon.
	parts := strings.Split(node, ":")

	// Get the node ID.
	nodeID := parts[0]

	// Highlight the node ID.
	nodeID = styleNumber.Render(nodeID)

	// Get the rest of the node string.
	nodeStr := strings.Join(parts[1:], ":")

	// Return the highlighted node.
	return nodeID + ":" + nodeStr
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
	name string
	desc string
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

func (c *command) help() string {
	var help strings.Builder

	help.WriteString(styleCommand.Render(c.name) + " ")

	for _, arg := range c.args {
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
			if len(flagSet.Args()) < len(cmd.args) {
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
			name: "pattern",
			desc: "the pattern to load",
		},
	},
	fn: func(ctx context.Context, bt *bufio.Writer, args []string, flags map[string]string) error {
		dir := args[0]

		// Check if the directory exists.
		_, err := os.Stat(dir)
		if os.IsNotExist(err) {
			bt.WriteString(fmt.Sprintf("directory %q does not exist\n", dir))
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

		// patterns := []string{dir}
		patterns := []string{"./..."}
		// patterns := []string{"all"}

		pkgs, err = packages.Load(&packages.Config{
			Mode:    loadMode,
			Context: ctx,
			Env:     os.Environ(),
			Dir:     dir,
			Tests:   false,
			ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
				return parser.ParseFile(fset, filename, src, parseMode)
			},
		}, patterns...)
		if err != nil {
			bt.WriteString(err.Error() + "\n")
			bt.Flush()
			return nil
		}

		// Analyze the package.
		ssaProg, ssaPkgs = ssautil.Packages(pkgs, ssa.InstantiateGenerics|ssa.SanityCheckFunctions)

		ssaProg.Build()

		for _, pkg := range ssaPkgs {
			pkg.Build()
		}

		mainPkgs := ssautil.MainPackages(ssaPkgs)

		mainFn := mainPkgs[0].Members["main"].(*ssa.Function)

		var srcFns []*ssa.Function

		for _, pkg := range ssaPkgs {
			for _, fn := range pkg.Members {
				if fn.Object() == nil {
					continue
				}

				if fn.Object().Name() == "_" {
					continue
				}

				pngFn := pkg.Func(fn.Object().Name())
				if pngFn == nil {
					continue
				}

				srcFns = append(srcFns, pngFn)
			}
		}

		if mainFn == nil {
			bt.WriteString("no main function found\n")
			bt.Flush()
			return nil
		}

		cg, err = callgraph.New(mainFn, srcFns...)
		if err != nil {
			bt.WriteString(err.Error() + "\n")
			bt.Flush()
			return nil
		}

		bt.WriteString("loaded " + styleNumber.Render(fmt.Sprintf("%d", len(pkgs))) + " packages\n")
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

		cgStr := strings.ReplaceAll(cg.String(), "→", styleFaint.Render("→"))

		bt.WriteString(cgStr)
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
			nodesStrs = append(nodesStrs, highlightNode(node.String()))
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
			nodesStr.WriteString(nodeStr + "\n")
		}

		bt.WriteString(nodesStr.String())
		bt.Flush()
		return nil
	},
}

var builtinCommandsCallpath = &command{
	name: "callpath",
	desc: "find a callpath to a function",
	args: []*commandArg{
		{
			name: "function",
			desc: "the function to find a callpath to",
		},
	},
	fn: func(ctx context.Context, bt *bufio.Writer, args []string, flags map[string]string) error {
		if cg == nil {
			bt.WriteString("no callgraph is loaded\n")
			bt.Flush()
			return nil
		}

		if len(args) != 1 {
			bt.WriteString("usage: callpath <function>\n")
			bt.Flush()
			return nil
		}

		fn := args[0]

		path := callgraph.PathSearchCallTo(cg.Root, fn)

		if path == nil {
			bt.WriteString("no calls to " + fn + "\n")
			bt.Flush()
			return nil
		}

		pathStr := path.String()

		// Split on " → " and highlight each node.
		parts := strings.Split(pathStr, " → ")

		for i, part := range parts {
			parts[i] = highlightNode(part)
		}

		pathStr = strings.Join(parts, styleFaint.Render(" → "))

		bt.WriteString(pathStr + "\n")
		bt.Flush()
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
	bt.WriteString(styleBold.Render("Commands") + " " + styleFaint.Render("(tab complete)") + "\n\n")

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

func interruptContext(ctx context.Context) context.Context {
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		defer cancel()

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)

		select {
		case <-sig:
			return
		case <-ctx.Done():
			return
		}
	}()

	return ctx
}

func main() {
	ctx := interruptContext(context.Background())

	if err := startShell(ctx); err != nil {
		if err == io.EOF {
			os.Exit(0)
		}

		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
