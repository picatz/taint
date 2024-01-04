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
			desc: "the target to load (directory or github repository)",
		},
		{
			name:     "pattern",
			desc:     "the pattern to load (default: ./...)",
			optional: true,
		},
	},
	fn: func(ctx context.Context, bt *bufio.Writer, args []string, flags map[string]string) error {
		arg := args[0]

		var (
			pattern string = "./..."

			dir  string
			head string
			err  error
		)

		if len(args) > 1 {
			pattern = args[1]
		}

		// If the argument starts with https://github.com/, then we'll try to
		// clone the repository and load it.
		if strings.HasPrefix(arg, "https://github.com/") {
			// Clone the repository.
			dir, head, err = cloneRepository(ctx, arg)

			bt.WriteString("cloned " + styleNumber.Render(arg) + " to " + styleNumber.Render(dir) + " at " + styleNumber.Render(head) + "\n")
			bt.Flush()

			if err != nil {
				bt.WriteString(err.Error() + "\n")
				bt.Flush()
				return nil
			}
		} else {
			dir = arg
		}

		// Check if the directory exists.
		_, err = os.Stat(dir)
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
		patterns := []string{pattern}
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

		ssaBuildMode := ssa.InstantiateGenerics // ssa.SanityCheckFunctions | ssa.GlobalDebug

		// Analyze the package.
		ssaProg, ssaPkgs = ssautil.Packages(pkgs, ssaBuildMode)

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

		if mainFn == nil {
			bt.WriteString("no main function found\n")
			bt.Flush()
			return nil
		}

		cg, err = callgraphutil.NewGraph(mainFn, srcFns...)
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

		cgStr := strings.ReplaceAll(callgraphutil.GraphString(cg), "→", styleFaint.Render("→"))

		bt.WriteString(cgStr)
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
			desc: "the function to find callpaths to",
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

		paths := callgraphutil.PathsSearchCallTo(cg.Root, fn)

		if len(paths) == 0 {
			bt.WriteString("no calls to " + fn + "\n")
			bt.Flush()
			return nil
		}

		for _, path := range paths {
			pathStr := path.String()

			// Split on " → " and highlight each node.
			parts := strings.Split(pathStr, " → ")

			for i, part := range parts {
				parts[i] = highlightNode(part)
			}

			pathStr = strings.Join(parts, styleFaint.Render(" → "))

			bt.WriteString(pathStr + "\n")
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

func main() {
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

	// Get the directory name.
	dirName := strings.TrimSuffix(repoURL, u.Path)

	// Get the directory path.
	dir := filepath.Join(os.TempDir(), "taint", dirName)

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
