package main

import (
	"bufio"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
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
	styleBold   = lipgloss.NewStyle().Bold(true)
	styleFaint  = lipgloss.NewStyle().Faint(true)
	numberColor = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("69"))
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
	nodeID = numberColor.Render(nodeID)

	// Get the rest of the node string.
	nodeStr := strings.Join(parts[1:], ":")

	// Return the highlighted node.
	return nodeID + ":" + nodeStr
}

func startShell(ctx context.Context) error {
	// Set the terminal to raw mode.
	oldState, err := term.MakeRaw(0)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	defer term.Restore(0, oldState)

	termWidth, termHeight, err := term.GetSize(0)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	termReadWriter := struct {
		io.Reader
		io.Writer
	}{os.Stdin, os.Stdout}

	t := term.NewTerminal(termReadWriter, "") // Will set the prompt later.

	t.SetSize(termWidth, termHeight)

	// Use buffered output so we can write to the terminal without
	// having to wait for a newline, and so we can clear the screen
	// and move the cursor around without having to worry about
	// overwriting the prompt.
	bt := bufio.NewWriter(t)

	cls := func() {
		// Clear the screen.
		bt.WriteString("\033[2J")

		// Move to the top left.
		bt.WriteString("\033[H")

		// Flush the buffer to the terminal.
		bt.Flush()
	}

	cls()

	// Autocomplete for commands.
	t.AutoCompleteCallback = func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
		// If the user presses tab, then autocomplete the command.
		if key == '\t' {
			for _, cmd := range []string{"exit", "clear", "load", "pkgs", "cg", "nodes"} {
				if strings.HasPrefix(cmd, line) {
					// Return the new line and position, which must come after the
					// command.
					return cmd, len(cmd), true
				}
			}
		}

		// Otherwise, we'll just return the line.
		return line, pos, false
	}

	// Print welcome message.
	bt.WriteString(styleBold.Render("Commands") + " " + styleFaint.Render("(tab complete)") + "\n\n")
	bt.WriteString("- " + styleFaint.Render("clear") + " to clear screen.\n")
	bt.WriteString("- " + styleFaint.Render("exit") + " to quit.\n\n")
	bt.Flush()

	var (
		pkgs    []*packages.Package
		ssaProg *ssa.Program
		ssaPkgs []*ssa.Package
		cg      *callgraph.Graph
	)

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
			bt.WriteString(err.Error())
			bt.Flush()
			return err
		}

		// Check if the user wants to exit.
		if strings.TrimSpace(input) == "exit" {
			break // Exit the loop.
		}

		// Check if user wants to clear the screen.
		if strings.TrimSpace(input) == "clear" {
			// Clear the screen.
			cls()
			continue
		}

		// Check if the user wants to load a program.
		if strings.HasPrefix(input, "load ") {
			fields := strings.Fields(input)
			if len(fields) != 2 {
				bt.WriteString("usage: load <pattern>")
				bt.Flush()
				continue
			}

			dir := fields[1]

			// Check if the directory exists.
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				bt.WriteString("directory does not exist")
				bt.Flush()
				continue
			}

			loadMode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
				packages.NeedTypes | packages.NeedTypesSizes | packages.NeedImports |
				packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
				packages.NeedExportFile | packages.NeedDeps | packages.NeedEmbedPatterns | packages.NeedModule

			parseMode := parser.ParseComments

			ssaMode := ssa.InstantiateGenerics | ssa.SanityCheckFunctions

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
				bt.WriteString(err.Error())
				bt.Flush()
				continue
			}

			// Analyze the package.
			ssaProg, ssaPkgs = ssautil.Packages(pkgs, ssaMode)

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
				continue
			}

			cg, err = callgraph.New(mainFn, srcFns...)
			if err != nil {
				bt.WriteString(err.Error())
				bt.Flush()
				continue
			}

			bt.WriteString("loaded " + numberColor.Render(fmt.Sprintf("%d", len(pkgs))) + " packages\n")
			bt.Flush()
			continue
		}

		// Check if the user wants to list the loaded packages.
		if strings.TrimSpace(input) == "pkgs" {
			if len(pkgs) == 0 {
				bt.WriteString("no packages are loaded")
				bt.Flush()
				continue
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
			continue
		}

		// Check if the user wants to print the callgraph.
		if strings.TrimSpace(input) == "cg" {
			if cg == nil {
				bt.WriteString("no callgraph is loaded\n")
				bt.Flush()
				continue
			}

			cgStr := strings.ReplaceAll(cg.String(), "→", styleFaint.Render("→"))

			bt.WriteString(cgStr)
			bt.Flush()
			continue
		}

		// Check if the user wants to print the CG nodes.
		if strings.TrimSpace(input) == "nodes" {
			if cg == nil {
				bt.WriteString("no callgraph is loaded")
				bt.Flush()
				continue
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
			continue
		}

		// Check if the user wants to find a callpath to a function.
		if strings.HasPrefix(input, "callpath") {
			if cg == nil {
				bt.WriteString("no callgraph is loaded\n")
				bt.Flush()
				continue
			}

			fields := strings.Fields(input)

			if len(fields) != 2 {
				bt.WriteString("usage: callpath <function>\n")
				bt.Flush()
				continue
			}

			fn := fields[1]

			path := callgraph.PathSearchCallTo(cg.Root, fn)

			if path == nil {
				bt.WriteString("no calls to " + fn + "\n")
				bt.Flush()
				continue
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
			continue
		}

		// Check if the user wants to run a taint analysis.
		if strings.HasPrefix(input, "check") {
			if cg == nil {
				bt.WriteString("no callgraph is loaded\n")
				bt.Flush()
				continue
			}

			fields := strings.Fields(input)

			if len(fields) != 3 {
				bt.WriteString("usage: check <source> <sink>\n")
				bt.Flush()
				continue
			}

			source := fields[1]

			sink := fields[2]

			results := taint.Check(cg, taint.NewSources(source), taint.NewSinks(sink))

			var resultsStr strings.Builder

			for _, result := range results {
				resultsStr.WriteString(result.Path.String() + "\n")
			}

			bt.WriteString(resultsStr.String())
			bt.Flush()
			continue
		}

		// Print unknown command.
		bt.WriteString(fmt.Sprintf("unknown command: %q\n\n", input))
		// Print known commands.
		bt.WriteString("known commands: clear, exit, load, pkgs, cg, nodes\n")
		bt.Flush()
	}

	return nil
}

func main() {
	if err := startShell(context.Background()); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
