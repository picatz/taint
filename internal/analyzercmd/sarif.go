package analyzercmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/singlechecker"
)

type sarifConfig struct {
	enabled bool
	output  string
	args    []string
}

type analyzerJSON map[string]map[string][]analyzerDiagnosticJSON

type analyzerDiagnosticJSON struct {
	Posn    string `json:"posn"`
	Message string `json:"message"`
}

// Main runs analyzer with the standard singlechecker driver, plus a first-class
// SARIF export mode. Use -sarif to write SARIF to stdout, or
// -sarif-output <path> to write it to a file.
func Main(analyzer *analysis.Analyzer) {
	cfg, err := parseSARIFArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if cfg.enabled {
		os.Exit(runSARIF(os.Args[0], analyzer, cfg, os.Stdout, os.Stderr))
	}
	singlechecker.Main(analyzer)
}

func parseSARIFArgs(args []string) (sarifConfig, error) {
	cfg := sarifConfig{args: make([]string, 0, len(args))}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-sarif" || arg == "--sarif":
			cfg.enabled = true
		case strings.HasPrefix(arg, "-sarif="):
			cfg.enabled = true
			cfg.output = strings.TrimPrefix(arg, "-sarif=")
		case strings.HasPrefix(arg, "--sarif="):
			cfg.enabled = true
			cfg.output = strings.TrimPrefix(arg, "--sarif=")
		case arg == "-sarif-output" || arg == "--sarif-output":
			cfg.enabled = true
			if i+1 >= len(args) {
				return cfg, fmt.Errorf("%s requires a path", arg)
			}
			i++
			cfg.output = args[i]
		case strings.HasPrefix(arg, "-sarif-output="):
			cfg.enabled = true
			cfg.output = strings.TrimPrefix(arg, "-sarif-output=")
		case strings.HasPrefix(arg, "--sarif-output="):
			cfg.enabled = true
			cfg.output = strings.TrimPrefix(arg, "--sarif-output=")
		case arg == "-json" || arg == "--json" || strings.HasPrefix(arg, "-json=") || strings.HasPrefix(arg, "--json="):
			// SARIF mode drives singlechecker through JSON internally.
		default:
			cfg.args = append(cfg.args, arg)
		}
	}
	return cfg, nil
}

func runSARIF(exe string, analyzer *analysis.Analyzer, cfg sarifConfig, stdout, stderr io.Writer) int {
	args := append([]string{"-json"}, cfg.args...)
	cmd := exec.Command(exe, args...)
	cmd.Stdin = os.Stdin
	var jsonOut, jsonErr bytes.Buffer
	cmd.Stdout = &jsonOut
	cmd.Stderr = &jsonErr

	runErr := cmd.Run()
	if jsonErr.Len() > 0 {
		_, _ = stderr.Write(jsonErr.Bytes())
	}
	if runErr != nil && jsonOut.Len() == 0 {
		fmt.Fprintf(stderr, "%s: %v\n", filepath.Base(exe), runErr)
		return exitCode(runErr)
	}

	doc, err := parseAnalyzerJSON(jsonOut.Bytes())
	if err != nil {
		fmt.Fprintf(stderr, "%s: parse analyzer json: %v\n", filepath.Base(exe), err)
		return 1
	}

	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "%s: get working directory: %v\n", filepath.Base(exe), err)
		return 1
	}

	log := SARIFLogFromAnalyzerJSON(analyzer, doc, root)
	var out io.Writer = stdout
	var file *os.File
	if cfg.output != "" {
		file, err = os.Create(cfg.output)
		if err != nil {
			fmt.Fprintf(stderr, "%s: create SARIF output: %v\n", filepath.Base(exe), err)
			return 1
		}
		out = file
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		fmt.Fprintf(stderr, "%s: encode SARIF: %v\n", filepath.Base(exe), err)
		return 1
	}
	if file != nil {
		if err := file.Close(); err != nil {
			fmt.Fprintf(stderr, "%s: close SARIF output: %v\n", filepath.Base(exe), err)
			return 1
		}
	}
	return exitCode(runErr)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 1
}

func parseAnalyzerJSON(out []byte) (analyzerJSON, error) {
	idx := bytes.IndexByte(out, '{')
	if idx < 0 {
		return analyzerJSON{}, nil
	}
	var doc analyzerJSON
	if err := json.Unmarshal(out[idx:], &doc); err != nil {
		return nil, err
	}
	if doc == nil {
		doc = analyzerJSON{}
	}
	return doc, nil
}

type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID                   string                    `json:"id"`
	Name                 string                    `json:"name,omitempty"`
	ShortDescription     SARIFMessage              `json:"shortDescription,omitempty"`
	FullDescription      SARIFMessage              `json:"fullDescription,omitempty"`
	DefaultConfiguration SARIFDefaultConfiguration `json:"defaultConfiguration,omitempty"`
}

type SARIFDefaultConfiguration struct {
	Level string `json:"level,omitempty"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex,omitempty"`
	Level     string          `json:"level,omitempty"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

type Finding struct {
	RuleID  string
	URI     string
	Line    int
	Column  int
	Message string
}

// SARIFLogFromAnalyzerJSON converts singlechecker JSON diagnostics into a
// deterministic SARIF 2.1.0 log.
func SARIFLogFromAnalyzerJSON(analyzer *analysis.Analyzer, doc analyzerJSON, root string) SARIFLog {
	driverName := "taint"
	driverDoc := ""
	if analyzer != nil {
		driverName = analyzer.Name
		driverDoc = analyzer.Doc
	}

	var findings []Finding
	for _, byAnalyzer := range doc {
		for name, diagnostics := range byAnalyzer {
			ruleName := name
			if ruleName == "" {
				ruleName = driverName
			}
			for _, diagnostic := range diagnostics {
				path, line, column := splitPosn(diagnostic.Posn)
				findings = append(findings, Finding{
					RuleID:  ruleName,
					URI:     artifactURI(path, root),
					Line:    line,
					Column:  column,
					Message: diagnostic.Message,
				})
			}
		}
	}
	return SARIFLogFromFindings(driverName, driverDoc, findings)
}

// SARIFLogFromFindings converts normalized findings into a deterministic SARIF
// 2.1.0 log. URI values should already be relative to the user's target when
// possible.
func SARIFLogFromFindings(driverName, driverDoc string, findings []Finding) SARIFLog {
	if driverName == "" {
		driverName = "taint"
	}
	ruleSet := map[string]string{}
	seen := map[string]struct{}{}
	deduped := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.RuleID == "" {
			f.RuleID = driverName
		}
		if _, ok := ruleSet[f.RuleID]; !ok {
			ruleSet[f.RuleID] = ruleDescription(f.RuleID, driverName, driverDoc)
		}
		key := strings.Join([]string{
			f.RuleID,
			f.URI,
			strconv.Itoa(f.Line),
			strconv.Itoa(f.Column),
			f.Message,
		}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, f)
	}
	if len(ruleSet) == 0 {
		ruleSet[driverName] = ruleDescription(driverName, driverName, driverDoc)
	}

	ruleIDs := make([]string, 0, len(ruleSet))
	for id := range ruleSet {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	ruleIndex := make(map[string]int, len(ruleIDs))
	rules := make([]SARIFRule, 0, len(ruleIDs))
	for i, id := range ruleIDs {
		ruleIndex[id] = i
		rules = append(rules, SARIFRule{
			ID:                   id,
			Name:                 id,
			ShortDescription:     SARIFMessage{Text: ruleSet[id]},
			FullDescription:      SARIFMessage{Text: ruleSet[id]},
			DefaultConfiguration: SARIFDefaultConfiguration{Level: "warning"},
		})
	}

	sort.SliceStable(deduped, func(i, j int) bool {
		a, b := deduped[i], deduped[j]
		return strings.Join([]string{
			a.RuleID,
			a.URI,
			strconv.Itoa(a.Line),
			strconv.Itoa(a.Column),
			a.Message,
		}, "\x00") < strings.Join([]string{
			b.RuleID,
			b.URI,
			strconv.Itoa(b.Line),
			strconv.Itoa(b.Column),
			b.Message,
		}, "\x00")
	})

	results := make([]SARIFResult, 0, len(deduped))
	for _, f := range deduped {
		results = append(results, SARIFResult{
			RuleID:    f.RuleID,
			RuleIndex: ruleIndex[f.RuleID],
			Level:     "warning",
			Message:   SARIFMessage{Text: f.Message},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: f.URI},
					Region: SARIFRegion{
						StartLine:   f.Line,
						StartColumn: f.Column,
					},
				},
			}},
		})
	}

	return SARIFLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           driverName,
				InformationURI: "https://github.com/picatz/taint",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

func ruleDescription(ruleID, driverName, driverDoc string) string {
	if ruleID == driverName && driverDoc != "" {
		return driverDoc
	}
	switch ruleID {
	case "sqli":
		return "finds potential SQL injection issues"
	case "logi":
		return "finds potential log injection issues"
	case "xss":
		return "finds potential XSS issues"
	default:
		return ruleID
	}
}

func splitPosn(posn string) (path string, line, col int) {
	if posn == "" {
		return "", 0, 0
	}
	parts := strings.Split(posn, ":")
	if len(parts) >= 3 {
		col = atoiSafe(parts[len(parts)-1])
		line = atoiSafe(parts[len(parts)-2])
		path = strings.Join(parts[:len(parts)-2], ":")
	} else if len(parts) == 2 {
		line = atoiSafe(parts[1])
		path = parts[0]
	} else {
		path = parts[0]
	}
	return path, line, col
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func artifactURI(path, root string) string {
	if path == "" {
		return ""
	}
	if !filepath.IsAbs(path) {
		return filepath.ToSlash(path)
	}
	if rel, err := filepath.Rel(root, path); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}
