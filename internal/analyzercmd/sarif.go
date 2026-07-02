package analyzercmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	HelpURI string `json:"helpUri,omitempty"`
	// ShortDescription, FullDescription, Help, DefaultConfiguration, and
	// Properties are struct-typed. Go's encoding/json treats "omitempty" as a
	// no-op for struct fields (IsEmptyValue never considers a struct value
	// empty), so a zero-value struct would still be encoded as `{}` if we
	// used "omitempty" here. "omitzero" (Go 1.24+) actually checks
	// reflect.Value.IsZero, so these are correctly omitted when unset.
	ShortDescription     SARIFMessage              `json:"shortDescription,omitzero"`
	FullDescription      SARIFMessage              `json:"fullDescription,omitzero"`
	Help                 SARIFMessage              `json:"help,omitzero"`
	DefaultConfiguration SARIFDefaultConfiguration `json:"defaultConfiguration,omitzero"`
	Properties           SARIFProperties           `json:"properties,omitzero"`
}

type SARIFDefaultConfiguration struct {
	Level string `json:"level,omitempty"`
}

// SARIFProperties carries the GitHub code scanning conventions used to rank
// and categorize alerts: "security-severity" (a numeric string from 0.1-10.0,
// CVSS-aligned) drives the severity badge, "tags" drives categorization (a
// "security" tag plus a "external/cwe/cwe-NNN" tag per rule), and
// "precision" indicates confidence in the finding.
type SARIFProperties struct {
	Tags             []string `json:"tags,omitempty"`
	Precision        string   `json:"precision,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type SARIFResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex,omitempty"`
	Level               string            `json:"level,omitempty"`
	Message             SARIFMessage      `json:"message"`
	Locations           []SARIFLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

// SARIFMessage models SARIF's multiformatMessageString: a plain-text
// fallback plus an optional Markdown rendering. GitHub's code scanning UI
// prefers Markdown when both are present, which is why rule help messages
// set both fields.
type SARIFMessage struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	// See the comment on SARIFRule for why this uses "omitzero" rather than
	// the no-op "omitempty" for a struct field.
	Region SARIFRegion `json:"region,omitzero"`
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
		f.RuleID = detailedRuleID(f.RuleID, f.Message)
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
	ruleLevel := make(map[string]string, len(ruleIDs))
	rules := make([]SARIFRule, 0, len(ruleIDs))
	for i, id := range ruleIDs {
		ruleIndex[id] = i
		meta := ruleMetadata(id)
		level := meta.level
		if level == "" {
			level = "warning"
		}
		ruleLevel[id] = level
		rules = append(rules, SARIFRule{
			ID:               id,
			Name:             meta.name,
			HelpURI:          meta.helpURI,
			ShortDescription: SARIFMessage{Text: ruleSet[id]},
			FullDescription:  SARIFMessage{Text: ruleSet[id]},
			Help: SARIFMessage{
				Text:     ruleSet[id],
				Markdown: meta.helpMarkdown,
			},
			DefaultConfiguration: SARIFDefaultConfiguration{Level: level},
			Properties: SARIFProperties{
				Tags:             meta.tags,
				Precision:        meta.precision,
				SecuritySeverity: meta.securitySeverity,
			},
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
		level := ruleLevel[f.RuleID]
		if level == "" {
			level = "warning"
		}
		results = append(results, SARIFResult{
			RuleID:              f.RuleID,
			RuleIndex:           ruleIndex[f.RuleID],
			Level:               level,
			Message:             SARIFMessage{Text: f.Message},
			PartialFingerprints: map[string]string{"taint/v1": partialFingerprint(f)},
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
	case "sqli", "sqli/potential-sql-injection":
		return "finds potential SQL injection issues"
	case "logi", "logi/potential-log-injection":
		return "finds potential log injection issues"
	case "cmdi", "cmdi/potential-command-injection":
		return "finds potential command injection issues"
	case "xss", "xss/potential-xss":
		return "finds potential XSS issues"
	case "ptrv", "ptrv/potential-path-traversal":
		return "finds potential path traversal issues"
	case "ssrf", "ssrf/potential-server-side-request-forgery":
		return "finds potential server-side request forgery issues"
	default:
		return ruleID
	}
}

// sarifRuleMeta carries the per-rule metadata GitHub code scanning uses to
// render and rank an alert:
//
//   - securitySeverity is a numeric string from "0.1" to "10.0" (CVSS-aligned)
//     that drives the severity badge shown in the UI, via
//     properties["security-severity"].
//   - precision is GitHub/CodeQL's confidence convention (e.g. "low",
//     "medium", "high", "very-high"), via properties["precision"].
//   - level is the SARIF result/rule level ("error", "warning", or "note"),
//     which maps roughly to CVSS bands: critical/high -> error,
//     medium -> warning, low -> note.
//   - helpMarkdown is the rule's long-form help, rendered as Markdown by
//     GitHub in preference to the plain-text fallback.
type sarifRuleMeta struct {
	name             string
	helpURI          string
	tags             []string
	securitySeverity string
	precision        string
	level            string
	helpMarkdown     string
}

func ruleMetadata(ruleID string) sarifRuleMeta {
	switch ruleID {
	case "sqli/potential-sql-injection":
		return sarifRuleMeta{
			name:             "Potential SQL injection",
			helpURI:          "https://cwe.mitre.org/data/definitions/89.html",
			tags:             []string{"security", "external/cwe/cwe-89"},
			securitySeverity: "8.8",
			precision:        "medium",
			level:            "error",
			helpMarkdown: "## Potential SQL injection\n\n" +
				"Untrusted input reaches a SQL query without being sent through a " +
				"parameterized query or prepared statement. An attacker who " +
				"controls the input may be able to alter the query's structure " +
				"to read, modify, or delete data it should not have access to.\n\n" +
				"**Recommendation:** build the query with placeholders (`?` or " +
				"`$1`) and pass user-controlled values as query arguments " +
				"instead of concatenating or formatting them into the query " +
				"string.\n\n" +
				"See [CWE-89](https://cwe.mitre.org/data/definitions/89.html) for more details.",
		}
	case "logi/potential-log-injection":
		return sarifRuleMeta{
			name:             "Potential log injection",
			helpURI:          "https://cwe.mitre.org/data/definitions/117.html",
			tags:             []string{"security", "external/cwe/cwe-117"},
			securitySeverity: "5.3",
			precision:        "medium",
			level:            "warning",
			helpMarkdown: "## Potential log injection\n\n" +
				"Untrusted input reaches a log sink without sanitization. An " +
				"attacker may be able to inject forged log entries, control " +
				"characters, or terminal escape sequences that corrupt log " +
				"output or downstream log processing/analysis.\n\n" +
				"**Recommendation:** sanitize or encode user-controlled values " +
				"(strip newlines/control characters) before writing them to a " +
				"log, or use a structured logging API that keeps user input in " +
				"its own field rather than interpolating it into a message.\n\n" +
				"See [CWE-117](https://cwe.mitre.org/data/definitions/117.html) for more details.",
		}
	case "cmdi/potential-command-injection":
		return sarifRuleMeta{
			name:             "Potential command injection",
			helpURI:          "https://cwe.mitre.org/data/definitions/78.html",
			tags:             []string{"security", "external/cwe/cwe-78"},
			securitySeverity: "9.8",
			precision:        "medium",
			level:            "error",
			helpMarkdown: "## Potential command injection\n\n" +
				"Untrusted input flows into arguments (or a shell string) " +
				"passed to an OS command execution API. An attacker who " +
				"controls the input may be able to run arbitrary commands with " +
				"the privileges of the process.\n\n" +
				"**Recommendation:** avoid passing user-controlled data through " +
				"a shell interpreter; if a command must run, pass arguments as " +
				"a fixed argv list and validate/allowlist any user-controlled " +
				"argument rather than building the command with string " +
				"concatenation.\n\n" +
				"See [CWE-78](https://cwe.mitre.org/data/definitions/78.html) for more details.",
		}
	case "xss/potential-xss":
		return sarifRuleMeta{
			name:             "Potential cross-site scripting",
			helpURI:          "https://cwe.mitre.org/data/definitions/79.html",
			tags:             []string{"security", "external/cwe/cwe-79"},
			securitySeverity: "6.1",
			precision:        "medium",
			level:            "warning",
			helpMarkdown: "## Potential cross-site scripting (XSS)\n\n" +
				"Untrusted input reaches an HTTP response or HTML output " +
				"without contextual escaping. An attacker who controls the " +
				"input may be able to inject script or markup that executes in " +
				"a victim's browser.\n\n" +
				"**Recommendation:** render user-controlled values with " +
				"`html/template` (which auto-escapes by context) instead of " +
				"`text/template` or manual string concatenation, and avoid " +
				"disabling auto-escaping for user-controlled data.\n\n" +
				"See [CWE-79](https://cwe.mitre.org/data/definitions/79.html) for more details.",
		}
	case "ptrv/potential-path-traversal":
		return sarifRuleMeta{
			name:             "Potential path traversal",
			helpURI:          "https://cwe.mitre.org/data/definitions/22.html",
			tags:             []string{"security", "external/cwe/cwe-22"},
			securitySeverity: "7.5",
			precision:        "medium",
			level:            "error",
			helpMarkdown: "## Potential path traversal\n\n" +
				"Untrusted input reaches a filesystem API used to build or open " +
				"a file path without validation. An attacker who controls the " +
				"input may be able to use `../` sequences (or an absolute path) " +
				"to read, write, or execute files outside the intended " +
				"directory.\n\n" +
				"**Recommendation:** validate that the resolved path stays " +
				"within an intended base directory (for example with " +
				"`os.Root` or by rejecting `..` segments after `filepath.Clean`) " +
				"before using user-controlled input to build a file path.\n\n" +
				"See [CWE-22](https://cwe.mitre.org/data/definitions/22.html) for more details.",
		}
	case "ssrf/potential-server-side-request-forgery":
		return sarifRuleMeta{
			name:             "Potential server-side request forgery",
			helpURI:          "https://cwe.mitre.org/data/definitions/918.html",
			tags:             []string{"security", "external/cwe/cwe-918"},
			securitySeverity: "7.5",
			precision:        "medium",
			level:            "error",
			helpMarkdown: "## Potential server-side request forgery (SSRF)\n\n" +
				"Untrusted input reaches an outbound HTTP/network request " +
				"(e.g. as all or part of a URL or host) without validation. An " +
				"attacker who controls the input may be able to make the " +
				"server issue requests to internal/unintended hosts, such as " +
				"cloud metadata endpoints or internal-only services.\n\n" +
				"**Recommendation:** validate user-controlled URLs/hosts " +
				"against an allowlist of expected destinations before making " +
				"the request, and avoid letting user input select the request's " +
				"scheme, host, or port outright.\n\n" +
				"See [CWE-918](https://cwe.mitre.org/data/definitions/918.html) for more details.",
		}
	default:
		return sarifRuleMeta{
			name:      ruleID,
			precision: "medium",
			level:     "warning",
		}
	}
}

func detailedRuleID(analyzerName, message string) string {
	switch analyzerName {
	case "sqli":
		if strings.EqualFold(message, "potential sql injection") {
			return "sqli/potential-sql-injection"
		}
	case "logi":
		if strings.EqualFold(message, "potential log injection") {
			return "logi/potential-log-injection"
		}
	case "cmdi":
		if strings.EqualFold(message, "potential command injection") {
			return "cmdi/potential-command-injection"
		}
	case "xss":
		if strings.EqualFold(message, "potential XSS") {
			return "xss/potential-xss"
		}
	case "ptrv":
		if strings.EqualFold(message, "potential path traversal") {
			return "ptrv/potential-path-traversal"
		}
	case "ssrf":
		if strings.EqualFold(message, "potential server-side request forgery") {
			return "ssrf/potential-server-side-request-forgery"
		}
	}
	return analyzerName
}

func partialFingerprint(f Finding) string {
	h := sha256.New()
	_, _ = h.Write([]byte(f.RuleID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(f.URI))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(f.Message))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
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
