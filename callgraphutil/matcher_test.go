package callgraphutil

import (
	"testing"
)

func TestFunctionMatcher(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		strategy    MatchStrategy
		funcName    string
		shouldMatch bool
	}{
		// Exact matching tests
		{"exact match", "fmt.Printf", MatchExact, "fmt.Printf", true},
		{"exact no match", "fmt.Printf", MatchExact, "fmt.Println", false},

		// Fuzzy matching tests
		{"fuzzy match", "Printf", MatchFuzzy, "fmt.Printf", true},
		{"fuzzy no match", "Scanf", MatchFuzzy, "fmt.Printf", false},

		// Glob matching tests
		{"glob star", "fmt.*", MatchGlob, "fmt.Printf", true},
		{"glob question", "fmt.Print?", MatchGlob, "fmt.Printf", true},
		{"glob brackets", "fmt.Print[fl]", MatchGlob, "fmt.Printf", true},
		{"glob no match", "fmt.*", MatchGlob, "os.Exit", false},

		// Regex matching tests
		{"regex simple", "fmt\\.(Print|Scan).*", MatchRegex, "fmt.Printf", true},
		{"regex anchored", "^fmt\\.Printf$", MatchRegex, "fmt.Printf", true},
		{"regex no match", "^fmt\\.Printf$", MatchRegex, "fmt.Println", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewFunctionMatcher(tt.pattern, tt.strategy)
			if err != nil {
				t.Fatalf("Failed to create matcher: %v", err)
			}

			result := matcher.Match(tt.funcName)
			if result != tt.shouldMatch {
				t.Errorf("Expected match result %v for pattern '%s' (%s) against '%s', got %v",
					tt.shouldMatch, tt.pattern, tt.strategy, tt.funcName, result)
			}
		})
	}
}

func TestNewFunctionMatcherFromString(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectedStrategy MatchStrategy
		expectedPattern  string
		shouldError      bool
	}{
		// Prefix-based patterns
		{"exact prefix", "exact:fmt.Printf", MatchExact, "fmt.Printf", false},
		{"fuzzy prefix", "fuzzy:Printf", MatchFuzzy, "Printf", false},
		{"glob prefix", "glob:fmt.*", MatchGlob, "fmt.*", false},
		{"regex prefix", "regex:fmt\\.(Print|Scan).*", MatchRegex, "fmt\\.(Print|Scan).*", false},

		// Default to exact
		{"no prefix", "fmt.Printf", MatchExact, "fmt.Printf", false},
		{"colon in pattern", "http://example.com", MatchExact, "http://example.com", false},
		{"unknown prefix", "unknown:pattern", MatchExact, "unknown:pattern", false},

		// Error cases
		{"invalid regex", "regex:[invalid", MatchRegex, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewFunctionMatcherFromString(tt.input)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error for input '%s', got none", tt.input)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error for input '%s': %v", tt.input, err)
			}

			if matcher.Strategy() != tt.expectedStrategy {
				t.Errorf("Expected strategy %v for input '%s', got %v",
					tt.expectedStrategy, tt.input, matcher.Strategy())
			}

			if matcher.Pattern() != tt.expectedPattern {
				t.Errorf("Expected pattern '%s' for input '%s', got '%s'",
					tt.expectedPattern, tt.input, matcher.Pattern())
			}
		})
	}
}

func TestParseMatchStrategy(t *testing.T) {
	tests := []struct {
		input    string
		expected MatchStrategy
	}{
		{"exact", MatchExact},
		{"fuzzy", MatchFuzzy},
		{"fuzz", MatchFuzzy},
		{"substring", MatchFuzzy},
		{"contains", MatchFuzzy},
		{"glob", MatchGlob},
		{"pattern", MatchGlob},
		{"regex", MatchRegex},
		{"regexp", MatchRegex},
		{"re", MatchRegex},
		{"unknown", MatchExact},
		{"", MatchExact},
		{"FUZZY", MatchFuzzy}, // case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseMatchStrategy(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %v for input '%s', got %v",
					tt.expected, tt.input, result)
			}
		})
	}
}

func TestMatcherErrorHandling(t *testing.T) {
	// Test invalid regex
	_, err := NewFunctionMatcher("[invalid", MatchRegex)
	if err == nil {
		t.Error("Expected error for invalid regex pattern")
	}

	// Test invalid glob patterns should not error but fall back to exact matching
	matcher, err := NewFunctionMatcher("invalid[", MatchGlob)
	if err != nil {
		t.Errorf("Unexpected error for potentially invalid glob: %v", err)
	}

	// Should not match anything since it falls back to exact match
	if matcher.Match("something") {
		t.Error("Invalid glob should fall back to exact match and not match")
	}
}

func TestMatcherString(t *testing.T) {
	tests := []struct {
		pattern  string
		strategy MatchStrategy
		expected string
	}{
		{"fmt.Printf", MatchExact, "exact:fmt.Printf"},
		{"Printf", MatchFuzzy, "fuzzy:Printf"},
		{"fmt.*", MatchGlob, "glob:fmt.*"},
		{"fmt\\.(Print|Scan).*", MatchRegex, "regex:fmt\\.(Print|Scan).*"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			matcher, err := NewFunctionMatcher(tt.pattern, tt.strategy)
			if err != nil {
				t.Fatalf("Failed to create matcher: %v", err)
			}

			result := matcher.String()
			if result != tt.expected {
				t.Errorf("Expected string representation '%s', got '%s'", tt.expected, result)
			}
		})
	}
}
