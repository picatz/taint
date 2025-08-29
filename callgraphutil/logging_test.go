package callgraphutil

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLoggingSystem(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelDebug, &buf)

	logger.Info("Starting test")
	logger.Debug("Debug message")
	logger.Trace("Trace message (should not appear)")
	logger.Step("Processing data", "item1", "item2")
	logger.Warning("Warning message")
	logger.Error("Error message")

	output := buf.String()

	// Check that expected messages appear
	if !strings.Contains(output, "Starting test") {
		t.Error("Info message not found")
	}
	if !strings.Contains(output, "Debug message") {
		t.Error("Debug message not found")
	}
	if strings.Contains(output, "Trace message") {
		t.Error("Trace message should not appear at debug level")
	}
	if !strings.Contains(output, "Processing data: item1, item2") {
		t.Error("Step message not formatted correctly")
	}
}

func TestProgressTracker(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelInfo, &buf)
	ctx := WithLogger(context.Background(), logger)

	tracker := NewProgressTracker(ctx, "Test operation", 5)

	for i := 0; i < 5; i++ {
		tracker.Update(fmt.Sprintf("Item %d", i+1))
		time.Sleep(10 * time.Millisecond) // Small delay to see timing
	}

	tracker.Complete()

	output := buf.String()
	if !strings.Contains(output, "Test operation") {
		t.Error("Progress operation name not found")
	}
	if !strings.Contains(output, "complete") {
		t.Error("Completion message not found")
	}
}

func BenchmarkNewGraphWithLogging(b *testing.B) {
	// Use the existing small test data
	dir := "testdata"

	pkgs, err := loadPackages(context.Background(), dir, "./...")
	if err != nil {
		b.Skip("Test data not available:", err)
	}

	mainFn, srcFns, err := loadSSA(context.Background(), pkgs)
	if err != nil {
		b.Fatal(err)
	}

	// Create a logger for this benchmark
	var buf bytes.Buffer
	logger := NewLogger(LogLevelInfo, &buf)
	ctx := WithLogger(context.Background(), logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		graph, err := NewGraphWithContext(ctx, mainFn, srcFns...)
		if err != nil {
			b.Fatal(err)
		}
		_ = graph
	}

	// Print the logging output for the last iteration
	if b.N > 0 {
		b.Logf("Logging output:\n%s", buf.String())
	}
}
