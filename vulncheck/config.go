package vulncheck

import "github.com/picatz/taint"

// DefaultSources returns the taint sources the scanner treats as
// attacker-controlled by default: an inbound HTTP request and a decoded
// protocol-buffer message, the two entry points the built-in detectors model.
// The taint tier asks whether data from one of these reaches a vulnerable
// symbol. Callers wanting a different threat model (CLI arguments, environment,
// message-queue payloads) supply their own set with WithSources, or extend the
// flow rules with WithModels.
func DefaultSources() taint.Sources {
	return taint.NewSources(
		"*net/http.Request",
		"google.golang.org/protobuf/proto.Message",
	)
}

// scanConfig holds the tunable inputs to the taint tier of a scan.
type scanConfig struct {
	sources taint.Sources
	models  []taint.Model
}

// checkOptions renders the config into taint.CheckDetailed options.
func (c scanConfig) checkOptions() []taint.Option {
	if len(c.models) == 0 {
		return nil
	}
	return []taint.Option{taint.WithModels(c.models...)}
}

// Option configures a Scan.
type Option func(*scanConfig)

// WithSources replaces the default attacker-controlled source set used by the
// taint tier. An empty set disables the taint tier (findings top out at the
// symbol tier).
func WithSources(sources taint.Sources) Option {
	return func(c *scanConfig) { c.sources = sources }
}

// WithModels adds flow models (sources, sinks, sanitizers, summaries) to the
// taint tier, extending the analysis with framework or application knowledge
// exactly as the taint library's own WithModels does.
func WithModels(models ...taint.Model) Option {
	return func(c *scanConfig) { c.models = append(c.models, models...) }
}
