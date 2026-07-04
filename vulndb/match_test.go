package vulndb

import "testing"

func semverRange(events ...RangeEvent) Range {
	return Range{Type: "SEMVER", Events: events}
}

func TestAffectsVersion(t *testing.T) {
	tests := []struct {
		name    string
		ranges  []Range
		version string
		want    bool
	}{
		{
			name:    "in single interval",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "1.6.0"}, RangeEvent{Fixed: "1.7.6"})},
			version: "1.7.0",
			want:    true,
		},
		{
			name:    "at introduced boundary is affected",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "1.6.0"}, RangeEvent{Fixed: "1.7.6"})},
			version: "1.6.0",
			want:    true,
		},
		{
			name:    "at fixed boundary is not affected",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "1.6.0"}, RangeEvent{Fixed: "1.7.6"})},
			version: "1.7.6",
			want:    false,
		},
		{
			name:    "before introduced is not affected",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "1.6.0"}, RangeEvent{Fixed: "1.7.6"})},
			version: "1.5.0",
			want:    false,
		},
		{
			name:    "after fixed is not affected",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "1.6.0"}, RangeEvent{Fixed: "1.7.6"})},
			version: "1.8.0",
			want:    false,
		},
		{
			name: "second interval of a multi-interval range",
			ranges: []Range{semverRange(
				RangeEvent{Introduced: "1.6.0-0"}, RangeEvent{Fixed: "1.7.6"},
				RangeEvent{Introduced: "1.8.0-0"}, RangeEvent{Fixed: "1.8.2"},
			)},
			version: "1.8.1",
			want:    true,
		},
		{
			name: "gap between two intervals is not affected",
			ranges: []Range{semverRange(
				RangeEvent{Introduced: "1.6.0-0"}, RangeEvent{Fixed: "1.7.6"},
				RangeEvent{Introduced: "1.8.0-0"}, RangeEvent{Fixed: "1.8.2"},
			)},
			version: "1.7.6",
			want:    false,
		},
		{
			name:    "introduced zero means all before fixed",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "0"}, RangeEvent{Fixed: "1.2.3"})},
			version: "0.9.0",
			want:    true,
		},
		{
			name:    "open ended introduced zero with no fix",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "0"})},
			version: "99.0.0",
			want:    true,
		},
		{
			name:    "prerelease sentinel covers rc versions",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "1.6.0-0"}, RangeEvent{Fixed: "1.7.6"})},
			version: "1.6.0-rc1",
			want:    true,
		},
		{
			name:    "go-prefixed stdlib version",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "1.6.0-0"}, RangeEvent{Fixed: "1.7.6"})},
			version: "go1.7.0",
			want:    true,
		},
		{
			name:    "v-prefixed version",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "1.6.0"}, RangeEvent{Fixed: "1.7.6"})},
			version: "v1.7.0",
			want:    true,
		},
		{
			name:    "unparseable version conservatively affected",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "1.6.0"}, RangeEvent{Fixed: "1.7.6"})},
			version: "not-a-version",
			want:    true,
		},
		{
			name:    "empty version conservatively affected",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "1.6.0"}, RangeEvent{Fixed: "1.7.6"})},
			version: "",
			want:    true,
		},
		{
			name:    "non-semver range type conservatively affected",
			ranges:  []Range{{Type: "GIT", Events: []RangeEvent{{Introduced: "abc"}}}},
			version: "1.0.0",
			want:    true,
		},
		{
			name:    "fixed-first range affects versions below the fix",
			ranges:  []Range{semverRange(RangeEvent{Fixed: "1.2.3"})},
			version: "1.0.0",
			want:    true,
		},
		{
			name:    "fixed-first range clean at or above the fix",
			ranges:  []Range{semverRange(RangeEvent{Fixed: "1.2.3"})},
			version: "1.2.3",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Affected{Ranges: tt.ranges}
			if got := a.AffectsVersion(tt.version); got != tt.want {
				t.Errorf("AffectsVersion(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestFixedVersion(t *testing.T) {
	tests := []struct {
		name    string
		ranges  []Range
		version string
		want    string
	}{
		{
			name:    "single interval reports its fix",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "1.6.0"}, RangeEvent{Fixed: "1.7.6"})},
			version: "1.7.0",
			want:    "1.7.6",
		},
		{
			name: "reports the fix of the containing interval",
			ranges: []Range{semverRange(
				RangeEvent{Introduced: "1.6.0-0"}, RangeEvent{Fixed: "1.7.6"},
				RangeEvent{Introduced: "1.8.0-0"}, RangeEvent{Fixed: "1.8.2"},
			)},
			version: "1.8.1",
			want:    "1.8.2",
		},
		{
			name:    "unaffected version has no fix",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "1.6.0"}, RangeEvent{Fixed: "1.7.6"})},
			version: "1.8.0",
			want:    "",
		},
		{
			name:    "open ended range has no fix",
			ranges:  []Range{semverRange(RangeEvent{Introduced: "0"})},
			version: "1.0.0",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Affected{Ranges: tt.ranges}
			if got := a.FixedVersion(tt.version); got != tt.want {
				t.Errorf("FixedVersion(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestPackageInModule(t *testing.T) {
	tests := []struct {
		importPath string
		modulePath string
		want       bool
	}{
		{"github.com/x/y", "github.com/x/y", true},
		{"github.com/x/y/z", "github.com/x/y", true},
		{"github.com/x/yy", "github.com/x/y", false},
		{"github.com/x/y", "github.com/x/z", false},
		{"crypto/elliptic", stdlibModule, true},
		{"net/http", stdlibModule, true},
		{"github.com/x/y", stdlibModule, false},
		{"cmd/go", stdlibModule, false},
	}
	for _, tt := range tests {
		if got := packageInModule(tt.importPath, tt.modulePath); got != tt.want {
			t.Errorf("packageInModule(%q, %q) = %v, want %v", tt.importPath, tt.modulePath, got, tt.want)
		}
	}
}
