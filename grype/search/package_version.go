package search

import (
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

var _ vulnerability.Criteria = (*PackageVersionCriteria)(nil)

// PackageVersionCriteria conveys the searched package's version without constraining results: every
// record matches. Use it when the caller needs records on both sides of the version but the provider
// needs the version to decide where to search (e.g. search rules keyed on version markers). To
// constrain results by version, use ByVersion.
type PackageVersionCriteria struct {
	Version version.Version
}

// WithVersion returns criteria conveying the searched package's version without matching by version ranges
func WithVersion(v version.Version) vulnerability.Criteria {
	return &PackageVersionCriteria{Version: v}
}

func (v PackageVersionCriteria) MatchesVulnerability(_ vulnerability.Vulnerability) (bool, string, error) {
	return true, "", nil
}

func (v PackageVersionCriteria) Summarize() string {
	return "for package version: " + v.Version.Raw
}
