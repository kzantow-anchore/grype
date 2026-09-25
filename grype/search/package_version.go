package search

import (
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

var _ vulnerability.Criteria = (*PackageVersionCriteria)(nil)

// PackageVersionCriteria states the searched version without constraining results, for providers
// that choose where to search by version (e.g. search rules). To constrain by version, use ByVersion.
type PackageVersionCriteria struct {
	Version version.Version
}

// WithVersion returns criteria stating the searched version without constraining results.
func WithVersion(v version.Version) vulnerability.Criteria {
	return &PackageVersionCriteria{Version: v}
}

func (v PackageVersionCriteria) MatchesVulnerability(_ vulnerability.Vulnerability) (bool, string, error) {
	return true, "", nil
}

func (v PackageVersionCriteria) Summarize() string {
	return "for package version: " + v.Version.Raw
}
