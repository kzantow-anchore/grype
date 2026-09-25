package v6

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
)

// SearchRuleProvider is implemented by providers that evaluate search rules (see SearchRule).
type SearchRuleProvider interface {
	// SearchRewrites returns how the search subject p is rewritten: the zero value when no rule applies.
	SearchRewrites(p pkg.Package) SearchRewrites
}

// SearchRewrites is the resolved outcome of the search rules that apply to one search subject.
type SearchRewrites struct {
	// Distros are OS identities to search in addition to the subject's own: a channel of its OS, or
	// another OS
	Distros []distro.Distro

	// PackageNames are names to search in addition to the subject's own
	PackageNames []string

	// SkipCPE indicates the subject's distro data is complete, so a matcher should not fall back to
	// the CPE-indexed (NVD) records for it
	SkipCPE bool
}
