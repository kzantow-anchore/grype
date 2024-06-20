package match

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
)

var ErrCannotMerge = fmt.Errorf("unable to merge vulnerability matches")

// Match represents a finding in the vulnerability matching process, pairing a single package and a single vulnerability object.
type Match struct {
	Vulnerability vulnerability.Vulnerability // The vulnerability details of the match.
	Package       pkg.Package                 // The package used to search for a match.
	Details       Details                     // all ways in which how this particular match was made.
}

// String is the string representation of select match fields.
func (m Match) String() string {
	return fmt.Sprintf("Match(pkg=%s vuln=%q types=%q)", m.Package, m.Vulnerability.String(), m.Details.Types())
}

func (m Match) Fingerprint() Fingerprint {
	return Fingerprint{
		vulnerabilityID:        m.Vulnerability.ID,
		vulnerabilityNamespace: m.Vulnerability.Namespace,
		vulnerabilityFixes:     strings.Join(m.Vulnerability.Fix.Versions, ","),
		packageID:              m.Package.ID,
	}
}

func (m *Match) Merge(other Match) error {
	if other.Fingerprint() != m.Fingerprint() {
		return ErrCannotMerge
	}

	// there are cases related vulnerabilities are synthetic, for example when
	// orienting results by CVE. we need to keep track of these
	m.Vulnerability.RelatedVulnerabilities = mergeSlices(
		m.Vulnerability.RelatedVulnerabilities,
		other.Vulnerability.RelatedVulnerabilities,
		func(r vulnerability.Reference) string {
			return fmt.Sprintf("%s:%s", r.Namespace, r.ID)
		},
	)

	// also keep details from the other match that are unique
	m.Details = mergeSlices(
		m.Details,
		other.Details,
		func(detail Detail) string {
			return detail.ID()
		},
	)

	// retain all unique CPEs for consistent output
	m.Vulnerability.CPEs = ensureNonNil(cpe.Merge(m.Vulnerability.CPEs, other.Vulnerability.CPEs))

	return nil
}

func mergeSlices[T any](existing []T, new []T, id func(T) string) []T {
	ids := strset.New()
	for _, t := range existing {
		ids.Add(id(t))
	}
	for _, t := range new {
		if !ids.Has(id(t)) {
			existing = append(existing, t)
		}
	}

	// for stable output
	sort.Slice(existing, func(i, j int) bool {
		return strings.Compare(id(existing[i]), id(existing[j])) < 0
	})

	return existing
}

func ensureNonNil[T any](slice []T) []T {
	if slice == nil {
		return []T{}
	}
	return slice
}
