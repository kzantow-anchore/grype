package result

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
)

// When one package matches the same advisory both directly and via its source-RPM upstream, the two
// results share an ID and namespace but differ in confidence (direct = 1.0, indirect = 0.95, see
// detailProvider). keepMoreSpecificCandidates keeps only the more-specific direct result -- but the
// dropped indirect result's match detail is evidence of how the finding was made and must not be
// lost.
func TestKeepMoreSpecificCandidates_PreservesDroppedDetails(t *testing.T) {
	const id = "ELSA-2022-7628"
	const ns = "oracle:distro:oraclelinux:8"

	mkVuln := func() vulnerability.Vulnerability {
		return vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: id, Namespace: ns}}
	}
	directDetail := match.Detail{Type: match.ExactDirectMatch, Matcher: match.RpmMatcher, Confidence: 1.0, SearchedBy: "php-cli"}
	indirectDetail := match.Detail{Type: match.ExactIndirectMatch, Matcher: match.RpmMatcher, Confidence: 0.95, SearchedBy: "php"}

	candidates := Set{id: []Result{
		{ID: id, Vulnerabilities: []vulnerability.Vulnerability{mkVuln()}, Details: match.Details{directDetail}},
		{ID: id, Vulnerabilities: []vulnerability.Vulnerability{mkVuln()}, Details: match.Details{indirectDetail}},
	}}

	got := keepMoreSpecificCandidates(candidates, Set{})

	require.Len(t, got[id], 1, "the less-specific indirect candidate should be dropped")
	survivor := got[id][0]

	// the surviving direct result must carry its own detail plus the dropped indirect one...
	assert.ElementsMatch(t, []match.Type{match.ExactDirectMatch, match.ExactIndirectMatch}, survivor.Details.Types())
	// ...exactly once each (no double-counting of the survivor's own detail)
	assert.Len(t, survivor.Details, 2)
}

// A more-specific record in the not-vulnerable leg denies a less-specific candidate; that dropped
// candidate's detail must also survive on whatever result remains.
func TestKeepMoreSpecificCandidates_PreservesNAKDroppedDetails(t *testing.T) {
	const id = "CVE-2026-1"
	const nativeNS = "rapidfort:distro:rapidfort-ubuntu:20.4"
	const streamNS = "rapidfort:distro:rapidfort-ubuntu:20.4+rf"

	mkVuln := func(nsp string) vulnerability.Vulnerability {
		return vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: id, Namespace: nsp}}
	}
	// the stream result speaks more confidently for this package than the native rows do
	streamDetail := match.Detail{Type: match.ExactDirectMatch, Matcher: match.DpkgMatcher, Confidence: 1.0, SearchedBy: "stream"}
	nativeDetail := match.Detail{Type: match.ExactDirectMatch, Matcher: match.DpkgMatcher, Confidence: 0.5, SearchedBy: "native"}

	candidates := Set{id: []Result{
		{ID: id, Vulnerabilities: []vulnerability.Vulnerability{mkVuln(streamNS)}, Details: match.Details{streamDetail}},
		{ID: id, Vulnerabilities: []vulnerability.Vulnerability{mkVuln(nativeNS)}, Details: match.Details{nativeDetail}},
	}}
	// a higher-confidence not-vulnerable record for the same ID denies the lower-confidence native
	// candidate
	notVulnerable := Set{id: []Result{
		{ID: id, Vulnerabilities: []vulnerability.Vulnerability{mkVuln(streamNS)}, Details: match.Details{streamDetail}},
	}}

	got := keepMoreSpecificCandidates(candidates, notVulnerable)

	require.Len(t, got[id], 1, "the native candidate denied by the more-specific record should be dropped")
	survivor := got[id][0]
	assert.Contains(t, survivor.Details, nativeDetail, "the dropped native candidate's detail must be preserved as evidence")
}
