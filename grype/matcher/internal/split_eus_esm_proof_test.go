package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

// These tests drive SplitVulnerable with the record shapes from the RHEL EUS (rpm/rhel_eus.go) and
// Ubuntu ESM (dpkg/ubuntu_esm.go) fixtures and assert the outcomes those matchers' own tests assert,
// so that porting them onto the split is known to reach the same answers. Neither matcher is ported
// yet.
//
// Two behaviors would change with the port:
//
//  1. The matchers' disclosure searches are version-constrained, so a base disclosure whose range
//     misses the installed version never reaches the channel comparison. The split fetches
//     unconstrained.
//  2. A package installed at the base fix yields a not-vulnerable record (an ownership ignore) rather
//     than nothing, as the non-channel rpm path already does.
//
// Not covered: TestRedhatEUSMatches_HigherMinorOnlyFixStaysVulnerable. Its only record is a base
// row whose fix ships on a higher minor (0:3.1.3-23.el8_10 for an 8.4+eus host) with no +eus row for
// the CVE. No record distinguishes a reachable fix from one on an unreachable minor; only
// isFixReachableForEUS's parse of `.elN_M` does. Either the OS transformer must not put such a fix on
// an 8.4 row, or the split needs that predicate as a filter.

func esmVersion(raw string) *version.Version { return version.New(raw, version.DebFormat) }
func eusVersion(raw string) *version.Version { return version.New(raw, version.RpmFormat) }

const (
	esmBaseNS    = "ubuntu:distro:ubuntu:16.04"
	esmChannelNS = "ubuntu:distro:ubuntu:16.04+esm"

	eusBaseNS    = "redhat:distro:redhat:8.4"
	eusChannelNS = "redhat:distro:redhat:8.4+eus"
)

// streamRecord is one hydrated record: a single affected range and the fix it names, if any.
func streamRecord(namespace, constraint string, format version.Format, fixVersions ...string) vulnerability.Vulnerability {
	v := vulnerability.Vulnerability{
		Reference:   vulnerability.Reference{ID: "CVE-1", Namespace: namespace},
		PackageName: "pkg",
		Constraint:  version.MustGetConstraint(constraint, format),
	}
	if len(fixVersions) > 0 {
		v.Fix = vulnerability.Fix{State: vulnerability.FixStateFixed, Versions: fixVersions}
	} else {
		// the won't-fix shape
		v.Fix = vulnerability.Fix{State: vulnerability.FixStateNotFixed}
	}
	return v
}

var proofPkg = pkg.Package{ID: "pkg-1", Name: "pkg"}

// proofSet puts every record under one ID, ranked by namespace (see rankForNamespace).
func proofSet(vulns ...vulnerability.Vulnerability) result.Set {
	var results []result.Result
	for _, v := range vulns {
		results = append(results, result.Result{
			ID:              "CVE-1",
			Package:         &proofPkg,
			Vulnerabilities: []vulnerability.Vulnerability{v},
			Rank:            rankForNamespace(v.Namespace),
		})
	}
	return result.Set{"CVE-1": results}
}

// reported is the namespace and fix of one vulnerable record.
type reported struct {
	namespace string
	state     vulnerability.FixState
	fixes     []string
}

func reportedFrom(t *testing.T, s result.Set) []reported {
	t.Helper()
	var out []reported
	for _, v := range s.Vulnerabilities() {
		out = append(out, reported{namespace: v.Namespace, state: v.Fix.State, fixes: v.Fix.Versions})
	}
	return out
}

// TestProof_UbuntuESM covers the scenarios of TestUbuntuESM_VulnerableCases and
// TestUbuntuESM_FixedCases, in the same order.
func TestProof_UbuntuESM(t *testing.T) {
	const (
		basePocketFix = "1.11.0-2ubuntu1.1"
		esmFix        = "1.11.0-2ubuntu1.1+esm1"
	)

	t.Run("esm-only fix surfaced when installed below it", func(t *testing.T) {
		// the base pocket ships nothing; the esm channel ships the fix
		s := proofSet(
			streamRecord(esmBaseNS, ">= 0", version.DebFormat),
			streamRecord(esmChannelNS, "< "+esmFix, version.DebFormat, esmFix),
		)

		vulnerable, _ := SplitVulnerable(s, esmVersion("1.11.0-2ubuntu1"))

		// the channel is more specific and says vulnerable, so its record and fix are reported
		assert.Equal(t, []reported{{namespace: esmChannelNS, state: vulnerability.FixStateFixed, fixes: []string{esmFix}}},
			reportedFrom(t, vulnerable))
	})

	t.Run("channel off leaves base wont-fix visible", func(t *testing.T) {
		// no esm channel on the distro, so no channel row is searched
		s := proofSet(streamRecord(esmBaseNS, ">= 0", version.DebFormat))

		vulnerable, _ := SplitVulnerable(s, esmVersion("1.11.0-2ubuntu1"))

		assert.Equal(t, []reported{{namespace: esmBaseNS, state: vulnerability.FixStateNotFixed}},
			reportedFrom(t, vulnerable), "a Pro-only fix must never be treated as fixed for a non-Pro user")
	})

	t.Run("base standard-pocket fix still resolves with channel on", func(t *testing.T) {
		// the channel has no record, so the base rows decide
		s := proofSet(streamRecord(esmBaseNS, "< "+basePocketFix, version.DebFormat, basePocketFix))

		vulnerable, _ := SplitVulnerable(s, esmVersion("1.11.0-2ubuntu1"))

		assert.Equal(t, []reported{{namespace: esmBaseNS, state: vulnerability.FixStateFixed, fixes: []string{basePocketFix}}},
			reportedFrom(t, vulnerable))
	})

	t.Run("channel on with no esm fix stays vulnerable", func(t *testing.T) {
		// esm channel enabled, but the package has no fix in either stream
		s := proofSet(
			streamRecord(esmBaseNS, ">= 0", version.DebFormat),
			streamRecord(esmChannelNS, ">= 0", version.DebFormat),
		)

		vulnerable, _ := SplitVulnerable(s, esmVersion("1.11.0-2ubuntu1"))

		assert.Equal(t, []reported{{namespace: esmChannelNS, state: vulnerability.FixStateNotFixed}},
			reportedFrom(t, vulnerable))
	})

	t.Run("at esm fix is resolved", func(t *testing.T) {
		s := proofSet(
			streamRecord(esmBaseNS, ">= 0", version.DebFormat),
			streamRecord(esmChannelNS, "< "+esmFix, version.DebFormat, esmFix),
		)

		vulnerable, notVulnerable := SplitVulnerable(s, esmVersion(esmFix))

		// the channel's fix is at this version, so it answers "fixed"; the base won't-fix row does not override it
		require.Empty(t, vulnerable)
		require.NotEmpty(t, notVulnerable)
	})

	t.Run("at base standard-pocket fix is resolved", func(t *testing.T) {
		s := proofSet(streamRecord(esmBaseNS, "< "+basePocketFix, version.DebFormat, basePocketFix))

		vulnerable, notVulnerable := SplitVulnerable(s, esmVersion(basePocketFix))

		require.Empty(t, vulnerable)
		// behavior change 2: the matcher returns nothing here today
		require.NotEmpty(t, notVulnerable)
	})
}

// TestProof_RedhatEUS covers the EUS scenarios except the one noted in the file header.
func TestProof_RedhatEUS(t *testing.T) {
	const (
		eusFix  = "0:5.14.0-427.68.1.el9_4"
		mainFix = "0:5.14.0-503.11.1.el9_5"
	)

	t.Run("vulnerable on EUS", func(t *testing.T) {
		s := proofSet(
			streamRecord(eusBaseNS, "< "+mainFix, version.RpmFormat, mainFix),
			streamRecord(eusChannelNS, "< "+eusFix, version.RpmFormat, eusFix),
		)

		vulnerable, _ := SplitVulnerable(s, eusVersion("0:5.14.0-300.el9_4"))

		// below both fixes: the channel is more specific, so its fix is reported
		assert.Equal(t, []reported{{namespace: eusChannelNS, state: vulnerability.FixStateFixed, fixes: []string{eusFix}}},
			reportedFrom(t, vulnerable))
	})

	t.Run("between the EUS fix and the mainline fix is resolved", func(t *testing.T) {
		s := proofSet(
			streamRecord(eusBaseNS, "< "+mainFix, version.RpmFormat, mainFix),
			streamRecord(eusChannelNS, "< "+eusFix, version.RpmFormat, eusFix),
		)

		// 450 is past the EUS fix but below the mainline one
		vulnerable, notVulnerable := SplitVulnerable(s, eusVersion("0:5.14.0-450.el9_4"))

		// the channel answers "fixed"; the still-open base range is not consulted
		require.Empty(t, vulnerable)
		require.NotEmpty(t, notVulnerable)
	})

	t.Run("a lower reachable channel fix resolves despite a higher base fix", func(t *testing.T) {
		// the shape of TestRedhatEUSMatches_LowerReachableFixResolvesDespiteHigherFix: the base fix
		// is an unreachable higher-minor rebase, the channel fix is the reachable backport, and the
		// host is at the backport
		const (
			reachableChannelFix = "1:14.18.2-2.module+el8.4.0+13643+6c0ebf22"
			unreachableBaseFix  = "1:14.18.2-2.module+el8.5.0+13644+8d46dafd"
		)

		s := proofSet(
			streamRecord(eusBaseNS, "< "+unreachableBaseFix, version.RpmFormat, unreachableBaseFix),
			streamRecord(eusChannelNS, "< "+reachableChannelFix, version.RpmFormat, reachableChannelFix),
		)

		vulnerable, notVulnerable := SplitVulnerable(s, eusVersion(reachableChannelFix))

		require.Empty(t, vulnerable)
		require.NotEmpty(t, notVulnerable)
	})

	t.Run("a channel with nothing to say falls through to the base rows", func(t *testing.T) {
		// no +eus row for this CVE, so the base rows decide (the uncovered case in the file header
		// has this shape, with an unreachable fix)
		s := proofSet(streamRecord(eusBaseNS, "< "+mainFix, version.RpmFormat, mainFix))

		vulnerable, _ := SplitVulnerable(s, eusVersion("0:5.14.0-300.el9_4"))

		assert.Equal(t, []reported{{namespace: eusBaseNS, state: vulnerability.FixStateFixed, fixes: []string{mainFix}}},
			reportedFrom(t, vulnerable))
	})
}
