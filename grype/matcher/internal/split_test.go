package internal

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

var splitPkg = pkg.Package{ID: "pkg-1", Name: "openssl", Version: "1.1.1-2rfubu.1"}

func debVersion(raw string) *version.Version {
	return version.New(raw, version.DebFormat)
}

const (
	nativeNS = "rapidfort:distro:rapidfort-ubuntu:20.4"
	streamNS = "rapidfort:distro:rapidfort-ubuntu:20.4+rf"
)

func TestSet_SplitVulnerable_StreamFixOutranksOpenEndedNativeRow(t *testing.T) {
	// the native row is open-ended with no fix; the stream shipped a fix this build is past
	s := setOf("CVE-2026-1",
		record("CVE-2026-1", nativeNS, ">= 1.1.1-1ubuntu2"),
		record("CVE-2026-1", streamNS, "< 1.1.1-3rfubu.1", "1.1.1-3rfubu.1"),
	)

	vulnerable, notVulnerable := SplitVulnerable(s, debVersion("1.1.1-5rfubu.1"))

	require.Empty(t, vulnerable)
	require.ElementsMatch(t, []string{nativeNS, streamNS}, namespacesOf(notVulnerable))
}

func TestSet_SplitVulnerable_StreamOutranksNativeWhenBothVulnerable(t *testing.T) {
	// both streams cover this build with different fixes; only the more confident stream is reported
	s := setOf("CVE-2026-1",
		record("CVE-2026-1", nativeNS, "< 1.30+dfsg-7ubuntu0.20.04.2", "1.30+dfsg-7ubuntu0.20.04.2"),
		record("CVE-2026-1", streamNS, "< 1.30+dfsg-8rfubu.1", "1.30+dfsg-8rfubu.1"),
	)

	vulnerable, notVulnerable := SplitVulnerable(s, debVersion("1.30+dfsg-7rfubu.1"))

	require.Equal(t, []string{streamNS}, namespacesOf(vulnerable))
	require.Empty(t, notVulnerable, "a vulnerability still being reported must never also become an ignore")
}

func TestSet_SplitVulnerable_SilentStreamFallsThroughToNative(t *testing.T) {
	// the stream's range misses this build, so the native rows decide
	s := setOf("CVE-2026-1",
		record("CVE-2026-1", nativeNS, "< 1.5", "1.5"),
		record("CVE-2026-1", streamNS, ">= 2.0, < 2.5", "2.5"),
	)

	vulnerable, _ := SplitVulnerable(s, debVersion("1.0"))

	require.Equal(t, []string{nativeNS}, namespacesOf(vulnerable))
}

func TestSet_SplitVulnerable_SilentNativeFallsThroughToStream(t *testing.T) {
	// the native row misses this build, so the stream decides
	s := setOf("CVE-2026-1",
		record("CVE-2026-1", nativeNS, ">= 1.1.1-1ubuntu2"),
		record("CVE-2026-1", streamNS, "< 1.1.1-3rfubu.1", "1.1.1-3rfubu.1"),
	)

	vulnerable, _ := SplitVulnerable(s, debVersion("1.1.1-0ubuntu1"))

	require.Equal(t, []string{streamNS}, namespacesOf(vulnerable))
}

func TestSet_SplitVulnerable_OwnWindowsDoNotResolveEachOther(t *testing.T) {
	// one advisory with one range per release line: being past the first range does not resolve the second
	semver := func(constraint string, fixVersions ...string) vulnerability.Vulnerability {
		v := record("GHSA-1", "github:language:javascript", "< 0", fixVersions...)
		v.Constraint = version.MustGetConstraint(constraint, version.SemanticFormat)
		return v
	}
	s := setOf("GHSA-1",
		semver("< 8.4.1", "8.4.1"),
		semver(">= 9.0.0-beta.1, < 9.2.1", "9.2.1"),
	)

	vulnerable, notVulnerable := SplitVulnerable(s, version.New("9.0.0", version.SemanticFormat))

	require.Len(t, vulnerable.Vulnerabilities(), 1)
	require.Equal(t, ">= 9.0.0-beta.1, < 9.2.1 (semantic)", vulnerable.Vulnerabilities()[0].Constraint.String())
	require.Empty(t, notVulnerable)
}

func TestSet_SplitVulnerable_OutOfRangeWithNoFixIsNotVulnerable(t *testing.T) {
	// ownership ignores are built from records like this
	s := setOf("CVE-2026-1", record("CVE-2026-1", nativeNS, "< 1.0"))

	vulnerable, notVulnerable := SplitVulnerable(s, debVersion("1.5"))

	require.Empty(t, vulnerable)
	require.Equal(t, []string{nativeNS}, namespacesOf(notVulnerable))
}

func TestSet_SplitVulnerable_NoVersionRulesNothingOut(t *testing.T) {
	// a CPE search with no version cannot rule any record out
	s := setOf("CVE-2026-1",
		record("CVE-2026-1", nativeNS, "< 1.0", "1.0"),
		record("CVE-2026-1", streamNS, "< 2.0", "2.0"),
	)

	for _, v := range []*version.Version{nil, {}} {
		vulnerable, notVulnerable := SplitVulnerable(s, v)

		require.Equal(t, []string{streamNS}, namespacesOf(vulnerable))
		require.Empty(t, notVulnerable)
	}
}

func TestSet_SplitVulnerable_PatchesSearchedByVersionOnVulnerableLeg(t *testing.T) {
	// the version filter patches the searched-by version onto the match details, which the report asserts
	detail := match.Detail{
		Type:       match.ExactDirectMatch,
		SearchedBy: match.DistroParameters{Package: match.PackageParameter{Name: splitPkg.Name}},
	}
	s := result.Set{"CVE-2026-1": []result.Result{{
		ID:              "CVE-2026-1",
		Package:         &splitPkg,
		Details:         match.Details{detail},
		Vulnerabilities: []vulnerability.Vulnerability{record("CVE-2026-1", nativeNS, "< 2.0", "2.0")},
	}}}

	vulnerable, _ := SplitVulnerable(s, debVersion("1.0"))

	searchedBy := vulnerable["CVE-2026-1"][0].Details[0].SearchedBy.(match.DistroParameters)
	require.Equal(t, "1.0", searchedBy.Package.Version)
}

func TestSet_SplitVulnerable_IsStableAcrossCalls(t *testing.T) {
	// match detail order is derived from this and asserted verbatim in the report
	s := setOf("CVE-2026-1",
		record("CVE-2026-1", nativeNS, "< 5.0", "5.0"),
		record("CVE-2026-1", "another:namespace", "< 5.0", "5.0"),
		record("CVE-2026-1", streamNS, "< 5.0", "5.0"),
	)

	first, _ := SplitVulnerable(s, debVersion("1.0"))
	for i := 0; i < 20; i++ {
		next, _ := SplitVulnerable(s, debVersion("1.0"))
		require.Equal(t, first, next)
	}
}

// unaffectedRecord builds an unaffected (NAK) record over the given range.
func unaffectedRecord(id, namespace, constraint string) vulnerability.Vulnerability {
	v := record(id, namespace, constraint)
	v.Unaffected = true
	return v
}

func TestSet_SplitVulnerable_UnaffectedIsNeverAMatch(t *testing.T) {
	t.Run("an unaffected record covering the version reports nothing", func(t *testing.T) {
		s := setOf("CVE-1",
			unaffectedRecord("CVE-1", nativeNS, ">= 0"),
		)

		vulnerable, notVulnerable := SplitVulnerable(s, debVersion("1.1.1-2rfubu.1"))

		require.Empty(t, vulnerable, "a nak must never surface as a finding")
		require.Len(t, notVulnerable, 1, "and must still reach callers as evidence for ignores")
	})

	t.Run("an unaffected record denies an affected one covering the same version", func(t *testing.T) {
		s := setOf("CVE-1",
			record("CVE-1", nativeNS, ">= 0"),
			unaffectedRecord("CVE-1", nativeNS, ">= 0"),
		)

		vulnerable, _ := SplitVulnerable(s, debVersion("1.1.1-2rfubu.1"))

		require.Empty(t, vulnerable)
	})

	t.Run("a nak is not ranked against the streams", func(t *testing.T) {
		// a NAK denies regardless of which stream it came from
		s := setOf("CVE-1",
			record("CVE-1", streamNS, ">= 0"),
			unaffectedRecord("CVE-1", nativeNS, ">= 0"),
		)

		vulnerable, _ := SplitVulnerable(s, debVersion("1.1.1-2rfubu.1"))

		require.Empty(t, vulnerable)
	})

	t.Run("an unaffected record that does not cover the version denies nothing", func(t *testing.T) {
		// the apk "< 0" NAK shape, satisfied by no version
		s := setOf("CVE-1",
			record("CVE-1", nativeNS, ">= 0"),
			unaffectedRecord("CVE-1", nativeNS, "< 0"),
		)

		vulnerable, notVulnerable := SplitVulnerable(s, debVersion("1.1.1-2rfubu.1"))

		require.Len(t, vulnerable, 1, "the affected record still stands")
		require.Empty(t, notVulnerable, "the nak is folded into the finding's entry, not reported separately")
	})
}

// TestSet_SplitVulnerable_UsesEachResultsOwnSearchedVersion: an rpm's source-package records are
// searched at an epoch-less version (see rpm.Matcher.matchDistro), so each record must be compared
// against the version its own search used.
func TestSet_SplitVulnerable_UsesEachResultsOwnSearchedVersion(t *testing.T) {
	resultFor := func(searched string) result.Result {
		var details []match.Detail
		if searched != "" {
			details = []match.Detail{{
				SearchedBy: match.DistroParameters{
					Package: match.PackageParameter{Name: splitPkg.Name, Version: searched},
				},
			}}
		}
		return result.Result{
			ID:              "CVE-1",
			Package:         &splitPkg,
			Vulnerabilities: []vulnerability.Vulnerability{record("CVE-1", nativeNS, "< 2.0")},
			Details:         details,
		}
	}

	t.Run("a result inside its own searched version is vulnerable however the split was called", func(t *testing.T) {
		vulnerable, _ := SplitVulnerable(result.Set{"CVE-1": {resultFor("1.0")}}, debVersion("3.0"))
		require.Len(t, vulnerable, 1, "1.0 < 2.0 at the version this record was searched at")
	})

	t.Run("a result outside its own searched version is not, however the split was called", func(t *testing.T) {
		vulnerable, _ := SplitVulnerable(result.Set{"CVE-1": {resultFor("3.0")}}, debVersion("1.0"))
		require.Empty(t, vulnerable, "3.0 is past the fix bound at the version this record was searched at")
	})

	t.Run("a result naming no version falls back to the split's", func(t *testing.T) {
		vulnerable, _ := SplitVulnerable(result.Set{"CVE-1": {resultFor("")}}, debVersion("3.0"))
		require.Empty(t, vulnerable)
	})

	t.Run("results searched at different versions are judged independently in one split", func(t *testing.T) {
		s := result.Set{"CVE-1": {resultFor("1.0"), resultFor("3.0")}}

		vulnerable, _ := SplitVulnerable(s, nil)

		require.Len(t, vulnerable, 1)
		require.Len(t, vulnerable["CVE-1"], 1, "only the record whose own version is in range survives")
	})
}

func TestDetails_searchedPackageVersion(t *testing.T) {
	tests := []struct {
		name    string
		details match.Details
		want    string
		wantOK  bool
	}{
		{
			name:    "distro details name the version their search was made at",
			details: match.Details{{SearchedBy: match.DistroParameters{Package: match.PackageParameter{Name: "openssl", Version: "1.1.1"}}}},
			want:    "1.1.1",
			wantOK:  true,
		},
		{
			name:    "ecosystem details do too",
			details: match.Details{{SearchedBy: match.EcosystemParameters{Package: match.PackageParameter{Name: "django", Version: "3.2"}}}},
			want:    "3.2",
			wantOK:  true,
		},
		{
			name:    "cpe details do not: their package version is the cataloged one, not what the search compared against",
			details: match.Details{{SearchedBy: match.CPEParameters{Package: match.PackageParameter{Name: "openssl", Version: "1.1.1-r2"}}}},
			wantOK:  false,
		},
		{
			name:    "a blank version is no version",
			details: match.Details{{SearchedBy: match.DistroParameters{Package: match.PackageParameter{Name: "openssl"}}}},
			wantOK:  false,
		},
		{
			name: "the first detail to name one answers for the set",
			details: match.Details{
				{SearchedBy: match.CPEParameters{Package: match.PackageParameter{Version: "cataloged"}}},
				{SearchedBy: match.DistroParameters{Package: match.PackageParameter{Version: "searched"}}},
			},
			want:   "searched",
			wantOK: true,
		},
		{
			name:   "no details, no version",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := searchedPackageVersion(tt.details)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// record builds one hydrated DB record: a single affected range and the fix it names, if any.
func record(id, namespace, constraint string, fixVersions ...string) vulnerability.Vulnerability {
	v := vulnerability.Vulnerability{
		Reference:   vulnerability.Reference{ID: id, Namespace: namespace},
		PackageName: splitPkg.Name,
		Constraint:  version.MustGetConstraint(constraint, version.DebFormat),
	}
	if len(fixVersions) > 0 {
		v.Fix = vulnerability.Fix{State: vulnerability.FixStateFixed, Versions: fixVersions}
	} else {
		v.Fix = vulnerability.Fix{State: vulnerability.FixStateNotFixed}
	}
	return v
}

// rankForNamespace ranks channel namespaces above the rest, as a real record's stream does (see
// result.Rank).
func rankForNamespace(namespace string) result.Rank {
	if i := strings.LastIndex(namespace, ":"); i >= 0 && strings.Contains(namespace[i:], "+") {
		return result.Rank{Stream: result.StreamRuled}
	}
	return result.Rank{Stream: result.StreamOwn}
}

// setOf puts every record under one ID, ranked by namespace (see rankForNamespace).
func setOf(id string, vulns ...vulnerability.Vulnerability) result.Set {
	var results []result.Result
	for _, v := range vulns {
		results = append(results, result.Result{
			ID:              id,
			Package:         &splitPkg,
			Vulnerabilities: []vulnerability.Vulnerability{v},
			Rank:            rankForNamespace(v.Namespace),
		})
	}
	return result.Set{id: results}
}

func namespacesOf(s result.Set) []string {
	var out []string
	for _, v := range s.Vulnerabilities() {
		out = append(out, v.Namespace)
	}
	return out
}

// withAliases attaches related-vulnerability (alias) IDs to a record.
func withAliases(v vulnerability.Vulnerability, aliases ...string) vulnerability.Vulnerability {
	for _, a := range aliases {
		v.RelatedVulnerabilities = append(v.RelatedVulnerabilities, vulnerability.Reference{ID: a})
	}
	return v
}

func resultOf(v vulnerability.Vulnerability) result.Result {
	return result.Result{
		ID:              v.ID,
		Package:         &splitPkg,
		Vulnerabilities: []vulnerability.Vulnerability{v},
		Rank:            rankForNamespace(v.Namespace),
	}
}

// An advisory fixed exactly at the installed version resolves itself and same-vulnerability rows in
// other namespaces, but not a later advisory that patches additional CVEs (regression: OL8 httpd
// dropped ELSA-2022-7647 because it shares CVE-2022-31813 with the exactly-fixed ELSA-2022-9682).
func TestSet_SplitVulnerable_ExactFixDoesNotEraseBroaderSharedAliasAdvisory(t *testing.T) {
	installed := debVersion("1.0-1")

	exactlyFixed := withAliases(record("ELSA-A", nativeNS, "< 1.0-1", "1.0-1"), "CVE-SHARED")
	broader := withAliases(record("ELSA-B", nativeNS, "< 1.0-2", "1.0-2"), "CVE-SHARED", "CVE-OTHER")

	t.Run("broader still-open advisory survives", func(t *testing.T) {
		s := result.Set{"ELSA-A": {resultOf(exactlyFixed)}, "ELSA-B": {resultOf(broader)}}

		vulnerable, _ := SplitVulnerable(s, installed)

		require.Contains(t, vulnerable, "ELSA-B", "the later advisory patches CVE-OTHER at a build this install has not reached")
		require.NotContains(t, vulnerable, "ELSA-A", "the exactly-fixed advisory is not itself vulnerable")
	})

	t.Run("same-vuln row in another namespace is still resolved", func(t *testing.T) {
		sameVuln := record("CVE-SHARED", "nvd:cpe:cpe", ">= 0")
		s := result.Set{"ELSA-A": {resultOf(exactlyFixed)}, "CVE-SHARED": {resultOf(sameVuln)}}

		vulnerable, _ := SplitVulnerable(s, installed)

		require.NotContains(t, vulnerable, "CVE-SHARED", "exact-fix evidence resolves the same vulnerability across namespaces")
	})

	t.Run("later stream advisory for an already-fixed CVE is suppressed", func(t *testing.T) {
		// installed is exactly the lower stream's fix for CVE-SHARED
		higherStream := withAliases(record("ELSA-C", streamNS, "< 1.0-2", "1.0-2"), "CVE-SHARED")
		s := result.Set{"ELSA-A": {resultOf(exactlyFixed)}, "ELSA-C": {resultOf(higherStream)}}

		vulnerable, _ := SplitVulnerable(s, installed)

		require.NotContains(t, vulnerable, "ELSA-C", "a higher stream's advisory for a CVE already fixed in the installed stream is not vulnerable")
	})
}
