package result

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestRank_Compare(t *testing.T) {
	// strongest first; every rank outranks every rank after it
	ordered := []Rank{
		{Stream: StreamRuled, Kind: match.ExactDirectMatch},
		{Stream: StreamRuled, Kind: match.ExactIndirectMatch},
		{Stream: StreamRuled, Kind: match.CPEMatch},
		{Stream: StreamRuled},
		{Stream: StreamOwn, Kind: match.ExactDirectMatch},
		{Stream: StreamOwn, Kind: match.ExactIndirectMatch},
		{Stream: StreamOwn, Kind: match.CPEMatch},
		{Stream: StreamOwn},
	}
	for i, a := range ordered {
		for j, b := range ordered {
			got := a.Compare(b)
			switch {
			case i < j:
				assert.Positivef(t, got, "%+v should outrank %+v", a, b)
			case i > j:
				assert.Negativef(t, got, "%+v should rank below %+v", a, b)
			default:
				assert.Zerof(t, got, "%+v should equal itself", a)
			}
		}
	}
}

func TestRankOf_UsesTheStrongestDetail(t *testing.T) {
	details := match.Details{{Type: match.CPEMatch}, {Type: match.ExactIndirectMatch}}
	assert.Equal(t, Rank{Stream: StreamRuled, Kind: match.ExactIndirectMatch}, rankOf(StreamRuled, details))
	assert.Equal(t, Rank{Stream: StreamOwn}, rankOf(StreamOwn, nil))
}

func TestResult_Derive_KeepsRank(t *testing.T) {
	r := Result{ID: "x", Vulnerabilities: []vulnerability.Vulnerability{{}}, Details: match.Details{{}}, Rank: Rank{Stream: StreamRuled, Kind: match.ExactDirectMatch}}
	assert.Equal(t, Result{ID: "x", Rank: r.Rank}, r.Derive())
}

// A package that is its own upstream is searched under its own name, so only the search can say its
// upstream records are indirect; their details and rank must say so too.
func TestProvider_IndirectPackageNameSearch(t *testing.T) {
	d := distro.New(distro.Alpine, "3.18", "")
	vuln := vulnerability.Vulnerability{
		Reference:   vulnerability.Reference{ID: "CVE-2026-1", Namespace: "alpine:distro:alpine:3.18"},
		PackageName: "busybox",
	}
	p := pkg.Package{Name: "busybox", Version: "1.36.1-r0", Type: syftPkg.ApkPkg, Distro: d}
	other := vuln
	other.PackageName = "other"
	rp := NewProvider(mock.VulnerabilityProvider(vuln, other), p, match.ApkMatcher)

	for _, tt := range []struct {
		name     string
		criteria vulnerability.Criteria
		want     match.Type
	}{
		{name: "own name", criteria: search.ByPackageName("busybox"), want: match.ExactDirectMatch},
		{name: "own name, searched as an upstream", criteria: search.ByIndirectPackageName("busybox"), want: match.ExactIndirectMatch},
		{name: "another name", criteria: search.ByPackageName("other"), want: match.ExactIndirectMatch},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rp.FindResults(tt.criteria, search.ByDistro(*d))
			require.NoError(t, err)
			require.Len(t, got["CVE-2026-1"], 1)
			r := got["CVE-2026-1"][0]
			assert.Equal(t, []match.Type{tt.want}, r.Details.Types())
			assert.Equal(t, Rank{Stream: StreamOwn, Kind: tt.want}, r.Rank)
		})
	}
}

func TestFanOutNames_KeepsIndirectness(t *testing.T) {
	cs := []vulnerability.Criteria{search.ByIndirectPackageName("rf-curl"), search.ByDistro(*distro.New(distro.Debian, "12", ""))}
	got := fanOutNames([]ruledSearch{{criteria: cs}}, []string{"curl"}, 0)
	require.Len(t, got, 2)
	assert.Equal(t, search.ByIndirectPackageName("curl"), got[1].criteria[0])
}
