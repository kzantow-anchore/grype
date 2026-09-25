package result

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// channelRule adds channel to the subject's OS when the searched name and version match.
type channelRule struct {
	name, version, channel string
}

// ruleProvider resolves a fixed rule set against the subject it is handed, as the DB provider does.
type ruleProvider struct {
	vulnerability.Provider
	rules []channelRule
}

var _ v6.SearchRuleProvider = ruleProvider{}

func (p ruleProvider) SearchRewrites(criteria []vulnerability.Criteria) v6.SearchRewrites {
	var name, ver string
	var distros []distro.Distro
	for _, c := range criteria {
		switch c := c.(type) {
		case *search.PackageNameCriteria:
			name = c.PackageName
		case *search.PackageVersionCriteria:
			ver = c.Version.Raw
		case *search.DistroCriteria:
			distros = append(distros, c.Distros...)
		}
	}
	var out v6.SearchRewrites
	for _, r := range p.rules {
		if !regexpMatch(r.name, name) || !regexpMatch(r.version, ver) {
			continue
		}
		for _, d := range distros {
			d.Channels = []string{r.channel}
			out.Distros = append(out.Distros, d)
		}
	}
	return out
}

func regexpMatch(pattern, s string) bool {
	return s != "" && regexp.MustCompile("^(?:"+pattern+")$").MatchString(s)
}

func TestApplySearchRules_EvaluatesCriteriaNotCatalogedPackage(t *testing.T) {
	rf := *distro.New(distro.RapidFortRedHat, "9", "")

	// the search is for the source package, under another name and an epoch-less version; only the
	// searched values may select a rule
	cataloged := pkg.Package{Name: "libfoo", Version: "1:1.0-1.el9", Type: syftPkg.RpmPkg, Distro: &rf}

	vp := ruleProvider{
		Provider: mock.VulnerabilityProvider(),
		rules: []channelRule{
			// selected by the searched name
			{name: `rf-.*`, version: `.*`, channel: "rf"},
			// selected by the searched version
			{name: `.*`, version: `.*\.fc43`, channel: "fc43"},
			// would be selected by the cataloged version, must not be
			{name: `.*`, version: `1:.*`, channel: "wrong"},
		},
	}

	cs := []vulnerability.Criteria{
		search.ByPackageName("rf-foo"),
		search.ByDistro(rf),
		search.WithVersion(*version.New("1.0-1.fc43", version.RpmFormat)),
	}

	got := applySearchRules(vp, cataloged, cs)

	type searched struct {
		channels string
		stream   Stream
	}
	var searches []searched
	for _, s := range got {
		dc := s.criteria[1].(*search.DistroCriteria)
		require.Len(t, dc.Distros, 1)
		searches = append(searches, searched{channels: strings.Join(dc.Distros[0].Channels, ","), stream: s.stream})
	}
	require.ElementsMatch(t, []searched{
		{channels: "", stream: StreamOwn},
		{channels: "rf", stream: StreamRuled},
		{channels: "fc43", stream: StreamRuled},
	}, searches)
}

// fixedRewrites resolves every search to the same rewrites, recording the criteria it was asked about.
type fixedRewrites struct {
	vulnerability.Provider
	rewrites v6.SearchRewrites
	asked    *[][]vulnerability.Criteria
}

var _ v6.SearchRuleProvider = fixedRewrites{}

func (p fixedRewrites) SearchRewrites(criteria []vulnerability.Criteria) v6.SearchRewrites {
	*p.asked = append(*p.asked, criteria)
	return p.rewrites
}

func TestApplySearchRules_CPESearchIsAnOSLessPartitionSearch(t *testing.T) {
	rf := distro.New(distro.RapidFortAlpine, "3.18", "")
	cataloged := pkg.Package{Name: "curl", Version: "8.5.0-r0", Type: syftPkg.ApkPkg, Distro: rf}
	cs := []vulnerability.Criteria{search.ByCPE(cpe.Must("cpe:2.3:a:haxx:curl:8.5.0:*:*:*:*:*:*:*", ""))}

	overlay := *rf
	overlay.Channels = []string{"rf"}

	t.Run("the rules read the cataloged package's name, version, OS and ecosystem", func(t *testing.T) {
		var asked [][]vulnerability.Criteria
		applySearchRules(fixedRewrites{Provider: mock.VulnerabilityProvider(), asked: &asked}, cataloged, cs)
		require.Len(t, asked, 1)
		require.ElementsMatch(t, []vulnerability.Criteria{
			cs[0],
			search.ByEcosystem(cataloged.Language, cataloged.Type),
			search.ByPackageName(cataloged.Name),
			search.WithVersion(*version.New(cataloged.Version, version.ApkFormat)),
			search.ByDistro(*rf),
		}, asked[0])
	})

	t.Run("excluding the OS-less partition runs no search", func(t *testing.T) {
		var asked [][]vulnerability.Criteria
		vp := fixedRewrites{Provider: mock.VulnerabilityProvider(), asked: &asked, rewrites: v6.SearchRewrites{ExcludeOSLess: true}}
		require.Empty(t, applySearchRules(vp, cataloged, cs))
	})

	t.Run("OS rows are not added to an OS-less search", func(t *testing.T) {
		var asked [][]vulnerability.Criteria
		vp := fixedRewrites{Provider: mock.VulnerabilityProvider(), asked: &asked, rewrites: v6.SearchRewrites{Distros: []distro.Distro{overlay}}}
		got := applySearchRules(vp, cataloged, cs)
		require.Len(t, got, 1)
		require.Equal(t, cs, got[0].criteria)
	})

	t.Run("the package's own OS search is never excluded", func(t *testing.T) {
		var asked [][]vulnerability.Criteria
		vp := fixedRewrites{Provider: mock.VulnerabilityProvider(), asked: &asked, rewrites: v6.SearchRewrites{ExcludeOSLess: true}}
		distroSearch := []vulnerability.Criteria{search.ByPackageName("curl"), search.ByDistro(*rf)}
		got := applySearchRules(vp, cataloged, distroSearch)
		require.Len(t, got, 1)
		require.Equal(t, distroSearch, got[0].criteria)
	})
}

func TestApplySearchRules_OSSearch(t *testing.T) {
	deb := *distro.New(distro.Debian, "12", "")
	cataloged := pkg.Package{Name: "rf-curl", Version: "7.88.1-10+deb12u5.echo1", Type: syftPkg.DebPkg, Distro: &deb}
	cs := []vulnerability.Criteria{search.ByPackageName("rf-curl"), search.ByDistro(deb)}

	echo := *distro.New(distro.Echo, "12", "")
	var asked [][]vulnerability.Criteria
	vp := fixedRewrites{Provider: mock.VulnerabilityProvider(), asked: &asked, rewrites: v6.SearchRewrites{
		Distros:      []distro.Distro{echo, deb}, // the second reads the package's own rows again
		PackageNames: []string{"curl"},
	}}

	got := applySearchRules(vp, cataloged, cs)

	require.Len(t, asked, 1)
	require.Equal(t, append(slices.Clone(cs), search.ByEcosystem(cataloged.Language, cataloged.Type)), asked[0],
		"an OS search carries no ecosystem, so the rules read the cataloged package's")

	type searched struct {
		name, distro string
		stream       Stream
	}
	var searches []searched
	for _, s := range got {
		searches = append(searches, searched{
			name:   s.criteria[0].(*search.PackageNameCriteria).PackageName,
			distro: s.criteria[1].(*search.DistroCriteria).Distros[0].Name(),
			stream: s.stream,
		})
	}
	require.Equal(t, []searched{
		{name: "rf-curl", distro: "debian", stream: StreamOwn},
		{name: "curl", distro: "debian", stream: StreamOwn},
		{name: "rf-curl", distro: "echo", stream: StreamRuled},
		{name: "curl", distro: "echo", stream: StreamRuled},
	}, searches)
}
