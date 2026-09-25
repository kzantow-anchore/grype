package v6

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestSearchRule_Validate(t *testing.T) { //nolint:funlen // one case per validation rule
	tests := []struct {
		name    string
		row     SearchRule
		wantErr string
	}{
		{
			name:    "no predicate at all",
			row:     SearchRule{ReplacementDistroName: ptr("echo")},
			wantErr: "must have at least one predicate",
		},
		{
			name:    "replacement package name without a name pattern",
			row:     SearchRule{ReplacementPackageName: "$1", MatchPackageVersion: `.*\.rf.*`},
			wantErr: "must have a package name pattern",
		},
		{
			name:    "channel substitution without a distro name",
			row:     SearchRule{MatchPackageVersion: `.*\.rf.*`, ReplacementChannel: ptr("rf")},
			wantErr: "must have a distro name to match",
		},
		{
			name:    "substitution without package predicates",
			row:     SearchRule{MatchDistroName: "debian", ReplacementChannel: ptr("rf")},
			wantErr: "must have at least one package predicate",
		},
		{
			name:    "invalid pattern",
			row:     SearchRule{MatchDistroName: "debian", MatchPackageVersion: `(`, ReplacementChannel: ptr("rf")},
			wantErr: "invalid pattern",
		},
		{
			name:    "positional reference beyond the pattern's groups",
			row:     SearchRule{MatchDistroName: "d", MatchPackageVersion: `.*\.fc(\d+)`, ReplacementChannel: ptr("fc$2")},
			wantErr: "exceeds the 1 groups",
		},
		{
			name:    "positional channel reference with no version pattern",
			row:     SearchRule{MatchDistroName: "d", MatchPackageName: `(rf)-.*`, ReplacementChannel: ptr("$1")},
			wantErr: "no pattern to resolve against",
		},
		{
			name:    "positional reference in a distro name",
			row:     SearchRule{MatchPackageVersion: `.*\+(echo)\d*`, ReplacementDistroName: ptr("$1")},
			wantErr: "use a named group",
		},
		{
			name:    "a reference to a group no pattern names",
			row:     SearchRule{MatchDistroName: "d", MatchPackageVersion: `.*\.fc(?P<release>\d+)`, ReplacementChannel: ptr("fc${fedora}")},
			wantErr: "names no group",
		},
		{
			// Go's template rules: `$1x` is the group named "1x", not group 1 then "x"
			name:    "an unbraced reference runs to the end of the name",
			row:     SearchRule{MatchDistroName: "d", MatchPackageVersion: `.*\.fc(\d+)`, ReplacementChannel: ptr("$1x")},
			wantErr: "names no group",
		},
		{
			name:    "an exclude pattern's groups are not referenceable",
			row:     SearchRule{MatchDistroName: "d", MatchPackageName: `.*`, ExcludePackageVersion: `.*\.(?P<tag>el)\d+`, ReplacementChannel: ptr("${tag}")},
			wantErr: "names no group",
		},
		{
			name:    "a group named by two patterns is ambiguous",
			row:     SearchRule{MatchDistroName: "d", MatchPackageName: `(?P<x>.*)`, MatchPackageVersion: `(?P<x>.*)`, ReplacementChannel: ptr("${x}")},
			wantErr: "more than one pattern",
		},
		{
			name: "a name repeated across alternation branches of one pattern",
			row:  SearchRule{MatchDistroName: "d", MatchPackageVersion: `.*\.fc(?P<v>\d+)|.*\.f(?P<v>\d+)`, ReplacementChannel: ptr("fc${v}")},
		},
		{
			name: "named references resolve across patterns",
			row:  SearchRule{MatchDistroName: "d", MatchDistroVersion: `(?P<major>\d+).*`, MatchPackageName: `(?P<base>.*)-rf`, ReplacementChannel: ptr("el${major}"), ReplacementPackageName: "${base}"},
		},
		{
			name: "a named distro name reference",
			row:  SearchRule{MatchEcosystem: "deb", MatchPackageVersion: `.*\+(?P<vendor>echo)\d*`, ReplacementDistroName: ptr("${vendor}")},
		},
		{
			name: "a rule that substitutes nothing may omit package predicates",
			row:  SearchRule{MatchDistroName: "rapidfort-alpine"},
		},
		{
			name: "an ecosystem-scoped rule may omit package predicates too",
			row:  SearchRule{MatchEcosystem: "apk"},
		},
		{
			name: "a distro version alone is a predicate",
			row:  SearchRule{MatchDistroVersion: `9.*`},
		},
		{
			name: "a rule that substitutes nothing may still name the packages it speaks for",
			row:  SearchRule{MatchDistroName: "rapidfort-alpine", MatchPackageName: "curl"},
		},
		{
			// a distroless search is not a substitution
			name: "a rule naming the NVD records may omit package predicates",
			row:  SearchRule{MatchDistroName: "rapidfort-alpine", ReplacementDistroName: ptr("")},
		},
		{
			name: "distro name substitution without a distro predicate is legal (echo shape)",
			row:  SearchRule{MatchEcosystem: "deb", MatchPackageVersion: `.*[.-]echo.*`, ReplacementDistroName: ptr("echo")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.row.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestParseTemplate(t *testing.T) {
	groups := []string{"whole", "one"}
	named := map[string]string{"name": "N", "1x": "ONE-X"}
	tests := []struct {
		template string
		want     string
	}{
		{template: "", want: ""},
		{template: "rf", want: "rf"},
		{template: "fc$1", want: "fcone"},
		{template: "${1}x", want: "onex"},
		{template: "$1x", want: "ONE-X"},
		{template: "$0", want: "whole"},
		{template: "$name-$1", want: "N-one"},
		{template: "${name}s", want: "Ns"},
		{template: "$$1", want: "$1"},
		{template: "a$", want: "a$"},
		{template: "a$-b", want: "a$-b"},
		{template: "${name", want: "${name"},
		{template: "$9", want: ""},
		{template: "${missing}", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.template, func(t *testing.T) {
			assert.Equal(t, tt.want, parseTemplate(tt.template).expand(groups, named))
		})
	}
}

func TestKnownSearchRules_AllValid(t *testing.T) {
	for _, r := range KnownSearchRules() {
		assert.NoError(t, r.Validate())
	}
	rules := newSearchRuleIndex(KnownSearchRules())
	assert.Len(t, rules.rules, len(KnownSearchRules()), "every built-in rule must compile")
}

// searchOf states a search as a matcher makes it: a name, a version and an OS or ecosystem.
func searchOf(name, ver string, format version.Format, extra ...vulnerability.Criteria) []vulnerability.Criteria {
	cs := []vulnerability.Criteria{search.ByPackageName(name)}
	if ver != "" {
		cs = append(cs, search.WithVersion(*version.New(ver, format)))
	}
	return append(cs, extra...)
}

func rulesProvider(rows ...SearchRule) vulnerabilityProvider {
	return vulnerabilityProvider{searchRules: newSearchRuleIndex(rows)}
}

func TestVulnerabilityProvider_SearchRewrites_KnownRules(t *testing.T) { //nolint:funlen // one case per built-in rule
	vp := rulesProvider(KnownSearchRules()...)
	rfRedhat := *distro.New(distro.RapidFortRedHat, "9", "")
	rfUbuntu := *distro.New(distro.RapidFortUbuntu, "22.04", "")
	rfAlpine := *distro.New(distro.RapidFortAlpine, "3.18", "")
	apk := search.ByEcosystem(syftPkg.UnknownLanguage, syftPkg.ApkPkg)

	channels := func(rw SearchRewrites) []string {
		var out []string
		for _, d := range rw.Distros {
			out = append(out, d.Name()+"@"+d.Version+"+"+strings.Join(d.Channels, ","))
		}
		return out
	}

	tests := []struct {
		name     string
		criteria []vulnerability.Criteria
		want     []string
		wantExcl bool
	}{
		{
			name:     "rapidfort-redhat rf rebuild marker",
			criteria: searchOf("curl", "7.76.1-29.el9.rf.1", version.RpmFormat, search.ByDistro(rfRedhat)),
			want:     []string{"rapidfort-redhat@9+rf"},
		},
		{
			name:     "rapidfort-redhat fedora dist tag binds the first tag",
			criteria: searchOf("curl", "7.78.0-3.fc31.fc43", version.RpmFormat, search.ByDistro(rfRedhat)),
			want:     []string{"rapidfort-redhat@9+fc31"},
		},
		{
			name:     "the rebuild marker outranks the dist tag",
			criteria: searchOf("curl", "7.78.0-3.fc43.rf.1", version.RpmFormat, search.ByDistro(rfRedhat)),
			want:     []string{"rapidfort-redhat@9+rf"},
		},
		{
			name:     "rf- name fallback",
			criteria: searchOf("rf-scanner", "1.0-1", version.RpmFormat, search.ByDistro(rfRedhat)),
			want:     []string{"rapidfort-redhat@9+rf"},
		},
		{
			name:     "rf- name with a native el version is channel-less",
			criteria: searchOf("rf-scanner", "1.0-1.el9", version.RpmFormat, search.ByDistro(rfRedhat)),
		},
		{
			name:     "rf- name with a dist tag follows the dist tag",
			criteria: searchOf("rf-scanner", "1.0-1.fc43", version.RpmFormat, search.ByDistro(rfRedhat)),
			want:     []string{"rapidfort-redhat@9+fc43"},
		},
		{
			name:     "native el version",
			criteria: searchOf("curl", "7.76.1-29.el9", version.RpmFormat, search.ByDistro(rfRedhat)),
		},
		{
			name:     "rapidfort-ubuntu rebuild",
			criteria: searchOf("curl", "7.81.0-1ubuntu1.15rfubu1", version.DebFormat, search.ByDistro(rfUbuntu)),
			want:     []string{"rapidfort-ubuntu@22.04+rf"},
		},
		{
			name:     "rapidfort-ubuntu pre-release rebuild marker",
			criteria: searchOf("curl", "7.81.0-1rfubuntu1.15~rf.1", version.DebFormat, search.ByDistro(rfUbuntu)),
			want:     []string{"rapidfort-ubuntu@22.04+rf"},
		},
		{
			name:     "rapidfort-debian rebuild",
			criteria: searchOf("curl", "7.88.1-10+rf.1", version.DebFormat, search.ByDistro(*distro.New(distro.RapidFortDebian, "12", ""))),
			want:     []string{"rapidfort-debian@12+rf"},
		},
		{
			name:     "rapidfort-debian stock build",
			criteria: searchOf("curl", "7.88.1-10+deb12u5", version.DebFormat, search.ByDistro(*distro.New(distro.RapidFortDebian, "12", ""))),
		},
		{
			name:     "rapidfort-ubuntu stock build",
			criteria: searchOf("rf-curl", "7.81.0-1ubuntu1.15", version.DebFormat, search.ByDistro(rfUbuntu)),
		},
		{
			name:     "rapidfort-alpine apk states its data is complete",
			criteria: searchOf("curl", "8.5.0-r0", version.ApkFormat, search.ByDistro(rfAlpine), apk),
			wantExcl: true,
		},
		{
			name:     "rapidfort-alpine rule speaks only for apk packages",
			criteria: searchOf("curl", "8.5.0-r0", version.ApkFormat, search.ByDistro(rfAlpine), search.ByEcosystem(syftPkg.JavaScript, syftPkg.NpmPkg)),
		},
		{
			name:     "stock alpine",
			criteria: searchOf("curl", "8.5.0-r0", version.ApkFormat, search.ByDistro(*distro.New(distro.Alpine, "3.18", "")), apk),
		},
		{
			name:     "echo marker on debian",
			criteria: searchOf("curl", "7.88.1-10+deb12u5.echo1", version.DebFormat, search.ByDistro(*distro.New(distro.Debian, "12", "")), search.ByEcosystem(syftPkg.UnknownLanguage, syftPkg.DebPkg)),
			want:     []string{"echo@12+"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vp.SearchRewrites(tt.criteria)
			assert.Equal(t, tt.want, channels(got))
			assert.Equal(t, tt.wantExcl, got.ExcludeOSLess)
			assert.Empty(t, got.PackageNames)
		})
	}
}

// One case per replacement a rule can make, each reached by the search criteria alone.
func TestVulnerabilityProvider_SearchRewrites_Replacements(t *testing.T) { //nolint:funlen // one case per replacement type
	rfRedhat := *distro.New(distro.RapidFortRedHat, "9.4", "")
	deb := *distro.New(distro.Debian, "12", "")
	deb.Channels = []string{"x"}
	debEco := search.ByEcosystem(syftPkg.UnknownLanguage, syftPkg.DebPkg)

	t.Run("channel: literal", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageVersion: `.*\.rf`, ReplacementChannel: ptr("rf")})
		got := vp.SearchRewrites(searchOf("curl", "1.0-1.rf", version.RpmFormat, search.ByDistro(rfRedhat)))
		require.Len(t, got.Distros, 1)
		assert.Equal(t, "rapidfort-redhat", got.Distros[0].Name())
		assert.Equal(t, "9.4", got.Distros[0].Version, "the searched OS version is kept")
		assert.Equal(t, []string{"rf"}, got.Distros[0].Channels)
	})

	t.Run("channel: positional group of the version pattern", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageVersion: `.*?\.fc(\d+).*`, ReplacementChannel: ptr("fc$1")})
		got := vp.SearchRewrites(searchOf("curl", "1.0-1.fc31.fc43", version.RpmFormat, search.ByDistro(rfRedhat)))
		require.Len(t, got.Distros, 1)
		assert.Equal(t, []string{"fc31"}, got.Distros[0].Channels)
	})

	t.Run("channel: named group of the version pattern", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageVersion: `.*?\.fc(?P<fedora>\d+).*`, ReplacementChannel: ptr("fc${fedora}")})
		got := vp.SearchRewrites(searchOf("curl", "1.0-1.fc43", version.RpmFormat, search.ByDistro(rfRedhat)))
		require.Len(t, got.Distros, 1)
		assert.Equal(t, []string{"fc43"}, got.Distros[0].Channels)
	})

	t.Run("channel: named group of the distro version pattern", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchDistroName: "rapidfort-redhat", MatchDistroVersion: `(?P<major>\d+)(?:\..*)?`, MatchPackageName: `rf-.*`, ReplacementChannel: ptr("el${major}")})
		got := vp.SearchRewrites(searchOf("rf-curl", "1.0-1", version.RpmFormat, search.ByDistro(rfRedhat)))
		require.Len(t, got.Distros, 1)
		assert.Equal(t, []string{"el9"}, got.Distros[0].Channels)
	})

	t.Run("channel: named group of the name pattern", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `(?P<stream>rf|fips)-.*`, ReplacementChannel: ptr("${stream}")})
		got := vp.SearchRewrites(searchOf("fips-openssl", "3.0-1", version.RpmFormat, search.ByDistro(rfRedhat)))
		require.Len(t, got.Distros, 1)
		assert.Equal(t, []string{"fips"}, got.Distros[0].Channels)
	})

	t.Run("channel: an empty expansion selects the channel-less rows", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchDistroName: "debian", MatchPackageVersion: `.*?(?:\+(?P<ch>rf))?`, ReplacementChannel: ptr("${ch}")})
		got := vp.SearchRewrites(searchOf("curl", "1.0-1", version.DebFormat, search.ByDistro(deb)))
		require.Len(t, got.Distros, 1)
		assert.Empty(t, got.Distros[0].Channels, "the searched OS's own channels are dropped too")
	})

	t.Run("distro name: literal, on an OS search", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchEcosystem: "deb", MatchPackageVersion: `.*[.-]echo.*`, ReplacementDistroName: ptr("echo")})
		got := vp.SearchRewrites(searchOf("curl", "7.88.1-10+deb12u5.echo1", version.DebFormat, search.ByDistro(deb), debEco))
		require.Len(t, got.Distros, 1)
		assert.Equal(t, "echo", got.Distros[0].Name())
		assert.Equal(t, "12", got.Distros[0].Version, "the searched OS version is kept")
		assert.Empty(t, got.Distros[0].Channels, "the searched OS's channels are dropped")
		assert.False(t, got.ExcludeOSLess, "a substitution adds partitions without excluding any")
	})

	t.Run("distro name: literal, on an OS-less search", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchEcosystem: "deb", MatchPackageVersion: `.*[.-]echo.*`, ReplacementDistroName: ptr("echo")})
		got := vp.SearchRewrites(searchOf("curl", "7.88.1-10+deb12u5.echo1", version.DebFormat, debEco))
		require.Len(t, got.Distros, 1)
		assert.Equal(t, "echo", got.Distros[0].Name())
		assert.Empty(t, got.Distros[0].Version, "an OS-less search gains the OS version-free")
	})

	t.Run("distro name: named group", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchEcosystem: "deb", MatchPackageVersion: `.*[.+-](?P<vendor>echo|minimus)\d*`, ReplacementDistroName: ptr("${vendor}")})
		got := vp.SearchRewrites(searchOf("curl", "7.88.1-10+deb12u5.echo1", version.DebFormat, search.ByDistro(deb), debEco))
		require.Len(t, got.Distros, 1)
		assert.Equal(t, "echo", got.Distros[0].Name())
	})

	t.Run("distro name and channel together", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchDistroName: "debian", MatchPackageVersion: `.*\+(?P<vendor>echo)(?P<n>\d+)`, ReplacementDistroName: ptr("${vendor}"), ReplacementChannel: ptr("v${n}")})
		got := vp.SearchRewrites(searchOf("curl", "1.0-1+echo2", version.DebFormat, search.ByDistro(deb)))
		require.Len(t, got.Distros, 1)
		assert.Equal(t, "echo", got.Distros[0].Name())
		assert.Equal(t, "12", got.Distros[0].Version)
		assert.Equal(t, []string{"v2"}, got.Distros[0].Channels)
	})

	t.Run("package name: positional group of the name pattern", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchDistroName: "debian", MatchPackageName: `rf-(.+)`, ReplacementPackageName: "$1"})
		got := vp.SearchRewrites(searchOf("rf-curl", "1.0-1", version.DebFormat, search.ByDistro(deb)))
		assert.Equal(t, []string{"curl"}, got.PackageNames)
		assert.Empty(t, got.Distros)
	})

	t.Run("package name: named group, on an ecosystem search (rootio shape)", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchEcosystem: "python", MatchPackageName: `rootio[-_](?P<upstream>.+)`, ReplacementPackageName: "${upstream}"})
		got := vp.SearchRewrites(searchOf("rootio-requests", "2.31.0", version.PythonFormat, search.ByEcosystem(syftPkg.Python, syftPkg.PythonPkg)))
		assert.Equal(t, []string{"requests"}, got.PackageNames)
		assert.False(t, got.ExcludeOSLess)
	})

	t.Run("package name: named group of the version pattern", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchEcosystem: "java-archive", MatchPackageName: `.*`, MatchPackageVersion: `.*\.(?P<flavor>jre\d+)`, ReplacementPackageName: "$0-${flavor}"})
		got := vp.SearchRewrites(searchOf("guava", "32.1.3.jre8", version.MavenFormat, search.ByEcosystem(syftPkg.Java, syftPkg.JavaPkg)))
		assert.Equal(t, []string{"guava-jre8"}, got.PackageNames)
	})

	t.Run("package name: the searched name and repeats are not added", func(t *testing.T) {
		vp := rulesProvider(
			SearchRule{MatchDistroName: "debian", MatchPackageName: `(cu)rl`, ReplacementPackageName: "rf-$1"},
			SearchRule{MatchDistroName: "debian", MatchPackageName: `cu(?P<rest>rl)`, ReplacementPackageName: "cu${rest}"},
			SearchRule{MatchDistroName: "debian", MatchPackageName: `(?P<n>curl)`, ReplacementPackageName: "rf-cu"},
		)
		got := vp.SearchRewrites(searchOf("curl", "1.0-1", version.DebFormat, search.ByDistro(deb)))
		assert.Equal(t, []string{"rf-cu"}, got.PackageNames)
	})

	t.Run("no substitution: the OS-less partition is excluded", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchDistroName: "debian", MatchPackageName: `curl`})
		assert.Equal(t, SearchRewrites{ExcludeOSLess: true}, vp.SearchRewrites(searchOf("curl", "1.0-1", version.DebFormat, search.ByDistro(deb))))
	})

	t.Run("distroless: a rule naming the OS-less partition keeps it searched", func(t *testing.T) {
		vp := rulesProvider(
			SearchRule{MatchDistroName: "debian", MatchPackageVersion: `.*\+rf.*`, ReplacementChannel: ptr("rf"), Priority: 30},
			SearchRule{MatchDistroName: "debian"},
			SearchRule{MatchDistroName: "debian", ReplacementDistroName: ptr("")},
		)
		got := vp.SearchRewrites(searchOf("curl", "1.0-1+rf1", version.DebFormat, search.ByDistro(deb)))
		assert.False(t, got.ExcludeOSLess)
		require.Len(t, got.Distros, 1, "the OS-less rule adds no store search")
		assert.Equal(t, []string{"rf"}, got.Distros[0].Channels)
	})
}

func TestVulnerabilityProvider_SearchRewrites_Criteria(t *testing.T) { //nolint:funlen // one case per criteria shape
	rfRedhat := *distro.New(distro.RapidFortRedHat, "9", "")
	rhel := *distro.New(distro.RedHat, "9", "")
	channelRule := SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `curl`, MatchPackageVersion: `.*\.rf`, ReplacementChannel: ptr("rf")}
	vp := rulesProvider(channelRule)

	t.Run("the version may constrain results or only be conveyed", func(t *testing.T) {
		v := *version.New("1.0-1.rf", version.RpmFormat)
		for _, vc := range []vulnerability.Criteria{search.ByVersion(v), search.WithVersion(v)} {
			got := vp.SearchRewrites([]vulnerability.Criteria{search.ByPackageName("curl"), search.ByDistro(rfRedhat), vc})
			assert.Len(t, got.Distros, 1)
		}
	})

	t.Run("an indirect package name is the searched name", func(t *testing.T) {
		got := vp.SearchRewrites([]vulnerability.Criteria{search.ByIndirectPackageName("curl"), search.ByDistro(rfRedhat), search.WithVersion(*version.New("1.0-1.rf", version.RpmFormat))})
		assert.Len(t, got.Distros, 1)
	})

	t.Run("a predicate whose subject the search does not state does not match", func(t *testing.T) {
		assert.Zero(t, vp.SearchRewrites([]vulnerability.Criteria{search.ByPackageName("curl"), search.ByDistro(rfRedhat)}), "no version")
		assert.Zero(t, vp.SearchRewrites(searchOf("", "1.0-1.rf", version.RpmFormat, search.ByDistro(rfRedhat))), "no name")
		assert.Zero(t, vp.SearchRewrites(searchOf("curl", "1.0-1.rf", version.RpmFormat)), "no OS")
	})

	t.Run("each OS of a search is rewritten on its own", func(t *testing.T) {
		got := vp.SearchRewrites(searchOf("curl", "1.0-1.rf", version.RpmFormat, search.ByDistro(rhel, rfRedhat)))
		require.Len(t, got.Distros, 1)
		assert.Equal(t, "rapidfort-redhat", got.Distros[0].Name())
	})

	t.Run("the ecosystem falls back to the language", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchEcosystem: "python", MatchPackageName: `rootio-(.+)`, ReplacementPackageName: "$1"})
		got := vp.SearchRewrites(searchOf("rootio-requests", "", version.UnknownFormat, search.ByEcosystem(syftPkg.Python, "")))
		assert.Equal(t, []string{"requests"}, got.PackageNames)
	})

	t.Run("exclude patterns reject only a present subject", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `rf-.*`, ExcludePackageName: `rf-skip`, ExcludePackageVersion: `.*\.el\d+`, ReplacementChannel: ptr("rf")})
		assert.Len(t, vp.SearchRewrites(searchOf("rf-curl", "1.0-1", version.RpmFormat, search.ByDistro(rfRedhat))).Distros, 1)
		assert.Len(t, vp.SearchRewrites(searchOf("rf-curl", "", version.UnknownFormat, search.ByDistro(rfRedhat))).Distros, 1, "no version to exclude")
		assert.Zero(t, vp.SearchRewrites(searchOf("rf-curl", "1.0-1.el9", version.RpmFormat, search.ByDistro(rfRedhat))))
		assert.Zero(t, vp.SearchRewrites(searchOf("rf-skip", "1.0-1", version.RpmFormat, search.ByDistro(rfRedhat))))
	})

	t.Run("the distro version matches the release, then the label", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchDistroName: "ubuntu", MatchDistroVersion: `(?P<code>jammy)`, MatchPackageName: `.*`, ReplacementChannel: ptr("${code}-rf")})
		ubuntu := *distro.New(distro.Ubuntu, "22.04", "jammy")
		got := vp.SearchRewrites(searchOf("curl", "", version.UnknownFormat, search.ByDistro(ubuntu)))
		require.Len(t, got.Distros, 1)
		assert.Equal(t, []string{"jammy-rf"}, got.Distros[0].Channels)
	})

	t.Run("only the highest priority rules apply", func(t *testing.T) {
		vp := rulesProvider(
			SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `curl`, ReplacementChannel: ptr("a"), Priority: 2},
			SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `curl`, ReplacementChannel: ptr("b"), Priority: 1},
		)
		got := vp.SearchRewrites(searchOf("curl", "", version.UnknownFormat, search.ByDistro(rfRedhat)))
		require.Len(t, got.Distros, 1)
		assert.Equal(t, []string{"a"}, got.Distros[0].Channels)
	})

	t.Run("rules tied at the winning priority all apply", func(t *testing.T) {
		vp := rulesProvider(
			SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `curl`, ReplacementChannel: ptr("a"), Priority: 2},
			SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `(cu)rl`, ReplacementPackageName: "rf-$1", Priority: 2},
			SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `curl`, ReplacementChannel: ptr("c"), Priority: 1},
		)
		got := vp.SearchRewrites(searchOf("curl", "", version.UnknownFormat, search.ByDistro(rfRedhat)))
		require.Len(t, got.Distros, 1)
		assert.Equal(t, []string{"a"}, got.Distros[0].Channels)
		assert.Equal(t, []string{"rf-cu"}, got.PackageNames)
	})
}

func TestFilterSearchRulesForClient(t *testing.T) {
	clientVersion := version.New("6.1.0", version.SemanticFormat)
	rows := []SearchRule{
		{MatchDistroName: "a", MatchPackageName: "x", ReplacementChannel: ptr("c")},
		{MatchDistroName: "b", MatchPackageName: "x", ReplacementChannel: ptr("c"), ApplicableClientDBSchemas: "< 6.0.0"},
		{MatchDistroName: "c", MatchPackageName: "x", ReplacementChannel: ptr("c"), ApplicableClientDBSchemas: ">= 6.0.0"},
		// an unparsable constraint fails open
		{MatchDistroName: "d", MatchPackageName: "x", ReplacementChannel: ptr("c"), ApplicableClientDBSchemas: "not-a-constraint"},
	}

	got := filterSearchRulesForClient(rows, clientVersion)
	var names []string
	for _, r := range got {
		names = append(names, r.MatchDistroName)
	}
	assert.Equal(t, []string{"a", "c", "d"}, names)
}
