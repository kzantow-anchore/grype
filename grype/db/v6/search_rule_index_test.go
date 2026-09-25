package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// linearMatchingRules is the unindexed reference the index must agree with.
func linearMatchingRules(idx *searchRuleIndex, s searchSubject) []matchedRule {
	var matched []matchedRule
	for _, r := range idx.rules {
		if m, ok := r.match(s); ok {
			matched = append(matched, matchedRule{rule: r, match: m})
		}
	}
	return matched
}

func ordsOf(rules []matchedRule) []int {
	out := make([]int, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.rule.ord)
	}
	return out
}

// The index must not change which rules match nor their order, which decides search order and so
// reaches grype's output.
func TestSearchRuleIndex_MatchesLinearScan(t *testing.T) { //nolint:funlen // one fixture rule set plus the package shapes it has to cover
	rows := append(KnownSearchRules(),
		// unscoped
		SearchRule{MatchPackageName: `unscoped-.*`, ReplacementPackageName: "vendor-$0"},
		// distro version predicate with no distro name
		SearchRule{MatchDistroVersion: `9.*`, MatchPackageName: `.*`, ReplacementPackageName: "byver-$0"},
		// uppercase distro name
		SearchRule{MatchDistroName: "RapidFort-RedHat", MatchPackageName: `upper-.*`, ReplacementChannel: ptr("upper"), Priority: 99},
		// several exact package names under one distro
		SearchRule{MatchDistroName: "debian", MatchPackageName: `curl`, ReplacementPackageName: "curl-exact"},
		SearchRule{MatchDistroName: "debian", MatchPackageName: `curl`, ReplacementPackageName: "curl-also"},
		// ecosystem-scoped with an exact name
		SearchRule{MatchEcosystem: "apk", MatchPackageName: `busybox`, ReplacementPackageName: "busybox-alt"},
	)
	idx := newSearchRuleIndex(rows)
	require.Len(t, idx.rules, len(rows), "every rule in this fixture must compile")

	debian := distro.New(distro.Debian, "11", "")
	rfRedhat := distro.New(distro.RapidFortRedHat, "9", "")
	rfRedhatEUS := distro.New(distro.RapidFortRedHat, "9", "")
	rfRedhatEUS.Channels = []string{"eus"}

	subjects := map[string]searchSubject{
		"no OS at all": {
			name:    "curl",
			version: "1.2.3-4",
		},
		"one OS": {
			name:    "curl",
			version: "1.2.3-4",
			distro:  debian,
		},
		"one OS, exact-name rules apply": {
			name:    "curl",
			version: "1.1.1n-0+deb11u4.echo1",
			distro:  debian,
		},
		"a distro carrying a channel": {
			name:    "curl",
			version: "7.78.0-3.fc43",
			distro:  rfRedhatEUS,
		},
		"uppercase rule reached by a lowercase distro name": {
			name:    "upper-thing",
			version: "1.0-1",
			distro:  rfRedhat,
		},
		"an unknown distro type no rule speaks for": {
			name:    "curl",
			version: "1.0-1",
			distro:  distro.New(distro.Type("not-a-real-distro"), "1", ""),
		},
		"ecosystem only": {
			name:      "busybox",
			version:   "1.36.1-r15",
			ecosystem: string(syftPkg.ApkPkg),
		},
		"ecosystem and OS together": {
			name:      "openssl",
			version:   "1.1.1n-0+deb11u4.echo1",
			ecosystem: string(syftPkg.DebPkg),
			distro:    debian,
		},
		"no package name": {
			version: "7.78.0-3.fc43",
			distro:  rfRedhat,
		},
		"no version": {
			name:   "rf-scanner",
			distro: rfRedhat,
		},
	}

	for name, s := range subjects {
		t.Run(name, func(t *testing.T) {
			want := linearMatchingRules(idx, s)
			got := matchingRules(idx, s)
			assert.Equal(t, ordsOf(want), ordsOf(got),
				"the index selected different rules (or a different order) than a linear scan")
		})
	}
}

// A rule reachable through two buckets would be applied twice.
func TestSearchRuleIndex_FilesEveryRuleExactlyOnce(t *testing.T) {
	idx := newSearchRuleIndex(append(KnownSearchRules(),
		SearchRule{MatchPackageName: `unscoped-.*`, ReplacementPackageName: "vendor-$0"},
		// both a distro name and an ecosystem: filed under the distro
		SearchRule{MatchDistroName: "debian", MatchEcosystem: "deb", MatchPackageName: `curl`, ReplacementPackageName: "x"},
	))

	filed := map[int]int{}
	count := func(rules []*compiledSearchRule) {
		for _, r := range rules {
			filed[r.ord]++
		}
	}
	for _, b := range idx.byDistroName {
		count(b)
	}
	for _, b := range idx.byEcosystem {
		count(b)
	}
	count(idx.unscoped)

	require.Len(t, filed, len(idx.rules), "every rule must be filed somewhere")
	for _, r := range idx.rules {
		assert.Equalf(t, 1, filed[r.ord], "rule %d is filed in more than one bucket", r.ord)
	}
}
