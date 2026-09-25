package result

import (
	"slices"
	"strings"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

// Search rules (see v6.SearchRule) state which OperatingSystem rows (a release channel, another
// vendor's OS name) and which additional names a package is searched with. The provider resolves the
// rules into v6.SearchRewrites; this file turns those into the searches to run in place of
// one criteria set.
//
// The package's own search always runs; rewrites add to it. Each search records the stream it reads
// on the results it produces (see Rank): a stream selected for this build outranks the package's own
// rows.

// ruledSearch is one store search to run for a criteria set.
type ruledSearch struct {
	criteria []vulnerability.Criteria
	stream   Stream
}

// applySearchRules returns the searches to run for one criteria set: none when the rewrites exclude
// the partition it reads, the search as made when there are no rewrites. Rules are evaluated against
// the criteria the search carries (see ruleCriteria).
func applySearchRules(vp vulnerability.Provider, catalogedPkg pkg.Package, cs []vulnerability.Criteria) []ruledSearch {
	own := []ruledSearch{{criteria: cs, stream: StreamOwn}}

	rp, ok := vp.(v6.SearchRuleProvider)
	if !ok {
		return own
	}

	distroIdx, nameIdx := searchDimensions(cs)

	rw := rp.SearchRewrites(ruleCriteria(catalogedPkg, cs))
	if distroIdx < 0 && catalogedPkg.Distro != nil && slices.ContainsFunc(cs, isCPECriteria) {
		// an OS-less partition search (by CPE, the NVD records) for a package on an OS: the rewrites'
		// OS rows extend the package's own OS searches, so only the exclusion applies
		if rw.ExcludeOSLess {
			return nil
		}
		return own
	}
	if len(rw.Distros) == 0 && len(rw.PackageNames) == 0 {
		return own
	}

	out := ruledSearchSet{}
	out.add(cs, distroIdx, StreamOwn)
	for _, d := range rw.Distros {
		out.add(withDistro(cs, distroIdx, d), distroIdx, StreamRuled)
	}

	return fanOutNames(out.searches, rw.PackageNames, nameIdx)
}

// ruledSearchSet accumulates searches, dropping those reading the same OS rows as an earlier one (an
// overlay whose channel expanded empty reads the package's own rows); the first keeps its stream.
type ruledSearchSet struct {
	searches []ruledSearch
	seen     map[string]struct{}
}

func (s *ruledSearchSet) add(cs []vulnerability.Criteria, distroIdx int, stream Stream) {
	key := searchKey(cs, distroIdx)
	if s.seen == nil {
		s.seen = map[string]struct{}{}
	}
	if _, ok := s.seen[key]; ok {
		return
	}
	s.seen[key] = struct{}{}
	s.searches = append(s.searches, ruledSearch{criteria: cs, stream: stream})
}

// searchKey identifies the OS rows a search reads.
func searchKey(cs []vulnerability.Criteria, distroIdx int) string {
	if distroIdx < 0 {
		return ""
	}
	dc, ok := cs[distroIdx].(*search.DistroCriteria)
	if !ok {
		return ""
	}
	var out []string
	for _, d := range dc.Distros {
		out = append(out, strings.ToLower(d.Name())+"@"+d.Version+"@"+strings.ToLower(d.Codename)+"+"+strings.ToLower(strings.Join(d.Channels, ",")))
	}
	return strings.Join(out, "|")
}

// ruleCriteria is cs with what the search does not state but the rules read, taken from the
// cataloged package: its ecosystem (an OS search carries none), and on a CPE search, which carries no
// name, version or OS, the package's own. These criteria only select rules; they are never searched.
func ruleCriteria(catalogedPkg pkg.Package, cs []vulnerability.Criteria) []vulnerability.Criteria {
	var extra []vulnerability.Criteria
	if !slices.ContainsFunc(cs, isEcosystemCriteria) {
		extra = append(extra, search.ByEcosystem(catalogedPkg.Language, catalogedPkg.Type))
	}
	if slices.ContainsFunc(cs, isCPECriteria) {
		extra = append(extra, search.ByPackageName(catalogedPkg.Name))
		if catalogedPkg.Version != "" {
			extra = append(extra, search.WithVersion(*version.New(catalogedPkg.Version, pkg.VersionFormat(catalogedPkg))))
		}
		if catalogedPkg.Distro != nil {
			extra = append(extra, search.ByDistro(*catalogedPkg.Distro))
		}
	}
	if len(extra) == 0 {
		return cs
	}
	return append(slices.Clone(cs), extra...)
}

func isEcosystemCriteria(c vulnerability.Criteria) bool {
	_, ok := c.(*search.EcosystemCriteria)
	return ok
}

// searchDimensions locates the distro and name criteria a rewrite replaces.
func searchDimensions(criteria []vulnerability.Criteria) (distroIdx, nameIdx int) {
	distroIdx, nameIdx = -1, -1
	for i, c := range criteria {
		switch c.(type) {
		case *search.DistroCriteria:
			if distroIdx < 0 {
				distroIdx = i
			}
		case *search.PackageNameCriteria, *search.IndirectPackageNameCriteria:
			nameIdx = i
		}
	}
	return distroIdx, nameIdx
}

// withDistro is the criteria set with its distro criteria replaced by d, or gaining one if it had none.
func withDistro(cs []vulnerability.Criteria, distroIdx int, d distro.Distro) []vulnerability.Criteria {
	out := slices.Clone(cs)
	dc := &search.DistroCriteria{Distros: []distro.Distro{d}}
	if distroIdx < 0 {
		return append(out, dc)
	}
	// keep the original search's aliasing
	if original, ok := cs[distroIdx].(*search.DistroCriteria); ok {
		dc.Exact = original.Exact
	}
	out[distroIdx] = dc
	return out
}

// fanOutNames adds a copy of every search under every additional name the rewrites contribute.
// Derived names are not re-expanded. Only the first search keeps the CPE criteria, since rewrites
// never change it and every other search would read the same CPE rows again.
func fanOutNames(searches []ruledSearch, names []string, nameIdx int) []ruledSearch {
	if nameIdx < 0 {
		names = nil
	}

	out := make([]ruledSearch, 0, len(searches)*(1+len(names)))
	for _, s := range searches {
		out = append(out, s)
		for _, n := range names {
			withName := s
			withName.criteria = slices.Clone(s.criteria)
			withName.criteria[nameIdx] = search.WithPackageName(s.criteria[nameIdx], n)
			out = append(out, withName)
		}
	}

	for i := range out {
		if i == 0 {
			continue
		}
		out[i].criteria = withoutCPECriteria(out[i].criteria)
	}
	return out
}

func withoutCPECriteria(cs []vulnerability.Criteria) []vulnerability.Criteria {
	out := make([]vulnerability.Criteria, 0, len(cs))
	for _, c := range cs {
		if isCPECriteria(c) {
			continue
		}
		out = append(out, c)
	}
	return out
}

func isCPECriteria(c vulnerability.Criteria) bool {
	_, ok := c.(*search.CPECriteria)
	return ok
}
