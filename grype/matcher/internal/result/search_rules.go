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

type ruledSearch struct {
	criteria []vulnerability.Criteria
	stream   Stream
}

// applySearchRules expands one criteria set into the searches the rules call for: the original plus
// any rewrites, or none when the rules exclude it.
func applySearchRules(vp vulnerability.Provider, catalogedPkg pkg.Package, cs []vulnerability.Criteria) []ruledSearch {
	own := []ruledSearch{{criteria: cs, stream: StreamOwn}}

	rp, ok := vp.(v6.SearchRuleProvider)
	if !ok {
		return own
	}

	distroIdx, nameIdx := searchDimensions(cs)

	rw := rp.SearchRewrites(ruleCriteria(catalogedPkg, cs))
	if distroIdx < 0 && catalogedPkg.Distro != nil && slices.ContainsFunc(cs, isCPECriteria) {
		// a CPE search for an OS package: rewritten OS rows are searched by the OS search, so only
		// the exclusion applies
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

// ruledSearchSet drops searches that read the same OS rows as an earlier one.
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

// ruleCriteria adds what the rules read but cs lacks, from the cataloged package: the ecosystem, and
// for a CPE search the name, version and OS. Used only to select rules, never searched.
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

func withDistro(cs []vulnerability.Criteria, distroIdx int, d distro.Distro) []vulnerability.Criteria {
	out := slices.Clone(cs)
	dc := &search.DistroCriteria{Distros: []distro.Distro{d}}
	if distroIdx < 0 {
		return append(out, dc)
	}
	if original, ok := cs[distroIdx].(*search.DistroCriteria); ok {
		dc.Exact = original.Exact
	}
	out[distroIdx] = dc
	return out
}

// fanOutNames adds a copy of every search per additional name. Only the first search keeps its CPE
// criteria, since the copies would read the same CPE rows again.
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

	for i := 1; i < len(out); i++ {
		out[i].criteria = withoutCPECriteria(out[i].criteria)
	}
	return out
}

func withoutCPECriteria(cs []vulnerability.Criteria) []vulnerability.Criteria {
	return slices.DeleteFunc(slices.Clone(cs), isCPECriteria)
}

func isCPECriteria(c vulnerability.Criteria) bool {
	_, ok := c.(*search.CPECriteria)
	return ok
}
