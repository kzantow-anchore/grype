package v6

import (
	"slices"
	"strings"
)

// searchRuleIndex files compiled rules by their exact-match predicates (MatchDistroName,
// MatchEcosystem) so a query evaluates only the rules that could match it. The regex predicates
// then decide, so the index never changes which rules apply.
type searchRuleIndex struct {
	// rules is the compiled set in the order it was read; the buckets below hold the same pointers
	rules []*compiledSearchRule

	// byDistroName files rules with a MatchDistroName, keyed by its lowercased value
	byDistroName map[string][]*compiledSearchRule

	// byEcosystem files rules with no distro name but a MatchEcosystem, keyed by its lowercased value
	byEcosystem map[string][]*compiledSearchRule

	// unscoped holds rules with neither, which are candidates for every query
	unscoped []*compiledSearchRule
}

func newSearchRuleIndex(rows []SearchRule) *searchRuleIndex {
	idx := &searchRuleIndex{
		rules:        compileSearchRules(rows),
		byDistroName: map[string][]*compiledSearchRule{},
		byEcosystem:  map[string][]*compiledSearchRule{},
	}

	for i, r := range idx.rules {
		r.ord = i

		// each rule is filed under exactly one bucket, so candidates need no deduplication
		switch {
		case r.row.MatchDistroName != "":
			key := strings.ToLower(r.row.MatchDistroName)
			idx.byDistroName[key] = append(idx.byDistroName[key], r)
		case r.row.MatchEcosystem != "":
			key := strings.ToLower(r.row.MatchEcosystem)
			idx.byEcosystem[key] = append(idx.byEcosystem[key], r)
		default:
			idx.unscoped = append(idx.unscoped, r)
		}
	}

	return idx
}

// candidates appends the rules that could match s to dst, in the order the rules were read, so the
// result equals a linear scan over the whole set.
func (idx *searchRuleIndex) candidates(s searchSubject, dst []*compiledSearchRule) []*compiledSearchRule {
	if idx == nil || len(idx.rules) == 0 {
		return dst
	}

	dst = append(dst, idx.unscoped...)

	if s.distro != nil {
		if name := strings.ToLower(s.distro.Name()); name != "" {
			dst = append(dst, idx.byDistroName[name]...)
		}
	}

	if s.ecosystem != "" {
		dst = append(dst, idx.byEcosystem[strings.ToLower(s.ecosystem)]...)
	}

	slices.SortFunc(dst, func(a, b *compiledSearchRule) int { return a.ord - b.ord })
	return dst
}
