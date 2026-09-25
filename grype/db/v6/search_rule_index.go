package v6

import (
	"slices"
	"strings"
)

// searchRuleIndex buckets rules by their exact-match predicates so a query only evaluates rules that
// could match it. Each rule is in exactly one bucket.
type searchRuleIndex struct {
	rules []*compiledSearchRule

	// byDistroName is keyed by lowercased MatchDistroName
	byDistroName map[string][]*compiledSearchRule

	// byEcosystem holds rules with no MatchDistroName, keyed by lowercased MatchEcosystem
	byEcosystem map[string][]*compiledSearchRule

	// unscoped holds rules with neither
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

// candidates appends the rules that could match s to dst, in read order.
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
