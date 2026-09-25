package result

import (
	"cmp"

	"github.com/anchore/grype/grype/match"
)

// Stream is how specifically the OS rows a result was found in describe the package's build.
type Stream int

const (
	// StreamOwn is the package's own rows: its OS, or the OS-less partition
	StreamOwn Stream = iota

	// StreamRuled is rows a search rule selected for this build (a channel of its OS, or another OS;
	// see v6.SearchRule)
	StreamRuled
)

// Rank is how authoritatively a result speaks for the package when the results for one
// vulnerability disagree (see internal.SplitVulnerable). It is the one ordering of results: compare
// with Compare, never by a field.
//
// Ranks order by stream first, then by the kind of match (see match.CompareTypes: direct, indirect,
// CPE). So a rule-selected stream outranks the package's own rows even when reached indirectly, and
// within a stream a direct match outranks an indirect one.
//
// Rank is not reported on matches. It is unrelated to SearchRule.Priority, which decides which rules
// select streams, not which results win.
type Rank struct {
	Stream Stream

	// Kind is the strongest match type of the result's own details, set when the result is found (an
	// indirect search says so, see search.ByIndirectPackageName). Details added later as evidence (see
	// keepMoreSpecificCandidates) do not change it.
	Kind match.Type
}

// rankOf is the rank of a result found in stream with details.
func rankOf(stream Stream, details match.Details) Rank {
	return Rank{Stream: stream, Kind: details.BestType()}
}

// Compare orders two ranks: positive when r outranks o, negative when o outranks r, zero when equal.
func (r Rank) Compare(o Rank) int {
	if c := cmp.Compare(r.Stream, o.Stream); c != 0 {
		return c
	}
	// CompareTypes orders strongest first
	return -match.CompareTypes(r.Kind, o.Kind)
}
