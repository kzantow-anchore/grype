package result

import (
	"cmp"

	"github.com/anchore/grype/grype/match"
)

// Stream is how specifically the OS rows a result was found in describe the package's build.
type Stream int

const (
	// StreamOwn is the package's own OS rows, or no OS
	StreamOwn Stream = iota

	// StreamRuled is rows a search rule selected for this build (see v6.SearchRule)
	StreamRuled
)

// Rank decides which result wins when results for one vulnerability disagree: by stream, then by
// match type. A rule-selected stream outranks the package's own rows even when reached indirectly.
type Rank struct {
	Stream Stream

	// Kind is the strongest match type of the details the result was found with; details merged in
	// later do not change it
	Kind match.Type
}

func rankOf(stream Stream, details match.Details) Rank {
	return Rank{Stream: stream, Kind: details.BestType()}
}

// Compare is positive when r outranks o.
func (r Rank) Compare(o Rank) int {
	if c := cmp.Compare(r.Stream, o.Stream); c != 0 {
		return c
	}
	return -match.CompareTypes(r.Kind, o.Kind)
}
