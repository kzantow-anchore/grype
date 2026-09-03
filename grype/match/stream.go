package match

import "slices"

// Stream is a SearchedBy payload marking the confidence of a stream's result. The value
// is Detail.Confidence; this payload is how a reader finds the detail carrying it.
type Stream struct {
	// Stream names the OS identity the search read -- a release channel, or another vendor's OS
	// rows -- for the audit trail. Empty when the search read the package's own data.
	Stream string `json:"stream,omitempty"`
}

// StreamDetail builds the detail recording how confidently one search speaks for the package.
func StreamDetail(matcher MatcherType, stream string, confidence float64) Detail {
	return Detail{
		Matcher:    matcher,
		SearchedBy: Stream{Stream: stream},
		Confidence: confidence,
	}
}

// WithoutStreamDetail returns the details without the one recording search confidence, which is
// a matching-time ranking signal rather than evidence for the match. The given set is never modified:
// a detail set is shared by every copy of the record it was found for.
func (m Details) WithoutStreamDetail() Details {
	return slices.DeleteFunc(m, func(d Detail) bool {
		_, isStream := d.SearchedBy.(Stream)
		return isStream
	})
}
