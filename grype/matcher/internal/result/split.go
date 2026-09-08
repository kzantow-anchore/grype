package result

import (
	"slices"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// SplitVulnerable partitions the set into the records that say the searched version is vulnerable
// and everything else.
//
// The partition is made per affected version window, per release stream, and against the provider's
// unaffected records:
//
//   - One provider record can describe several affected version windows at once -- one build per
//     release line it patched -- each hydrated into its own vulnerability.Vulnerability with its own
//     constraint and fix. Only the windows this version falls inside are kept, so the fix a match
//     reports is the fix of the window it matched.
//
//   - A package can be described by more than one release stream at once (a base distro's rows and a
//     rebuild's channel), and the streams can disagree. The question is asked of one stream at a
//     time, most specific first, and the first stream with an answer gives it; a stream whose ranges
//     do not cover this version has no answer and the question falls through to the next one down.
//     How confidently a stream speaks for the package is read off the detail the search that
//     produced its records recorded it on (see confidenceOf).
//
//   - The set holds the provider's unaffected records (NAKs) alongside its affected ones. Those can
//     only deny, and are not ranked against the streams -- see the denials below.
//
// The second return is everything not reported, not merely what is fixed: it also holds records
// whose ranges do not cover this version at all, with no fix recorded. Callers use it to build the
// ignores applied to packages this one owns files for. A vulnerability reported in the first return
// never appears in the second.
//
// v is the version to test against for records that do not name their own; see searchedVersion for
// the ones that do.
func (s Set) SplitVulnerable(v *version.Version) (vulnerable, notVulnerable Set) {
	affected, unaffected := splitUnaffected(s)

	// constrain unaffected to those matching the provided version
	unaffected = filterByVersion(unaffected, v, matchesConstraints)

	// consider exact fix version matches to be strong evidence of unaffected
	unaffected = unaffected.Merge(keepByExactFixVersion(affected, v))

	// find all records matching the version constraint
	candidates := filterByVersion(affected, v, matchesConstraints)

	// keep records from other namespaces -- this is due to the way records are stored in the db:
	// we might have 2 or more vulnerability objects each with their own range and by matching one in a namespace,
	// we should ignore the others
	notVulnerable = affected.Filter(removeExactVulnerabilitiesByNamespace(candidates))

	if v != nil {
		// ensure the version all not vulnerable records fall inside the constraints
		notVulnerable = filterByVersion(notVulnerable, v, outsideConstraints)

		// only keep fixes
		notVulnerable = notVulnerable.Filter(search.ByFixedVersion(*v))
	}

	// remove records where we have a more specific result indicating the version is not vulnerable
	candidates = keepMoreSpecificCandidates(candidates, notVulnerable)

	// remove explicitly unaffected records
	vulnerable = candidates.Remove(unaffected)

	// An unaffected record whose ranges do not cover this version is left out of both legs: it is a
	// statement about other builds, and callers reconcile other sources against the not-vulnerable
	// leg, so letting it through would suppress a finding the provider never answered.
	return vulnerable, removeSame(affected, vulnerable).Merge(unaffected)
}

func keepByExactFixVersion(affected Set, v *version.Version) Set {
	if v == nil || v.Raw == "" {
		return Set{}
	}
	return affected.Filter(search.ByFunc(func(vuln vulnerability.Vulnerability) (bool, string, error) {
		matches := slices.Contains(vuln.Fix.Versions, v.Raw)
		if matches {
			return true, "", nil
		}
		return false, "does not have exact fix version", nil
	}))
}

func removeExactVulnerabilitiesByNamespace(candidates Set) vulnerability.Criteria {
	return search.ByFunc(func(incoming vulnerability.Vulnerability) (bool, string, error) {
		vulnerable := candidates[incoming.ID]
		for _, v := range vulnerable {
			for _, v := range v.Vulnerabilities {
				if v.ID == incoming.ID && v.Namespace == incoming.Namespace {
					return false, "same vulnerability ID", nil
				}
			}
		}
		return true, "", nil // keep, this is a unique namespace for the record
	})
}

// matchesConstraints is the criteria testing a record's affected range against the searched
// version. A search made without a version cannot rule anything out, so every record stays a
// candidate.
func matchesConstraints(v *version.Version) vulnerability.Criteria {
	if v == nil || v.Raw == "" {
		return search.ByFunc(func(vulnerability.Vulnerability) (bool, string, error) {
			return true, "", nil
		})
	}
	return search.ByVersion(*v)
}

// outsideConstraints indicates the vulnerability explicitly falls outside the vulnerable constraint range
func outsideConstraints(v *version.Version) vulnerability.Criteria {
	if v == nil || v.Raw == "" {
		return search.ByFunc(func(vulnerability.Vulnerability) (bool, string, error) {
			return false, "", nil
		})
	}
	return search.ByFunc(func(vuln vulnerability.Vulnerability) (bool, string, error) {
		matches, err := vuln.Constraint.Satisfied(v)
		if err != nil {
			return false, err.Error(), err
		}
		return !matches, "", nil
	})
}

//nolint:gocognit
func removeSame(s Set, removals Set) Set {
	// collect all incoming identifiers into one unified set
	incomingConfidenceScores := map[string]float64{}
	for id, results := range removals {
		confidence := 0.
		for _, result := range results {
			c := confidenceOf(result)
			if c > confidence {
				confidence = c
			}
			incomingConfidenceScores[id] = c
			for _, v := range result.Vulnerabilities {
				for _, alias := range v.RelatedVulnerabilities {
					if incomingConfidenceScores[alias.ID] < c {
						incomingConfidenceScores[alias.ID] = c
					}
				}
			}
		}
	}

	// keep only entries whose identities don't overlap with incoming
	out := Set{}
	for id, results := range s {
		incomingConfidence, ok := incomingConfidenceScores[id]
		if ok {
			// non-alias match for the whole set
			continue
		}
		// match each individual result's alias set against the incoming set's id and aliases
		results = slices.DeleteFunc(results, func(r Result) bool {
			c := confidenceOf(r)
			for _, v := range r.Vulnerabilities {
				for _, alias := range v.RelatedVulnerabilities {
					incomingAliasConfidence := incomingConfidenceScores[alias.ID]
					if c < incomingConfidence || c < incomingAliasConfidence {
						return true
					}
				}
			}
			return false
		})
		if len(results) == 0 {
			continue
		}
		out[id] = results
	}
	return out
}

// keepMoreSpecificCandidates returns a vulnerability criteria where we remove only vulnerabilities when there
// is more specific evidence in the notVulnerable set
func keepMoreSpecificCandidates(candidates, notVulnerable Set) Set {
	out := Set{}
	for id, results := range candidates {
		maxConfidence := 0.
		// keep the match details of every candidate we drop, so the evidence of a less-specific
		// finding is not lost when it is folded into the more-specific one that survives
		var droppedDetails match.Details
		// remove all results with lower confidence than the most specific result
		results = slices.DeleteFunc(results, func(candidate Result) bool {
			candidateConfidence := confidenceOf(candidate)
			if candidateConfidence > maxConfidence {
				maxConfidence = candidateConfidence
			}
			// if the candidate has lower confidence than a nak, drop it
			for _, nak := range notVulnerable[id] {
				nakConfidence := confidenceOf(nak)
				if candidateConfidence < nakConfidence {
					droppedDetails = append(droppedDetails, candidate.Details...)
					vulnerability.LogDropped(id, "SplitVulnerable", "the most specific stream describing this package reports the version fixed", nil)
					return true
				}
			}

			return false
		})

		// drop everything below the most specific result, collecting only the dropped candidates'
		// details -- a kept candidate already carries its own, so folding it back in here would
		// duplicate it.
		// TODO: we should keep every individual vulnerability we found as a evidence for a match but this isn't supported in the data model today
		results = slices.DeleteFunc(results, func(candidate Result) bool {
			if confidenceOf(candidate) < maxConfidence {
				droppedDetails = append(droppedDetails, candidate.Details...)
				return true
			}
			return false
		})

		if len(results) == 0 {
			log.WithFields("vulnerability", id).Trace("dropping vulnerability due to less specific vulnerable record")
			continue
		}

		// attach the dropped evidence to each surviving result. Clone before appending so we never
		// write through a Details slice shared with the source set; any duplicates are collapsed
		// later by mergeDetails when the matches are assembled.
		if len(droppedDetails) > 0 {
			for i := range results {
				results[i].Details = append(slices.Clone(results[i].Details), droppedDetails...)
			}
		}
		out[id] = results
	}
	return out
}

// splitUnaffected splits the set into vulnerability claims vs. unaffected / NAK records
func splitUnaffected(s Set) (affected, unaffected Set) {
	affected, unaffected = Set{}, Set{}
	for id, results := range s {
		for _, r := range results {
			a, u := splitVulns(r.Vulnerabilities)
			if len(a) > 0 {
				affected[id] = append(affected[id], withVulns(r, a))
			}
			if len(u) > 0 {
				unaffected[id] = append(unaffected[id], withVulns(r, u))
			}
		}
	}
	return affected, unaffected
}

func splitVulns(vulns []vulnerability.Vulnerability) (affected, unaffected []vulnerability.Vulnerability) {
	for _, v := range vulns {
		if v.Unaffected {
			unaffected = append(unaffected, v)
		} else {
			affected = append(affected, v)
		}
	}
	return affected, unaffected
}

// withVulns returns a copy of r carrying only the given vulnerabilities, keeping the details it was
// found by: the details describe the search, and the search is what turned up every one of them.
func withVulns(r Result, vulns []vulnerability.Vulnerability) Result {
	out := r
	out.Vulnerabilities = vulns
	return out
}

// confidenceOf is the maximum confidence level reported by the match details: this is likely to be reported in
// a match.Stream detail when multiple sources are considered to get results
func confidenceOf(r Result) float64 {
	maxConfidence := 0.
	for _, d := range r.Details {
		// if this is a stream result, use it's confidence directly
		if _, ok := d.SearchedBy.(match.Stream); ok {
			return d.Confidence
		}
		if d.Confidence > maxConfidence {
			maxConfidence = d.Confidence
		}
	}
	return maxConfidence
}

// filterByVersion keeps the records matching a version-dependent criteria, testing each against the
// version its own search was made with (see searchedVersion) and falling back to v for the records
// that name none. Results are filtered one at a time because those versions can differ within a
// single tier -- an rpm's source-package records are only commensurate with the epoch-less version
// they were searched at.
func filterByVersion(s Set, v *version.Version, criteria func(*version.Version) vulnerability.Criteria) Set {
	out := Set{}
	for id, results := range s {
		var row []Result
		for _, r := range results {
			row = append(row, filterOne(id, r, criteria(searchedVersion(r, v)))...)
		}
		if len(row) > 0 {
			out[id] = row
		}
	}
	return out
}

// searchedVersion returns the version a record's own search was made with, falling back to v.
//
// It is read back off the match details, which already describe that search: a caller passes
// search.WithVersion to convey the version without constraining results, and the provider records
// it on the details it builds (see extractSearchParameters). Nothing else has to carry it, and a
// record cannot end up tested against a version no detail of it admits to.
//
// This lets one call to SplitVulnerable span a package and its upstreams: an rpm's source-package
// search drops the epoch, since sourceRPMs omit epochs even where the binary has one (see
// rpm.matchUpstreamPackages), so records found under the source name are only commensurate with
// that version and not with the binary's.
//
// Which details record it, and which record the cataloged version instead, is spelled out on
// match.Details.SearchedPackageVersion.
func searchedVersion(r Result, v *version.Version) *version.Version {
	raw, ok := searchedPackageVersion(r.Details)
	if !ok || (v != nil && raw == v.Raw) {
		return v
	}

	// the comparison terms come from the split's own version, which is the same package in the same
	// ecosystem searched under a different name; only the raw version differs
	switch {
	case v != nil:
		return version.NewWithConfig(raw, v.Format, v.Config)
	case r.Package != nil:
		return version.New(raw, pkg.VersionFormat(*r.Package))
	}
	return nil
}

// filterOne keeps the record if it matches the criteria, preserving the detail-patching Filter
// performs so the searched-by version still lands on the match details.
func filterOne(id string, r Result, criteria vulnerability.Criteria) []Result {
	return Set{id: {r}}.Filter(criteria)[id]
}

func searchedPackageVersion(details match.Details) (string, bool) {
	for _, detail := range details {
		switch d := detail.SearchedBy.(type) {
		case match.DistroParameters:
			return d.Package.Version, d.Package.Version != ""
		case match.EcosystemParameters:
			return d.Package.Version, d.Package.Version != ""
		}
	}
	return "", false
}
