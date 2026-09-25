package internal

import (
	"slices"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// SplitVulnerable partitions the set into the records that say the searched version is vulnerable
// and everything else.
//
// The partition is made per affected version range, per release stream, and against the provider's
// unaffected records:
//
//   - One record can describe several affected ranges, each hydrated as its own Vulnerability with
//     its own constraint and fix. Only the ranges covering this version are kept.
//
//   - Several streams can describe one package (a base distro's rows and a rebuild's channel) and
//     disagree. The highest-ranked stream with an answer decides (see result.Rank); a stream whose
//     ranges miss this version has no answer.
//
//   - Unaffected records (NAKs) only deny and are not ranked against the streams.
//
// notVulnerable is everything not reported, including records whose ranges miss this version with no
// fix recorded; callers build ownership ignores from it. No vulnerability appears in both returns.
//
// v is the fallback version for records that do not name their own (see searchedVersion).
func SplitVulnerable(s result.Set, v *version.Version) (vulnerable, notVulnerable result.Set) {
	affected, unaffected := splitUnaffected(s)

	unaffected = filterByVersion(unaffected, v, matchesConstraints)

	// a fix exactly at the installed version proves the build carries that advisory's patch; applied
	// separately from the NAKs below (see removeExactlyFixed)
	exactlyFixed := keepByExactFixVersion(affected, v)

	candidates := filterByVersion(affected, v, matchesConstraints)

	// a vulnerability is stored as several objects, each with its own range; matching one in a
	// namespace sets aside the others in that namespace
	notVulnerable = affected.Filter(removeExactVulnerabilitiesByNamespace(candidates))

	if v != nil {
		notVulnerable = filterByVersion(notVulnerable, v, outsideConstraints)

		// FIXME this should keep some other statuses like not-vulnerable
		notVulnerable = notVulnerable.Filter(search.ByFixedVersion(*v))
	}

	candidates = keepMoreSpecificCandidates(candidates, notVulnerable)

	// a NAK denies any candidate for the same vulnerability (by ID + aliases across namespaces)
	vulnerable = candidates.Remove(unaffected)

	vulnerable = removeExactlyFixed(vulnerable, exactlyFixed)

	// an unaffected record whose ranges miss this version is in neither leg: callers reconcile other
	// sources against notVulnerable, and it would suppress a finding the provider never answered
	return vulnerable, removeByIDAndAlias(affected, vulnerable).Merge(unaffected).Merge(exactlyFixed)
}

func keepByExactFixVersion(affected result.Set, v *version.Version) result.Set {
	if v == nil || v.Raw == "" {
		return result.Set{}
	}
	return affected.Filter(search.ByFunc(func(vuln vulnerability.Vulnerability) (bool, string, error) {
		matches := slices.Contains(vuln.Fix.Versions, v.Raw)
		if matches {
			return true, "", nil
		}
		return false, "does not have exact fix version", nil
	}))
}

// removeExactlyFixed drops candidates where every CVE is patched by an advisory fixed exactly at the
// installed version. A candidate naming an additional CVE is kept (e.g. OL8 ELSA-2022-7647 shares
// CVE-2022-31813 with the exactly-fixed ELSA-2022-9682 but patches more). Only CVE IDs are compared:
// advisory IDs (ELSA-..., RHSA-...) label CVEs and are not themselves patched.
func removeExactlyFixed(candidates, exactlyFixed result.Set) result.Set {
	if len(exactlyFixed) == 0 {
		return candidates
	}
	patched := strset.New()
	for id, results := range exactlyFixed {
		patched.Add(cveIDsOf(getIdentity(id, results)).List()...)
	}
	out := result.Set{}
	for id, results := range candidates {
		cves := cveIDsOf(getIdentity(id, results))
		// patched.IsSubset(cves) reports whether cves is a subset of patched
		if cves.Size() > 0 && patched.IsSubset(cves) {
			continue
		}
		out[id] = results
	}
	return out
}

func getIdentity(id string, results []result.Result) *strset.Set {
	out := strset.New(id)
	for _, r := range results {
		for _, v := range r.Vulnerabilities {
			for _, alias := range v.RelatedVulnerabilities {
				out.Add(alias.ID)
			}
		}
	}
	return out
}

// cveIDsOf returns the CVE IDs of an identity set, excluding advisory IDs (ELSA-..., RHSA-...).
func cveIDsOf(s *strset.Set) *strset.Set {
	out := strset.New()
	s.Each(func(id string) bool {
		if strings.HasPrefix(id, "CVE-") {
			out.Add(id)
		}
		return true
	})
	return out
}

func removeExactVulnerabilitiesByNamespace(candidates result.Set) vulnerability.Criteria {
	return search.ByFunc(func(incoming vulnerability.Vulnerability) (bool, string, error) {
		vulnerable := candidates[incoming.ID]
		for _, v := range vulnerable {
			for _, v := range v.Vulnerabilities {
				// FIXME this is to work around an issue in the database where multiple GHSAs and possibly other providers
				// result in multiple ranges being hydrated as multiple vulnerability objects each with their own range
				// ideally, these could be merged together when we retrieve these records from the DB but that would change
				// the fix version displayed in some cases
				if v.ID == incoming.ID && v.Namespace == incoming.Namespace {
					return false, "same vulnerability ID", nil
				}
			}
		}
		return true, "", nil // keep, this is a unique namespace for the record
	})
}

// matchesConstraints tests a record's affected range against v; with no version every record matches.
func matchesConstraints(v *version.Version) vulnerability.Criteria {
	if v == nil || v.Raw == "" {
		return search.ByFunc(func(vulnerability.Vulnerability) (bool, string, error) {
			return true, "", nil
		})
	}
	return search.ByVersion(*v)
}

// outsideConstraints tests that v falls outside a record's affected range; with no version nothing matches.
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

// removeByIDAndAlias drops from s the records for a vulnerability in removals: every record whose ID a
// removal carries (as its ID or an alias), so no vulnerability is reported in both legs of the split,
// and every record sharing an alias with a higher-ranked removal. A record sharing only an alias with an
// equally or lower-ranked removal is kept: it is a separate advisory (e.g. another release line's,
// naming a shared CVE) that still answers for the version.
//
//nolint:gocognit
func removeByIDAndAlias(s result.Set, removals result.Set) result.Set {
	// the highest rank of a removal by each of its IDs and aliases
	removedRank := map[string]result.Rank{}
	raise := func(id string, r result.Rank) {
		if prev, ok := removedRank[id]; !ok || r.Compare(prev) > 0 {
			removedRank[id] = r
		}
	}
	for id, results := range removals {
		for _, r := range results {
			raise(id, r.Rank)
			for _, v := range r.Vulnerabilities {
				for _, alias := range v.RelatedVulnerabilities {
					raise(alias.ID, r.Rank)
				}
			}
		}
	}

	out := result.Set{}
	for id, results := range s {
		if _, ok := removedRank[id]; ok {
			continue
		}
		results = slices.DeleteFunc(slices.Clone(results), func(r result.Result) bool {
			for _, v := range r.Vulnerabilities {
				for _, alias := range v.RelatedVulnerabilities {
					if removed, ok := removedRank[alias.ID]; ok && r.Rank.Compare(removed) < 0 {
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

// keepMoreSpecificCandidates drops candidates ranked below a not-vulnerable record for the same ID,
// then drops candidates ranked below the highest-ranked candidate (see result.Rank). The dropped
// candidates' details are kept as evidence on the survivors.
func keepMoreSpecificCandidates(candidates, notVulnerable result.Set) result.Set {
	out := result.Set{}
	for id, results := range candidates {
		var maxRank result.Rank
		for i, candidate := range results {
			if i == 0 || candidate.Rank.Compare(maxRank) > 0 {
				maxRank = candidate.Rank
			}
		}
		var droppedDetails match.Details
		results = slices.DeleteFunc(results, func(candidate result.Result) bool {
			for _, nak := range notVulnerable[id] {
				if candidate.Rank.Compare(nak.Rank) < 0 {
					droppedDetails = append(droppedDetails, candidate.Details...)
					vulnerability.LogDropped(id, "SplitVulnerable", "the most specific stream describing this package reports the version fixed", nil)
					return true
				}
			}

			return false
		})

		// TODO: keep every vulnerability found as evidence for a match; the data model does not support this today
		results = slices.DeleteFunc(results, func(candidate result.Result) bool {
			if candidate.Rank.Compare(maxRank) < 0 {
				droppedDetails = append(droppedDetails, candidate.Details...)
				return true
			}
			return false
		})

		if len(results) == 0 {
			log.WithFields("vulnerability", id).Trace("dropping vulnerability due to less specific vulnerable record")
			continue
		}

		// clone so the Details slice shared with the source set is not written through; duplicates
		// are collapsed by mergeDetails when matches are assembled
		if len(droppedDetails) > 0 {
			for i := range results {
				results[i].Details = append(slices.Clone(results[i].Details), droppedDetails...)
			}
		}
		out[id] = results
	}
	return out
}

// splitUnaffected splits the set into affected records and unaffected (NAK) records.
func splitUnaffected(s result.Set) (affected, unaffected result.Set) {
	affected, unaffected = result.Set{}, result.Set{}
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

// withVulns returns a copy of r with only the given vulnerabilities.
func withVulns(r result.Result, vulns []vulnerability.Vulnerability) result.Result {
	out := r
	out.Vulnerabilities = vulns
	return out
}

// filterByVersion keeps the records matching criteria, testing each result against the version its
// own search used (see searchedVersion) and falling back to v.
func filterByVersion(s result.Set, v *version.Version, criteria func(*version.Version) vulnerability.Criteria) result.Set {
	out := result.Set{}
	for id, results := range s {
		var row []result.Result
		for _, r := range results {
			row = append(row, filterOne(id, r, criteria(searchedVersion(r, v)))...)
		}
		if len(row) > 0 {
			out[id] = row
		}
	}
	return out
}

// searchedVersion returns the version a record's own search used, read from its match details (see
// extractSearchParameters and searchedPackageVersion), falling back to v. This lets one split span a
// package and its upstreams: an rpm's source-package search drops the epoch (see
// rpm.Matcher.matchDistro), so those records are only comparable with that version.
func searchedVersion(r result.Result, v *version.Version) *version.Version {
	raw, ok := searchedPackageVersion(r.Details)
	if !ok || (v != nil && raw == v.Raw) {
		return v
	}

	// same package and ecosystem, so v's format and config apply
	switch {
	case v != nil:
		return version.NewWithConfig(raw, v.Format, v.Config)
	case r.Package != nil:
		return version.New(raw, pkg.VersionFormat(*r.Package))
	}
	return nil
}

// filterOne filters a single record through Set.Filter, so its detail patching still applies.
func filterOne(id string, r result.Result, criteria vulnerability.Criteria) []result.Result {
	return result.Set{id: {r}}.Filter(criteria)[id]
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
