package internal

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/internal/ignorereasons"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// FindResultsByDistro searches the distro feed for every name the provider claims for searchPkg and
// splits the union into the records this version is vulnerable to and everything else (see
// SplitVulnerable). notVulnerable holds fixed records, records whose ranges miss this version,
// records a more specific stream overruled, and unaffected/NAK records; callers reconcile other
// sources (e.g. NVD/CPE) against it and build ownership ignores from it.
//
// The fanout over PackageSearchNames is what makes the rootio NAK pattern work: `rootio-libssl3`
// also searches `libssl3`, and a rootio NAK denies the upstream disclosure by ID + alias identity.
func FindResultsByDistro(provider vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig) (vulnerable result.Set, notVulnerable result.Set, err error) {
	if searchPkg.Distro == nil {
		return result.Set{}, result.Set{}, nil
	}

	if isUnknownVersion(searchPkg.Version) {
		log.WithFields("package", searchPkg.Name).Trace("skipping package with unknown version")
		return result.Set{}, result.Set{}, nil
	}

	pkgVersion := distroVersion(searchPkg, cfg)

	rp := result.NewProvider(provider, matchPackage(searchPkg, catalogPkg), upstreamMatcher)

	applicable, err := applicableForDistro(provider, rp, searchPkg, pkgVersion, search.ByPackageName)
	if err != nil {
		return nil, nil, err
	}

	// one split over every name: a fix under one name resolves a disclosure under another
	vulnerable, notVulnerable = SplitVulnerable(applicable, pkgVersion)
	return vulnerable, notVulnerable, nil
}

// FindResultsByDistroAcrossUpstreams searches the distro feed for searchPkg and each package it was
// built from, then splits the union once, so a fix recorded under the source name resolves a
// disclosure recorded under the binary name. Each record is compared against the version its own
// search used (see searchedVersion), since an upstream's version can differ from the binary's.
//
// catalogPkg is the package matches are attributed to when searchPkg is not the cataloged one (rpm
// searches with an epoch patched in); nil attributes them to searchPkg.
func FindResultsByDistroAcrossUpstreams(provider vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig) (vulnerable result.Set, notVulnerable result.Set, err error) {
	if searchPkg.Distro == nil {
		return result.Set{}, result.Set{}, nil
	}

	rp := result.NewProvider(provider, matchPackage(searchPkg, catalogPkg), upstreamMatcher)

	// the fallback comparison version (see SplitVulnerable); an unknown version satisfies nothing
	// but still carries the format and comparison config
	pkgVersion := distroVersion(searchPkg, cfg)

	applicable := result.Set{}
	if isUnknownVersion(searchPkg.Version) {
		// the upstreams may still carry versions worth searching
		log.WithFields("package", searchPkg.Name).Trace("skipping package with unknown version")
	} else {
		applicable, err = applicableForDistro(provider, rp, searchPkg, pkgVersion, search.ByPackageName)
		if err != nil {
			return nil, nil, err
		}
	}

	for _, upstreamPkg := range pkg.UpstreamPackages(searchPkg) {
		if upstreamPkg.Distro == nil || isUnknownVersion(upstreamPkg.Version) {
			continue
		}

		// an upstream's records are indirect matches even under the package's own name (a package that
		// is its own origin), which comparing names cannot tell
		found, err := applicableForDistro(provider, rp, upstreamPkg, distroVersion(upstreamPkg, cfg), search.ByIndirectPackageName)
		if err != nil {
			return nil, nil, err
		}
		applicable = applicable.Merge(found)
	}

	vulnerable, notVulnerable = SplitVulnerable(applicable, pkgVersion)
	return vulnerable, notVulnerable, nil
}

// applicableForDistro collects every record for searchPkg over every name the provider claims for it
// (rootio packages fan out to the bare upstream name), each searched by byName.
func applicableForDistro(provider vulnerability.Provider, rp result.Provider, searchPkg pkg.Package, pkgVersion *version.Version, byName func(string) vulnerability.Criteria) (result.Set, error) {
	applicable := result.Set{}
	for _, name := range provider.PackageSearchNames(searchPkg) {
		v, err := rp.FindAll(
			byName(name),
			search.ByDistro(*searchPkg.Distro),
			OnlyQualifiedPackages(searchPkg),
			search.WithVersion(*pkgVersion),
		)
		if err != nil {
			return nil, fmt.Errorf("matcher failed to fetch distro=%q pkg=%q: %w", searchPkg.Distro, name, err)
		}
		applicable = applicable.Merge(v)
	}
	return applicable, nil
}

func distroVersion(p pkg.Package, cfg *version.ComparisonConfig) *version.Version {
	if cfg != nil {
		return version.NewWithConfig(p.Version, pkg.VersionFormat(p), *cfg)
	}
	return version.New(p.Version, pkg.VersionFormat(p))
}

// MatchPackageByDistroAcrossUpstreams is the []match.Match form of FindResultsByDistroAcrossUpstreams.
func MatchPackageByDistroAcrossUpstreams(provider vulnerability.Provider, p pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig) ([]match.Match, []match.IgnoreFilter, error) {
	vulnerable, notVulnerable, err := FindResultsByDistroAcrossUpstreams(provider, p, nil, upstreamMatcher, cfg)
	if err != nil {
		return nil, nil, err
	}

	return vulnerable.ToMatches(), OwnershipIgnores(p, "DistroPackageFixed", notVulnerable.Vulnerabilities()...), nil
}

// MatchPackageByDistro is the []match.Match form of FindResultsByDistro: vulnerable records become
// matches, the rest become ownership ignores (e.g. an APK that owns NPM).
func MatchPackageByDistro(provider vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig) ([]match.Match, []match.IgnoreFilter, error) {
	vulnerable, notVulnerable, err := FindResultsByDistro(provider, searchPkg, catalogPkg, upstreamMatcher, cfg)
	if err != nil {
		return nil, nil, err
	}

	// Use the SBOM package (not the synthetic upstream) for file ownership — the upstream package doesn't have file metadata.
	ignores := OwnershipIgnores(matchPackage(searchPkg, catalogPkg), ignorereasons.DistroFixed, notVulnerable.Vulnerabilities()...)

	return vulnerable.ToMatches(), ignores, nil
}

func matchPackage(searchPkg pkg.Package, catalogPkg *pkg.Package) pkg.Package {
	if catalogPkg != nil {
		return *catalogPkg
	}
	return searchPkg
}

func isUnknownVersion(v string) bool {
	return strings.ToLower(v) == "unknown"
}
