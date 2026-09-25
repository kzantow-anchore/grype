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
// splits the union (see SplitVulnerable).
//
// Splitting across PackageSearchNames lets a rootio NAK under `rootio-libssl3` deny a disclosure
// under `libssl3`.
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

	vulnerable, notVulnerable = SplitVulnerable(applicable, pkgVersion)
	return vulnerable, notVulnerable, nil
}

// FindResultsByDistroAcrossUpstreams searches the distro feed for searchPkg and its upstream
// packages, then splits the union once, so a fix under the source name resolves a disclosure under
// the binary name.
//
// catalogPkg is the package matches are attributed to when it differs from searchPkg (e.g. an rpm
// searched with an explicit epoch); nil attributes them to searchPkg.
func FindResultsByDistroAcrossUpstreams(provider vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package, upstreamMatcher match.MatcherType, cfg *version.ComparisonConfig) (vulnerable result.Set, notVulnerable result.Set, err error) {
	if searchPkg.Distro == nil {
		return result.Set{}, result.Set{}, nil
	}

	rp := result.NewProvider(provider, matchPackage(searchPkg, catalogPkg), upstreamMatcher)

	pkgVersion := distroVersion(searchPkg, cfg)

	applicable := result.Set{}
	if isUnknownVersion(searchPkg.Version) {
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

		// indirect even when the upstream has the package's own name
		found, err := applicableForDistro(provider, rp, upstreamPkg, distroVersion(upstreamPkg, cfg), search.ByIndirectPackageName)
		if err != nil {
			return nil, nil, err
		}
		applicable = applicable.Merge(found)
	}

	vulnerable, notVulnerable = SplitVulnerable(applicable, pkgVersion)
	return vulnerable, notVulnerable, nil
}

// applicableForDistro collects every record for each name the provider claims for searchPkg.
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

	return vulnerable.ToMatches(), OwnershipIgnores(p, ignorereasons.DistroFixed, notVulnerable.Vulnerabilities()...), nil
}

// MatchPackageByDistro is the []match.Match form of FindResultsByDistro.
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
