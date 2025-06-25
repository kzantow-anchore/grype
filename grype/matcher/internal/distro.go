package internal

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

func MatchPackageByDistro(provider vulnerability.Provider, p pkg.Package, ty match.Type, upstreamMatcher match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	if p.Distro == nil {
		return nil, nil, nil
	}

	if ty == "" {
		ty = match.ExactDirectMatch
	}

	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	var matches []match.Match
	vulns, err := provider.FindVulnerabilities(
		search.ByPackageName(p.Name),
		search.ByDistro(*p.Distro),
		OnlyQualifiedPackages(p),
		OnlyVulnerableVersions(version.NewVersionFromPkg(p)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch distro=%q pkg=%q: %w", p.Distro, p.Name, err)
	}

	for _, vuln := range vulns {
		matches = append(matches, match.Match{
			Vulnerability: vuln,
			Package:       p,
			Details:       DistroMatchDetails(ty, upstreamMatcher, p, vuln),
		})
	}
	return matches, nil, err
}

func DistroMatchDetails(ty match.Type, upstreamMatcher match.MatcherType, p pkg.Package, vuln vulnerability.Vulnerability) []match.Detail {
	return []match.Detail{
		{
			Type:    ty,
			Matcher: upstreamMatcher,
			SearchedBy: match.DistroParameters{
				Distro: match.DistroIdentification{
					Type:    p.Distro.Type.String(),
					Version: p.Distro.Version,
				},
				Package: match.PackageParameter{
					Name:    p.Name,
					Version: p.Version,
				},
				Namespace: vuln.Namespace,
			},
			Found: match.DistroResult{
				VulnerabilityID:   vuln.ID,
				VersionConstraint: vuln.Constraint.String(),
			},
			Confidence: 1.0, // TODO: this is hard coded for now
		},
	}
}

func isUnknownVersion(v string) bool {
	return strings.ToLower(v) == "unknown"
}
