package search

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/vulnerability"
)

// ByPackageName returns criteria restricting vulnerabilities to match the package name provided
func ByPackageName(packageName string) vulnerability.Criteria {
	return &PackageNameCriteria{
		PackageName: packageName,
	}
}

type PackageNameCriteria struct {
	PackageName string
}

func (v *PackageNameCriteria) MatchesVulnerability(vuln vulnerability.Vulnerability) (bool, string, error) {
	matchesPackageName := strings.EqualFold(vuln.PackageName, v.PackageName)
	if !matchesPackageName {
		return false, fmt.Sprintf("vulnerability package name %q does not match expected package name %q", vuln.PackageName, v.PackageName), nil
	}
	return true, "", nil
}

// ByIndirectPackageName is ByPackageName for an upstream or source package's name; records found by
// it are indirect matches.
func ByIndirectPackageName(packageName string) vulnerability.Criteria {
	return &IndirectPackageNameCriteria{PackageNameCriteria: PackageNameCriteria{PackageName: packageName}}
}

// IndirectPackageNameCriteria is searched exactly as a PackageNameCriteria.
type IndirectPackageNameCriteria struct {
	PackageNameCriteria
}

// PackageNameOf returns the name c searches by and whether it is indirect; ok is false when c is not
// a package name criteria.
func PackageNameOf(c vulnerability.Criteria) (name string, indirect, ok bool) {
	switch c := c.(type) {
	case *PackageNameCriteria:
		return c.PackageName, false, true
	case *IndirectPackageNameCriteria:
		return c.PackageName, true, true
	}
	return "", false, false
}

// WithPackageName returns package name criteria for name, indirect when c is.
func WithPackageName(c vulnerability.Criteria, name string) vulnerability.Criteria {
	if _, indirect, _ := PackageNameOf(c); indirect {
		return ByIndirectPackageName(name)
	}
	return ByPackageName(name)
}

var _ interface {
	vulnerability.Criteria
} = (*PackageNameCriteria)(nil)

var _ interface {
	vulnerability.Criteria
} = (*IndirectPackageNameCriteria)(nil)
