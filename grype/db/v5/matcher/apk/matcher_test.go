package apk

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/search"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type mockStore struct {
	backend map[string]map[string][]v5.Vulnerability
}

func (s *mockStore) GetVulnerability(namespace, id string) ([]v5.Vulnerability, error) {
	// TODO implement me
	panic("implement me")
}

func (s *mockStore) SearchForVulnerabilities(namespace, name string) ([]v5.Vulnerability, error) {
	namespaceMap := s.backend[namespace]
	if namespaceMap == nil {
		return nil, nil
	}
	return namespaceMap[name], nil
}

func (s *mockStore) GetAllVulnerabilities() (*[]v5.Vulnerability, error) {
	return nil, nil
}

func (s *mockStore) GetVulnerabilityNamespaces() ([]string, error) {
	keys := make([]string, 0, len(s.backend))
	for k := range s.backend {
		keys = append(keys, k)
	}

	return keys, nil
}

func TestSecDBOnlyMatch(t *testing.T) {

	secDbVuln := v5.Vulnerability{
		// ID doesn't match - this is the key for comparison in the matcher
		ID:                "CVE-2020-2",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb:distro:alpine:3.12",
	}
	store := mockStore{
		backend: map[string]map[string][]v5.Vulnerability{
			"secdb:distro:alpine:3.12": {
				"libvncserver": []v5.Vulnerability{secDbVuln},
			},
		},
	}

	provider, err := v5.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	vulnFound, err := v5.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{
		{

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "libvncserver",
							"version": "0.9.9",
						},
						"namespace": "secdb:distro:alpine:3.12",
					},
					Found: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
						"vulnerabilityID":   "CVE-2020-2",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestBothSecdbAndNvdMatches(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	nvdVuln := v5.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd:cpe",
	}

	secDbVuln := v5.Vulnerability{
		// ID *does* match - this is the key for comparison in the matcher
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb:distro:alpine:3.12",
	}
	store := mockStore{
		backend: map[string]map[string][]v5.Vulnerability{
			"nvd:cpe": {
				"libvncserver": []v5.Vulnerability{nvdVuln},
			},
			"secdb:distro:alpine:3.12": {
				"libvncserver": []v5.Vulnerability{secDbVuln},
			},
		},
	}

	provider, err := v5.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	// ensure the SECDB record is preferred over the NVD record
	vulnFound, err := v5.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{
		{

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "libvncserver",
							"version": "0.9.9",
						},
						"namespace": "secdb:distro:alpine:3.12",
					},
					Found: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
						"vulnerabilityID":   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestBothSecdbAndNvdMatches_DifferentFixInfo(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	nvdVuln := v5.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "< 1.0.0",
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd:cpe",
		Fix: v5.Fix{
			Versions: []string{"1.0.0"},
			State:    v5.FixedState,
		},
	}

	secDbVuln := v5.Vulnerability{
		// ID *does* match - this is the key for comparison in the matcher
		ID:                "CVE-2020-1",
		VersionConstraint: "< 0.9.12",
		VersionFormat:     "apk",
		Namespace:         "secdb:distro:alpine:3.12",
		// SecDB indicates Alpine have backported a fix to v0.9...
		Fix: v5.Fix{
			Versions: []string{"0.9.12"},
			State:    v5.FixedState,
		},
	}
	store := mockStore{
		backend: map[string]map[string][]v5.Vulnerability{
			"nvd:cpe": {
				"libvncserver": []v5.Vulnerability{nvdVuln},
			},
			"secdb:distro:alpine:3.12": {
				"libvncserver": []v5.Vulnerability{secDbVuln},
			},
		},
	}

	provider, err := v5.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	// ensure the SECDB record is preferred over the NVD record
	vulnFound, err := v5.NewVulnerability(secDbVuln)
	assert.NoError(t, err)
	vulnFound.Fix = vulnerability.Fix{
		Versions: secDbVuln.Fix.Versions,
		State:    vulnerability.FixState(secDbVuln.Fix.State),
	}

	expected := []match.Match{
		{

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "libvncserver",
							"version": "0.9.9",
						},
						"namespace": "secdb:distro:alpine:3.12",
					},
					Found: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
						"vulnerabilityID":   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestBothSecdbAndNvdMatches_DifferentPackageName(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	nvdVuln := v5.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		// Note: the product name is NOT the same as the target package name
		CPEs:      []string{"cpe:2.3:a:lib_vnc_project-(server):libvncumbrellaproject:*:*:*:*:*:*:*:*"},
		Namespace: "nvd:cpe",
	}

	secDbVuln := v5.Vulnerability{
		// ID *does* match - this is the key for comparison in the matcher
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb:distro:alpine:3.12",
	}
	store := mockStore{
		backend: map[string]map[string][]v5.Vulnerability{
			"nvd:cpe": {
				"libvncumbrellaproject": []v5.Vulnerability{nvdVuln},
			},
			"secdb:distro:alpine:3.12": {
				"libvncserver": []v5.Vulnerability{secDbVuln},
			},
		},
	}

	provider, err := v5.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		CPEs: []cpe.CPE{
			// Note: the product name is NOT the same as the package name
			cpe.Must("cpe:2.3:a:*:libvncumbrellaproject:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	// ensure the SECDB record is preferred over the NVD record
	vulnFound, err := v5.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{
		{

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "libvncserver",
							"version": "0.9.9",
						},
						"namespace": "secdb:distro:alpine:3.12",
					},
					Found: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
						"vulnerabilityID":   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdOnlyMatches(t *testing.T) {
	nvdVuln := v5.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd:cpe",
	}
	store := mockStore{
		backend: map[string]map[string][]v5.Vulnerability{
			"nvd:cpe": {
				"libvncserver": []v5.Vulnerability{nvdVuln},
			},
		},
	}

	provider, err := v5.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	vulnFound, err := v5.NewVulnerability(nvdVuln)
	assert.NoError(t, err)
	vulnFound.CPEs = []cpe.CPE{cpe.Must(nvdVuln.CPEs[0], "")}

	expected := []match.Match{
		{

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: search.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
						Package: search.CPEPackageParameter{
							Name:    "libvncserver",
							Version: "0.9.9",
						},
					},
					Found: search.CPEResult{
						CPEs:              []string{vulnFound.CPEs[0].Attributes.BindToFmtString()},
						VersionConstraint: vulnFound.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdOnlyMatches_FixInNvd(t *testing.T) {
	nvdVuln := v5.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "< 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd:cpe",
		Fix: v5.Fix{
			Versions: []string{"0.9.12"},
			State:    v5.FixedState,
		},
	}
	store := mockStore{
		backend: map[string]map[string][]v5.Vulnerability{
			"nvd:cpe": {
				"libvncserver": []v5.Vulnerability{nvdVuln},
			},
		},
	}

	provider, err := v5.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	vulnFound, err := v5.NewVulnerability(nvdVuln)
	assert.NoError(t, err)
	vulnFound.CPEs = []cpe.CPE{cpe.Must(nvdVuln.CPEs[0], "")}
	// Important: for alpine matcher, fix version can come from secDB but _not_ from
	// NVD data.
	vulnFound.Fix = vulnerability.Fix{State: vulnerability.FixStateUnknown}

	expected := []match.Match{
		{

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: search.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
						Package: search.CPEPackageParameter{
							Name:    "libvncserver",
							Version: "0.9.9",
						},
					},
					Found: search.CPEResult{
						CPEs:              []string{vulnFound.CPEs[0].Attributes.BindToFmtString()},
						VersionConstraint: vulnFound.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdMatchesProperVersionFiltering(t *testing.T) {
	nvdVulnMatch := v5.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd:cpe",
	}
	nvdVulnNoMatch := v5.Vulnerability{
		ID:                "CVE-2020-2",
		VersionConstraint: "< 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd:cpe",
	}
	store := mockStore{
		backend: map[string]map[string][]v5.Vulnerability{
			"nvd:cpe": {
				"libvncserver": []v5.Vulnerability{nvdVulnMatch, nvdVulnNoMatch},
			},
		},
	}

	provider, err := v5.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.11-r10",
		Type:    syftPkg.ApkPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.11:*:*:*:*:*:*:*", ""),
		},
	}

	vulnFound, err := v5.NewVulnerability(nvdVulnMatch)
	assert.NoError(t, err)
	vulnFound.CPEs = []cpe.CPE{cpe.Must(nvdVulnMatch.CPEs[0], "")}

	expected := []match.Match{
		{

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: search.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:*:libvncserver:0.9.11:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
						Package: search.CPEPackageParameter{
							Name:    "libvncserver",
							Version: "0.9.11-r10",
						},
					},
					Found: search.CPEResult{
						CPEs:              []string{vulnFound.CPEs[0].Attributes.BindToFmtString()},
						VersionConstraint: vulnFound.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdMatchesWithSecDBFix(t *testing.T) {
	nvdVuln := v5.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "> 0.9.0, < 0.10.0", // note: this is not normal NVD configuration, but has the desired effect of a "wide net" for vulnerable indication
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd:cpe",
	}

	secDbVuln := v5.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "< 0.9.11", // note: this does NOT include 0.9.11, so NVD and SecDB mismatch here... secDB should trump in this case
		VersionFormat:     "apk",
	}

	store := mockStore{
		backend: map[string]map[string][]v5.Vulnerability{
			"nvd:cpe": {
				"libvncserver": []v5.Vulnerability{nvdVuln},
			},
			"secdb:distro:alpine:3.12": {
				"libvncserver": []v5.Vulnerability{secDbVuln},
			},
		},
	}

	provider, err := v5.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.11",
		Type:    syftPkg.ApkPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	expected := []match.Match{}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdMatchesNoConstraintWithSecDBFix(t *testing.T) {
	nvdVuln := v5.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "", // note: empty value indicates that all versions are vulnerable
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd:cpe",
	}

	secDbVuln := v5.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "< 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb:distro:alpine:3.12",
	}

	store := mockStore{
		backend: map[string]map[string][]v5.Vulnerability{
			"nvd:cpe": {
				"libvncserver": []v5.Vulnerability{nvdVuln},
			},
			"secdb:distro:alpine:3.12": {
				"libvncserver": []v5.Vulnerability{secDbVuln},
			},
		},
	}

	provider, err := v5.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.11",
		Type:    syftPkg.ApkPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	expected := []match.Match{}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNVDMatchCanceledByOriginPackageInSecDB(t *testing.T) {
	nvdVuln := v5.Vulnerability{
		ID:            "CVE-2015-3211",
		VersionFormat: "unknown",
		CPEs:          []string{"cpe:2.3:a:php-fpm:php-fpm:-:*:*:*:*:*:*:*"},
		Namespace:     "nvd:cpe",
	}
	secDBVuln := v5.Vulnerability{
		ID:                "CVE-2015-3211",
		VersionConstraint: "< 0",
		VersionFormat:     "apk",
		Namespace:         "wolfi:distro:wolfi:rolling",
	}
	store := mockStore{
		backend: map[string]map[string][]v5.Vulnerability{
			"nvd:cpe": {
				"php-fpm": []v5.Vulnerability{nvdVuln},
			},
			"wolfi:distro:wolfi:rolling": {
				"php-8.3": []v5.Vulnerability{secDBVuln},
			},
		},
	}

	provider, err := v5.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Wolfi, "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "php-8.3-fpm",
		Version: "8.3.11-r0",
		Type:    syftPkg.ApkPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:php-fpm:php-fpm:8.3.11-r0:*:*:*:*:*:*:*", ""),
		},
		Upstreams: []pkg.UpstreamPackage{
			{
				Name:    "php-8.3",
				Version: "8.3.11-r0",
			},
		},
	}

	expected := []match.Match{}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestDistroMatchBySourceIndirection(t *testing.T) {

	secDbVuln := v5.Vulnerability{
		// ID doesn't match - this is the key for comparison in the matcher
		ID:                "CVE-2020-2",
		VersionConstraint: "<= 1.3.3-r0",
		VersionFormat:     "apk",
		Namespace:         "secdb:distro:alpine:3.12",
	}
	store := mockStore{
		backend: map[string]map[string][]v5.Vulnerability{
			"secdb:distro:alpine:3.12": {
				"musl": []v5.Vulnerability{secDbVuln},
			},
		},
	}

	provider, err := v5.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "musl-utils",
		Version: "1.3.2-r0",
		Type:    syftPkg.ApkPkg,
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "musl",
			},
		},
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:musl-utils:musl-utils:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
		},
	}

	vulnFound, err := v5.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{
		{

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactIndirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "musl",
							"version": p.Version,
						},
						"namespace": "secdb:distro:alpine:3.12",
					},
					Found: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
						"vulnerabilityID":   "CVE-2020-2",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestSecDBMatchesStillCountedWithCpeErrors(t *testing.T) {
	// this should match the test package
	// the test package will have no CPE causing an error,
	// but the error should not cause the secDB matches to fail
	secDbVuln := v5.Vulnerability{
		ID:                "CVE-2020-2",
		VersionConstraint: "<= 1.3.3-r0",
		VersionFormat:     "apk",
		Namespace:         "secdb:distro:alpine:3.12",
	}

	store := mockStore{
		backend: map[string]map[string][]v5.Vulnerability{
			"secdb:distro:alpine:3.12": {
				"musl": []v5.Vulnerability{secDbVuln},
			},
		},
	}

	provider, err := v5.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "musl-utils",
		Version: "1.3.2-r0",
		Type:    syftPkg.ApkPkg,
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "musl",
			},
		},
		CPEs: []cpe.CPE{},
	}

	vulnFound, err := v5.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{
		{

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactIndirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "musl",
							"version": p.Version,
						},
						"namespace": "secdb:distro:alpine:3.12",
					},
					Found: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
						"vulnerabilityID":   "CVE-2020-2",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNVDMatchBySourceIndirection(t *testing.T) {
	nvdVuln := v5.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 1.3.3-r0",
		VersionFormat:     "unknown",
		CPEs:              []string{"cpe:2.3:a:musl:musl:*:*:*:*:*:*:*:*"},
		Namespace:         "nvd:cpe",
	}
	store := mockStore{
		backend: map[string]map[string][]v5.Vulnerability{
			"nvd:cpe": {
				"musl": []v5.Vulnerability{nvdVuln},
			},
		},
	}

	provider, err := v5.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "musl-utils",
		Version: "1.3.2-r0",
		Type:    syftPkg.ApkPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:musl-utils:musl-utils:*:*:*:*:*:*:*:*", ""),
			cpe.Must("cpe:2.3:a:musl-utils:musl-utils:*:*:*:*:*:*:*:*", ""),
		},
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "musl",
			},
		},
	}

	vulnFound, err := v5.NewVulnerability(nvdVuln)
	assert.NoError(t, err)
	vulnFound.CPEs = []cpe.CPE{cpe.Must(nvdVuln.CPEs[0], "")}

	expected := []match.Match{
		{
			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: search.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:musl:musl:1.3.2-r0:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
						Package: search.CPEPackageParameter{
							Name:    "musl",
							Version: "1.3.2-r0",
						},
					},
					Found: search.CPEResult{
						CPEs:              []string{vulnFound.CPEs[0].Attributes.BindToFmtString()},
						VersionConstraint: vulnFound.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func assertMatches(t *testing.T, expected, actual []match.Match) {
	t.Helper()
	var opts = []cmp.Option{
		cmpopts.IgnoreFields(vulnerability.Vulnerability{}, "Constraint"),
		cmpopts.IgnoreFields(pkg.Package{}, "Locations"),
	}

	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
