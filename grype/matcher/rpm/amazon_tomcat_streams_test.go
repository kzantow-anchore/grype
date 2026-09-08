package rpm

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// The fixture (testdata/amazon-tomcat-streams) holds REAL Amazon Linux 2 advisory records for
// the tomcat source rpm, kept verbatim in OS schema, so these tests exercise the whole
// vunnel -> grype-db -> grype path rather than hand-built v6 constraints or hand-built match
// details. See its db.yaml for what each record is and why it is in the fixture.

// amazonTomcat7Host is the package shape the matcher receives for the core tomcat 7 build on
// Amazon Linux 2: a binary rpm whose advisories are keyed on its source rpm ("tomcat"), so the
// matcher's source-indirection path engages and the direct and upstream searches merge into one
// split.
//
// The shape is real, from docker.io/anchore/test_images:vulnerabilities-amazonlinux-2:
//
//	tomcat-servlet-3.0-api 0:7.0.76-10.amzn2.0.2, sourceRpm tomcat-7.0.76-10.amzn2.0.2.src.rpm
func amazonTomcat7Host(id pkg.ID) pkg.Package {
	return dbtest.NewPackage("tomcat-servlet-3.0-api", "0:7.0.76-10.amzn2.0.2", syftPkg.RpmPkg).
		WithID(id).
		WithArchitecture("noarch").
		WithDistro(distro.New(distro.AmazonLinux, "2", "")).
		WithUpstream("tomcat", "7.0.76-10.amzn2.0.2").
		WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
		Build()
}

// TestAmazonTomcatStreams_UpstreamHitDoesNotDenyDirectFix pins that an advisory this build is
// past -- one the direct search resolves -- still reaches the caller as an ownership ignore even
// when an advisory from another release line is reported for a CVE they share.
//
// Both legs of the split are load bearing here: the vulnerable one becomes the reported matches,
// and the not-vulnerable one becomes the ownership ignores (internal.OwnershipIgnores) that
// suppress CPE findings on the archives this rpm contains. Losing a record from the
// not-vulnerable leg is not a silent no-op -- it is a new false positive on the contained
// tomcat-servlet-api jar.
//
// The two pairings differ only in how many aliases the resolved advisory names, which is exactly
// what the alias-identity pruning keys on:
//
//	ALAS2-2020-1402 (5 CVEs)  vs ALAS2TOMCAT8.5-2023-012, sharing CVE-2020-1938
//	ALAS2-2020-1449 (1 CVE)   vs ALAS2TOMCAT8.5-2023-008, sharing CVE-2020-9484
func TestAmazonTomcatStreams_UpstreamHitDoesNotDenyDirectFix(t *testing.T) {
	dbtest.DBs(t, "amazon-tomcat-streams").
		Run(func(t *testing.T, db *dbtest.DB) {
			pkgID := pkg.ID("tomcat-servlet-3.0-api")
			matcher := Matcher{}

			findings := db.Match(t, &matcher, amazonTomcat7Host(pkgID))

			// the tomcat8.5 topic's advisories are the only ones whose ranges cover a 7.0.76
			// build, and they are keyed on the same source rpm, so both are reported
			findings.SelectMatch("ALAS2TOMCAT8.5-2023-008").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch("< 8.5.56-1.amzn2 (rpm)")
			findings.SelectMatch("ALAS2TOMCAT8.5-2023-012").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch("< 8.5.51-1.amzn2 (rpm)")

			// the core tomcat 7 advisories this build is at or past: each must stay available as
			// an ignore under its own ID and every CVE it names, CVE-2020-1938 and CVE-2020-9484
			// included -- the aliases the reported tomcat8.5 advisories also answer for
			findings.Ignores().
				SelectRelatedPackageIgnores(IgnoreReasonDistroNotVulnerable,
					"ALAS2-2020-1402",
					"CVE-2018-1304", "CVE-2018-1305", "CVE-2018-8014", "CVE-2018-8034", "CVE-2020-1938",
					"ALAS2-2020-1449",
					"CVE-2020-9484",
				).
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}
