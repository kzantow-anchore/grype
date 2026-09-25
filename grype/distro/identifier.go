package distro

import "strings"

// LabelMatcher matches a single container image config label by key and value prefix
// (both case-insensitive).
type LabelMatcher struct {
	// Key is the label key to match, e.g. "maintainer"
	Key string

	// ValuePrefix matches any label value that begins with this prefix, e.g. "rapidfort"
	ValuePrefix string
}

// Matches indicates if the given label key/value pair satisfies this matcher.
func (m LabelMatcher) Matches(key, value string) bool {
	return strings.EqualFold(key, m.Key) && strings.HasPrefix(strings.ToLower(value), strings.ToLower(m.ValuePrefix))
}

// Identifier remaps a detected distro to a vendor-specific distro when the scanned source carries
// evidence (a marker file or a container image label) of being a curated derivative of a base
// distro. The vendor's vulnerability data lives under that distinct OS name in the DB.
type Identifier struct {
	// Name is the rule identifier used for configuration and logging, e.g. "rapidfort"
	Name string

	// MarkerPaths are file paths whose presence in the scanned source triggers this identifier
	MarkerPaths []string

	// Label is an image label that triggers this identifier (a zero value never matches).
	// Any one trigger (marker path or label) is sufficient.
	Label LabelMatcher

	// DistroIDs maps a detected /etc/os-release ID (e.g. "ubuntu") to the replacement distro ID
	// (e.g. "rapidfort-ubuntu"); other distros are left unchanged
	DistroIDs map[string]string

	// Apply is "auto" (apply when the source evidence matches) or "never"
	Apply FixChannelEnabled

	// Channels are fix channels to pin on the identified distro (empty means the identified
	// distro queries only channel-less OS records)
	Channels []string
}

// DefaultIdentifiers returns the built-in distro identifiers.
func DefaultIdentifiers() []Identifier {
	return []Identifier{
		{
			Name: "rapidfort",
			// the curation manifest is in every RapidFort-curated image; the maintainer label also
			// survives SBOM formats that keep image labels but not file catalogs
			MarkerPaths: []string{"/usr/share/rapidfort/curated.json"},
			Label:       LabelMatcher{Key: "maintainer", ValuePrefix: "rapidfort"},
			DistroIDs: map[string]string{
				string(Ubuntu): string(RapidFortUbuntu),
				"alpine":       string(RapidFortAlpine),
				"debian":       string(RapidFortDebian),
				// RapidFort publishes all EL-family data under rapidfort-redhat
				rhelOSReleaseID: string(RapidFortRedHat),
				"centos":        string(RapidFortRedHat),
				"fedora":        string(RapidFortRedHat),
			},
			Apply: ChannelConditionallyEnabled,
		},
	}
}
