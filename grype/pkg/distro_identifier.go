package pkg

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// applyDistroIdentifiers applies the first identifier triggered by the source evidence to d.
func applyDistroIdentifiers(s *sbom.SBOM, d *distro.Distro, identifiers []distro.Identifier) *distro.Distro {
	if d == nil {
		return d
	}

	for _, o := range identifiers {
		if o.Apply == distro.ChannelNeverEnabled {
			continue
		}
		if !identifierTriggered(o, s) {
			continue
		}
		newID, ok := o.DistroIDs[d.ID()]
		if !ok {
			continue
		}
		newType, ok := distro.IDMapping[newID]
		if !ok {
			log.WithFields("rule", o.Name, "distro", newID).Warn("distro identifier maps to an unknown distro ID")
			continue
		}

		nd := distro.New(newType, d.Version, "", d.IDLike...)

		// base-distro channels (e.g. esm/eus) are not inherited: they would exclude the identified
		// distro's channel-less OS records
		nd.Channels = o.Channels

		log.WithFields("rule", o.Name, "from", d.ID(), "to", newID).Info("applying source-evidence distro identifier")

		return nd
	}

	return d
}

// identifierTriggered indicates if the scanned source carries a marker file or a matching image label.
func identifierTriggered(o distro.Identifier, s *sbom.SBOM) bool {
	if s != nil {
		for _, p := range o.MarkerPaths {
			if sbomHasPath(s, p) {
				return true
			}
		}

		if o.Label.Key != "" && sourceMatchesLabel(&s.Source, o.Label) {
			return true
		}
	}

	return false
}

// sourceMatchesLabel indicates if the source is a container image with a label satisfying m.
func sourceMatchesLabel(src *source.Description, m distro.LabelMatcher) bool {
	if src == nil {
		return false
	}

	meta, ok := src.Metadata.(source.ImageMetadata)
	if !ok {
		return false
	}

	for key, value := range meta.Labels {
		if m.Matches(key, value) {
			return true
		}
	}

	return false
}

// sbomHasPath reports whether the SBOM's file catalog contains path. Default syft cataloging does
// not record arbitrary files, so this only finds markers a file cataloger recorded.
func sbomHasPath(s *sbom.SBOM, path string) bool {
	if s == nil {
		return false
	}
	for coordinates := range s.Artifacts.FileMetadata {
		if coordinates.RealPath == path {
			return true
		}
	}
	return false
}
