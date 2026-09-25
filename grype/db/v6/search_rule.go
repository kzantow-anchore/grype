package v6

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// Rules are evaluated against the criteria of one search (see searchSubjects), not against the
// cataloged package: matchers search under other names and versions (upstream packages, fanned-out
// names, epoch-patched rpm versions). A predicate whose subject the criteria do not state cannot
// match. The caller states what a search does not carry but the rules need as additional criteria
// (see result.applySearchRules): the package's ecosystem on an OS search, and the package's name,
// version and OS on a CPE search.
//
// Rules are ranked, not ordered: only the highest-priority matching rules apply, ties all apply, and
// rules with no substitution always apply (see highestPriority).
//
// Every pattern is anchored (see anchorPattern). Replacements are templates (see parseTemplate):
// `${name}` references a named group `(?P<name>...)` of any match pattern, and `$N` references group N
// of the pattern the replacement is derived from (MatchPackageVersion for ReplacementChannel,
// MatchPackageName for ReplacementPackageName). Use `.*?` before a group so it binds the first marker
// rather than the last.

// SearchRuleProvider is implemented by providers that evaluate search rules (see SearchRule).
type SearchRuleProvider interface {
	// SearchRewrites returns how the search stated by criteria is rewritten: the zero value when no
	// rule applies.
	SearchRewrites(criteria []vulnerability.Criteria) SearchRewrites
}

// SearchRewrites is the resolved outcome of the search rules that apply to one search.
type SearchRewrites struct {
	// Distros are OS identities to search in addition to the search's own: a channel of its OS, or
	// another OS
	Distros []distro.Distro

	// PackageNames are names to search in addition to the search's own
	PackageNames []string

	// ExcludeOSLess indicates the package is fully described by OS rows (its own and Distros), so
	// searches that read no OS rows for it are not run. The OS-less partition is the CPE-indexed (NVD)
	// records: a CPE search for a package on an OS is such a search.
	ExcludeOSLess bool
}

// anchorPattern anchors a rule pattern to the whole subject. The group is non-capturing so $N
// references keep their numbers, and so a top-level `|` does not anchor only its outer branches.
func anchorPattern(p string) string {
	return "^(?:" + p + ")$"
}

// Validate reports why the row is not a legal rule. It is shared by compileSearchRules (skip) and
// BeforeCreate (reject).
func (o SearchRule) Validate() error {
	_, err := compileSearchRule(o)
	return err
}

func (o SearchRule) validatePredicates() error {
	if o.MatchDistroName == "" && o.MatchDistroVersion == "" && o.MatchEcosystem == "" && o.MatchPackageName == "" && o.MatchPackageVersion == "" {
		return fmt.Errorf("search rule must have at least one predicate")
	}
	if o.ReplacementPackageName != "" && o.MatchPackageName == "" {
		return fmt.Errorf("search rule with a replacement package name must have a package name pattern")
	}
	if o.MatchDistroName == "" && o.ReplacementChannel != nil {
		// a channel is relative to one OS
		return fmt.Errorf("search rule with a channel substitution must have a distro name to match")
	}
	if o.MatchPackageName == "" && o.MatchPackageVersion == "" && o.hasSubstitution() {
		// only a rule with no substitution may be scoped to an OS or ecosystem alone
		return fmt.Errorf("search rule with a substitution must have at least one package predicate")
	}
	return nil
}

// hasSubstitution indicates whether the rule changes how a matched package is searched. A rule with
// no substitution marks packages fully described by OS rows (see SearchRewrites.ExcludeOSLess). A
// distroless search is not a substitution (see isDistrolessSearch).
func (o SearchRule) hasSubstitution() bool {
	if o.isDistrolessSearch() {
		return o.ReplacementChannel != nil || o.ReplacementPackageName != ""
	}
	return o.ReplacementChannel != nil || o.ReplacementDistroName != nil || o.ReplacementPackageName != ""
}

// isDistrolessSearch indicates whether the rule names the OS-less partition (the CPE-indexed, NVD
// records): a non-NULL but empty replacement OS name. No store search is rewritten; the rule only keeps
// that partition searched (see SearchRewrites.ExcludeOSLess).
func (o SearchRule) isDistrolessSearch() bool {
	return o.ReplacementDistroName != nil && *o.ReplacementDistroName == ""
}

// compiledSearchRule is the compiled form of a SearchRule row: each pattern as an anchored regex, each
// replacement as a parsed template.
type compiledSearchRule struct {
	row SearchRule

	// ord is the rule's position in the set as read (see searchRuleIndex.candidates)
	ord int

	distroVersion     *regexp.Regexp
	pkgName           *regexp.Regexp
	excludePkgName    *regexp.Regexp
	pkgVersion        *regexp.Regexp
	excludePkgVersion *regexp.Regexp

	channel    template
	distroName template
	name       template
}

// compileSearchRule compiles and validates one row.
func compileSearchRule(row SearchRule) (*compiledSearchRule, error) {
	if err := row.validatePredicates(); err != nil {
		return nil, err
	}

	rule := &compiledSearchRule{row: row}
	for _, pc := range []struct {
		pattern string
		dst     **regexp.Regexp
	}{
		{row.MatchDistroVersion, &rule.distroVersion},
		{row.MatchPackageName, &rule.pkgName},
		{row.ExcludePackageName, &rule.excludePkgName},
		{row.MatchPackageVersion, &rule.pkgVersion},
		{row.ExcludePackageVersion, &rule.excludePkgVersion},
	} {
		if pc.pattern == "" {
			continue
		}
		re, err := regexp.Compile(anchorPattern(pc.pattern))
		if err != nil {
			return nil, fmt.Errorf("search rule has an invalid pattern %q: %w", pc.pattern, err)
		}
		*pc.dst = re
	}

	named, err := rule.namedGroups()
	if err != nil {
		return nil, err
	}

	for _, tc := range []struct {
		field string
		value *string
		// positional is the pattern $N references resolve against; nil forbids them
		positional *regexp.Regexp
		dst        *template
	}{
		{"replacement channel", row.ReplacementChannel, rule.pkgVersion, &rule.channel},
		{"replacement distro name", row.ReplacementDistroName, nil, &rule.distroName},
		{"replacement package name", &row.ReplacementPackageName, rule.pkgName, &rule.name},
	} {
		if tc.value == nil {
			continue
		}
		t := parseTemplate(*tc.value)
		if err := t.validate(tc.positional, named); err != nil {
			return nil, fmt.Errorf("search rule %s %q: %w", tc.field, *tc.value, err)
		}
		*tc.dst = t
	}

	return rule, nil
}

// namedGroups returns the named groups of the match patterns, which any replacement may reference. A
// name defined by more than one pattern is ambiguous. Exclude patterns bind nothing: they only reject.
func (r *compiledSearchRule) namedGroups() (map[string]struct{}, error) {
	out := map[string]struct{}{}
	for _, re := range []*regexp.Regexp{r.distroVersion, r.pkgName, r.pkgVersion} {
		if re == nil {
			continue
		}
		seen := map[string]struct{}{}
		for _, n := range re.SubexpNames() {
			if n == "" {
				continue
			}
			if _, ok := seen[n]; ok {
				continue // repeated within one pattern (alternation branches)
			}
			seen[n] = struct{}{}
			if _, ok := out[n]; ok {
				return nil, fmt.Errorf("search rule defines group %q in more than one pattern", n)
			}
			out[n] = struct{}{}
		}
	}
	return out, nil
}

// compileSearchRules compiles rows in order, skipping invalid rows with a warning.
func compileSearchRules(rows []SearchRule) []*compiledSearchRule {
	var rules []*compiledSearchRule
	for _, row := range rows {
		rule, err := compileSearchRule(row)
		if err != nil {
			log.WithFields("error", err, "distro", row.MatchDistroName, "ecosystem", row.MatchEcosystem).Warn("skipping invalid search rule")
			continue
		}
		rules = append(rules, rule)
	}
	return rules
}

// searchSubject is what one search states about the package it searches for, as the rules read it.
type searchSubject struct {
	name      string
	version   string
	ecosystem string
	distro    *distro.Distro
}

// searchSubjects restates criteria as the subjects the rules are evaluated against: one per OS the
// search reads, or one with no OS. The last criterion of each kind wins.
func searchSubjects(criteria []vulnerability.Criteria) []searchSubject {
	var subject searchSubject
	var distros []distro.Distro
	for _, c := range criteria {
		switch c := c.(type) {
		case *search.PackageNameCriteria:
			subject.name = c.PackageName
		case *search.IndirectPackageNameCriteria:
			subject.name = c.PackageName
		case *search.VersionCriteria:
			subject.version = c.Version.Raw
		case search.VersionCriteria:
			subject.version = c.Version.Raw
		case *search.PackageVersionCriteria:
			subject.version = c.Version.Raw
		case *search.EcosystemCriteria:
			switch {
			case c.PackageType != "" && c.PackageType != syftPkg.UnknownPkg:
				subject.ecosystem = string(c.PackageType)
			case c.Language != "":
				subject.ecosystem = string(c.Language)
			}
		case *search.DistroCriteria:
			distros = append(distros, c.Distros...)
		}
	}
	if len(distros) == 0 {
		return []searchSubject{subject}
	}
	out := make([]searchSubject, 0, len(distros))
	for i := range distros {
		s := subject
		s.distro = &distros[i]
		out = append(out, s)
	}
	return out
}

// ruleMatch holds what a matching rule's patterns captured from the subject.
type ruleMatch struct {
	// named holds every named group of the match patterns (see namedGroups); an unmatched group is ""
	named map[string]string

	// nameGroups and versionGroups hold the positional groups of MatchPackageName and
	// MatchPackageVersion, group 0 being the whole subject
	nameGroups    []string
	versionGroups []string
}

// match reports what the rule captured when every set predicate matches the subject. A predicate
// whose subject the search does not state fails; an Exclude* predicate only rejects when its subject
// is present and matches.
func (r *compiledSearchRule) match(s searchSubject) (*ruleMatch, bool) {
	m := &ruleMatch{}

	if r.hasDistroPredicate() && !r.matchesDistro(s.distro, m) {
		return nil, false
	}
	if r.row.MatchEcosystem != "" && !strings.EqualFold(r.row.MatchEcosystem, s.ecosystem) {
		return nil, false
	}

	if r.pkgName != nil {
		if s.name == "" {
			return nil, false
		}
		if m.nameGroups = m.capture(r.pkgName, s.name); m.nameGroups == nil {
			return nil, false
		}
	}
	if r.excludePkgName != nil && s.name != "" && r.excludePkgName.MatchString(s.name) {
		return nil, false
	}
	if r.pkgVersion != nil {
		if s.version == "" {
			return nil, false
		}
		if m.versionGroups = m.capture(r.pkgVersion, s.version); m.versionGroups == nil {
			return nil, false
		}
	}
	if r.excludePkgVersion != nil && s.version != "" && r.excludePkgVersion.MatchString(s.version) {
		return nil, false
	}
	return m, true
}

// capture matches re against subject, recording its named groups; nil when re does not match.
func (m *ruleMatch) capture(re *regexp.Regexp, subject string) []string {
	groups := re.FindStringSubmatch(subject)
	if groups == nil {
		return nil
	}
	for i, n := range re.SubexpNames() {
		if n == "" {
			continue
		}
		if m.named == nil {
			m.named = map[string]string{}
		}
		// a name repeated across alternation branches binds the branch that matched
		if groups[i] != "" || m.named[n] == "" {
			m.named[n] = groups[i]
		}
	}
	return groups
}

// hasDistroPredicate indicates whether the rule constrains which OS it applies to.
func (r *compiledSearchRule) hasDistroPredicate() bool {
	return r.row.MatchDistroName != "" || r.distroVersion != nil
}

// matchesDistro indicates whether the distro predicates match; a search with no OS matches none.
func (r *compiledSearchRule) matchesDistro(d *distro.Distro, m *ruleMatch) bool {
	if d == nil {
		return false
	}
	if r.row.MatchDistroName != "" && !strings.EqualFold(r.row.MatchDistroName, d.Name()) {
		return false
	}
	if r.distroVersion != nil && !r.matchesDistroVersion(d, m) {
		return false
	}
	return true
}

// matchesDistroVersion matches the release version, then the version label, as
// OSSpecifier.matchesVersionPattern does.
func (r *compiledSearchRule) matchesDistroVersion(d *distro.Distro, m *ruleMatch) bool {
	if d.Version != "" && m.capture(r.distroVersion, d.Version) != nil {
		return true
	}
	return d.LabelVersion() != "" && m.capture(r.distroVersion, d.LabelVersion()) != nil
}

// overlayDistro returns the OS identity the rule adds to the search: the searched OS with the rule's
// channel, and/or another OS name. nil when the rule rewrites no OS. An OS-less search can only gain
// an OS name, version-free (e.g. echo alongside debian's OS-less ecosystem rows).
func (r *compiledSearchRule) overlayDistro(s searchSubject, m *ruleMatch) *distro.Distro {
	row := r.row
	if (row.ReplacementChannel == nil && row.ReplacementDistroName == nil) || row.isDistrolessSearch() {
		return nil
	}

	var name string
	if row.ReplacementDistroName != nil {
		if name = r.distroName.expand(nil, m.named); name == "" {
			return nil // a template that expands empty names no OS
		}
	}

	if s.distro == nil {
		if name == "" {
			return nil // a channel needs a searched OS to apply to
		}
		return distro.New(distro.TypeFromID(name), "", "")
	}

	overlay := *s.distro
	overlay.Channels = nil
	if name != "" {
		overlay = *distro.New(distro.TypeFromID(name), s.distro.Version, "")
	}
	if row.ReplacementChannel != nil {
		// an empty expansion selects the channel-less rows
		if channel := r.channel.expand(m.versionGroups, m.named); channel != "" {
			overlay.Channels = []string{channel}
		}
	}
	return &overlay
}

// expandPackageName returns the additional name this rule adds, or "" when it adds none.
func (r *compiledSearchRule) expandPackageName(m *ruleMatch) string {
	if r.row.ReplacementPackageName == "" {
		return ""
	}
	return r.name.expand(m.nameGroups, m.named)
}

// rewrites resolves the rules that apply to the search stated by criteria (see highestPriority) into
// the searches they add, per OS the search reads. A rule with no substitution states the package is
// fully described by OS rows, excluding the OS-less partition, unless a rule names that partition
// (see isDistrolessSearch).
func (idx *searchRuleIndex) rewrites(criteria []vulnerability.Criteria) SearchRewrites {
	var out SearchRewrites
	includeOSLess := false
	for _, s := range searchSubjects(criteria) {
		for _, rm := range highestPriority(matchingRules(idx, s)) {
			r := rm.rule
			switch {
			case r.row.isDistrolessSearch():
				includeOSLess = true
			case !r.row.hasSubstitution():
				out.ExcludeOSLess = true
			}
			if d := r.overlayDistro(s, rm.match); d != nil {
				out.Distros = append(out.Distros, *d)
			}
			if name := r.expandPackageName(rm.match); name != "" && name != s.name && !slices.Contains(out.PackageNames, name) {
				out.PackageNames = append(out.PackageNames, name)
			}
		}
	}
	if includeOSLess {
		out.ExcludeOSLess = false
	}
	return out
}

// matchedRule is a rule that matched a subject, with what it captured.
type matchedRule struct {
	rule  *compiledSearchRule
	match *ruleMatch
}

func matchingRules(idx *searchRuleIndex, s searchSubject) []matchedRule {
	var buf [16]*compiledSearchRule
	var matched []matchedRule
	for _, r := range idx.candidates(s, buf[:0]) {
		if m, ok := r.match(s); ok {
			matched = append(matched, matchedRule{rule: r, match: m})
		}
	}
	return matched
}

// highestPriority narrows matched rules to those at the highest Priority. Rules with no substitution
// are not ranked and are always kept: they state a fact about the package's data rather than compete
// over how it is searched.
func highestPriority(matched []matchedRule) []matchedRule {
	if len(matched) < 2 {
		return matched
	}
	best, ranked := 0, false
	for _, m := range matched {
		if !m.rule.row.hasSubstitution() {
			continue
		}
		if !ranked || m.rule.row.Priority > best {
			best, ranked = m.rule.row.Priority, true
		}
	}
	out := make([]matchedRule, 0, len(matched))
	for _, m := range matched {
		if !m.rule.row.hasSubstitution() || m.rule.row.Priority == best {
			out = append(out, m)
		}
	}
	return out
}

// template is a parsed replacement: literal text and group references.
type template []templatePart

type templatePart struct {
	literal string

	// ref is the referenced group: a name, or a number for a positional reference
	ref string

	// positional is the group number when ref is a number, else -1
	positional int
}

// parseTemplate parses a replacement as regexp.Regexp.Expand does: `$name` or `${name}` references a
// group, where a name is a run of letters, digits and underscores (so `$1x` is the group named "1x";
// write `${1}x`), and `$$` is a literal `$`. A `$` that starts no reference is literal.
func parseTemplate(s string) template {
	var out template
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			out = append(out, templatePart{literal: lit.String(), positional: -1})
			lit.Reset()
		}
	}
	for len(s) > 0 {
		i := strings.IndexByte(s, '$')
		if i < 0 {
			lit.WriteString(s)
			break
		}
		lit.WriteString(s[:i])
		s = s[i:]
		if len(s) > 1 && s[1] == '$' {
			lit.WriteByte('$')
			s = s[2:]
			continue
		}
		ref, rest, ok := extractRef(s)
		if !ok {
			lit.WriteByte('$')
			s = s[1:]
			continue
		}
		flush()
		out = append(out, templatePart{ref: ref, positional: positionalRef(ref)})
		s = rest
	}
	flush()
	return out
}

// extractRef returns the group reference at the start of s (which begins with `$`) and what follows it.
func extractRef(s string) (ref, rest string, ok bool) {
	s = s[1:]
	braced := len(s) > 0 && s[0] == '{'
	if braced {
		s = s[1:]
	}
	i := 0
	for i < len(s) && isRefByte(s[i]) {
		i++
	}
	if i == 0 {
		return "", "", false
	}
	ref, rest = s[:i], s[i:]
	if braced {
		if len(rest) == 0 || rest[0] != '}' {
			return "", "", false
		}
		rest = rest[1:]
	}
	return ref, rest, true
}

func isRefByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// positionalRef returns the group number ref names, or -1 when ref is a name.
func positionalRef(ref string) int {
	n := 0
	for i := 0; i < len(ref); i++ {
		if ref[i] < '0' || ref[i] > '9' {
			return -1
		}
		n = n*10 + int(ref[i]-'0')
		if n > 1<<16 {
			return -1
		}
	}
	return n
}

// validate reports a reference that can never resolve: a positional group positional does not have
// (or any positional group when positional is nil), or a name no match pattern defines.
func (t template) validate(positional *regexp.Regexp, named map[string]struct{}) error {
	for _, p := range t {
		switch {
		case p.ref == "":
			continue
		case p.positional >= 0:
			if positional == nil {
				return fmt.Errorf("positional reference $%s has no pattern to resolve against; use a named group", p.ref)
			}
			if p.positional > positional.NumSubexp() {
				return fmt.Errorf("reference $%s exceeds the %d groups of its pattern", p.ref, positional.NumSubexp())
			}
		default:
			if _, ok := named[p.ref]; !ok {
				return fmt.Errorf("reference ${%s} names no group of a match pattern", p.ref)
			}
		}
	}
	return nil
}

// expand resolves the template: positional references against groups, names against named. An
// unmatched group expands empty.
func (t template) expand(groups []string, named map[string]string) string {
	var sb strings.Builder
	for _, p := range t {
		switch {
		case p.ref == "":
			sb.WriteString(p.literal)
		case p.positional >= 0:
			if p.positional < len(groups) {
				sb.WriteString(groups[p.positional])
			}
		default:
			sb.WriteString(named[p.ref])
		}
	}
	return sb.String()
}
