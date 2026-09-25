package v6

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// Rules are evaluated against the criteria of one search, not the cataloged package, since matchers
// search under other names and versions (upstreams, rootio names, epoch-patched rpm versions). A
// predicate on something the criteria do not state does not match.

// SearchRuleProvider is implemented by providers that evaluate search rules.
type SearchRuleProvider interface {
	// SearchRewrites returns the zero value when no rule applies.
	SearchRewrites(criteria []vulnerability.Criteria) SearchRewrites
}

// SearchRewrites is the combined outcome of the search rules that apply to one search.
type SearchRewrites struct {
	// Distros are additional OS identities to search: a channel of the searched OS, or another OS
	Distros []distro.Distro

	// PackageNames are additional names to search
	PackageNames []string

	// ExcludeOSLess skips searches that read no OS rows (CPE searches against NVD), since the
	// package's OS rows fully describe it
	ExcludeOSLess bool
}

// anchorPattern matches the whole subject. The group is non-capturing so $N references keep their
// numbers, and so a top-level `|` is anchored on every branch.
func anchorPattern(p string) string {
	return "^(?:" + p + ")$"
}

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
		return fmt.Errorf("search rule with a channel substitution must have a distro name to match")
	}
	if o.MatchPackageName == "" && o.MatchPackageVersion == "" && o.hasSubstitution() {
		return fmt.Errorf("search rule with a substitution must have at least one package predicate")
	}
	return nil
}

// hasSubstitution is false for rules that only mark packages as fully described by OS rows, and for
// rules that only keep the OS-less partition searched.
func (o SearchRule) hasSubstitution() bool {
	if o.isDistrolessSearch() {
		return o.ReplacementChannel != nil || o.ReplacementPackageName != ""
	}
	return o.ReplacementChannel != nil || o.ReplacementDistroName != nil || o.ReplacementPackageName != ""
}

// isDistrolessSearch is true for an empty, non-NULL ReplacementDistroName, which keeps CPE (NVD)
// searches for the matched packages.
func (o SearchRule) isDistrolessSearch() bool {
	return o.ReplacementDistroName != nil && *o.ReplacementDistroName == ""
}

type compiledSearchRule struct {
	row SearchRule

	// ord is the rule's position in the set as read
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

// namedGroups returns the named groups of the match patterns, rejecting a name defined by more than
// one pattern.
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

// compileSearchRules skips invalid rows with a warning.
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

// searchSubject is what one search states about the package it searches for.
type searchSubject struct {
	name      string
	version   string
	ecosystem string
	distro    *distro.Distro
}

// searchSubjects returns one subject per searched OS, or one with no OS. The last criterion of each
// kind wins.
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

// ruleMatch holds what a matching rule's patterns captured.
type ruleMatch struct {
	named map[string]string

	// positional groups of MatchPackageName and MatchPackageVersion
	nameGroups    []string
	versionGroups []string
}

// match returns the captures when every predicate matches. An Exclude* predicate only rejects when
// its subject is present.
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

// capture records re's named groups and returns its positional groups, or nil when re does not match.
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

func (r *compiledSearchRule) hasDistroPredicate() bool {
	return r.row.MatchDistroName != "" || r.distroVersion != nil
}

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

// overlayDistro returns the OS the rule adds: the searched OS with the rule's channel, and/or another
// OS name, or nil. A search with no OS can only gain a version-less OS name.
func (r *compiledSearchRule) overlayDistro(s searchSubject, m *ruleMatch) *distro.Distro {
	row := r.row
	if (row.ReplacementChannel == nil && row.ReplacementDistroName == nil) || row.isDistrolessSearch() {
		return nil
	}

	var name string
	if row.ReplacementDistroName != nil {
		if name = r.distroName.expand(nil, m.named); name == "" {
			return nil
		}
	}

	if s.distro == nil {
		if name == "" {
			return nil
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

func (r *compiledSearchRule) expandPackageName(m *ruleMatch) string {
	if r.row.ReplacementPackageName == "" {
		return ""
	}
	return r.name.expand(m.nameGroups, m.named)
}

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

// highestPriority keeps the matched rules at the highest Priority. Rules with no substitution are
// always kept: they describe the package's data rather than compete over how it is searched.
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

type template []templatePart

type templatePart struct {
	literal string

	// ref is a group name or number; empty for a literal
	ref string

	// positional is the group number, or -1 when ref is a name
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

// extractRef parses the reference at the start of s, which begins with `$`.
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
	n, err := strconv.Atoi(ref)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// validate rejects references that can never resolve against positional (nil forbids positional
// references) or named.
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

// expand resolves references; an unmatched group expands empty.
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
