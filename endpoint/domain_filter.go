/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package endpoint

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/internal/idna"
)

type MatchAllDomainFilters []DomainFilterInterface

func (f MatchAllDomainFilters) Match(domain string) bool {
	for _, filter := range f {
		if filter == nil {
			continue
		}
		if !filter.Match(domain) {
			return false
		}
	}
	return true
}

type DomainFilterInterface interface {
	Match(domain string) bool
}

// DomainFilter holds a lists of valid domain names
type DomainFilter struct {
	// Filters define what domains to match
	Filters []string
	// exclude define what domains not to match
	exclude []string
	// regex defines a regular expression to match the domains
	regex *regexp.Regexp
	// regexExclusion defines a regular expression to exclude the domains matched
	regexExclusion *regexp.Regexp
}

var _ DomainFilterInterface = &DomainFilter{}

// domainFilterSerde is a helper type for serializing and deserializing DomainFilter.
type domainFilterSerde struct {
	Include      []string `json:"include,omitempty"`
	Exclude      []string `json:"exclude,omitempty"`
	RegexInclude string   `json:"regexInclude,omitempty"`
	RegexExclude string   `json:"regexExclude,omitempty"`
}

// prepareFilters provides consistent trimming for filters/exclude params
func prepareFilters(filters []string) []string {
	var fs []string
	for _, filter := range filters {
		if domain := normalizeDomain(strings.TrimSpace(filter)); domain != "" {
			fs = append(fs, domain)
		}
	}
	return fs
}

// NewDomainFilterWithExclusions returns a new DomainFilter, given a list of matches and exclusions
func NewDomainFilterWithExclusions(domainFilters []string, excludeDomains []string) *DomainFilter {
	return &DomainFilter{Filters: prepareFilters(domainFilters), exclude: prepareFilters(excludeDomains)}
}

// NewDomainFilter returns a new DomainFilter given a comma separated list of domains
func NewDomainFilter(domainFilters []string) *DomainFilter {
	return &DomainFilter{Filters: prepareFilters(domainFilters)}
}

// NewRegexDomainFilter returns a new DomainFilter given a regular expression
func NewRegexDomainFilter(regexDomainFilter *regexp.Regexp, regexDomainExclusion *regexp.Regexp) *DomainFilter {
	return &DomainFilter{regex: regexDomainFilter, regexExclusion: regexDomainExclusion}
}

// NewDomainFilterWithOptions creates a DomainFilter based on the provided parameters.
//
// Example usage:
// df := NewDomainFilterWithOptions(
//
//	WithDomainFilter([]string{"example.com"}),
//	WithDomainExclude([]string{"test.com"}),
//
// )
func NewDomainFilterWithOptions(opts ...DomainFilterOption) *DomainFilter {
	cfg := &domainFilterConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.isRegexFilter {
		return NewRegexDomainFilter(cfg.regexInclude, cfg.regexExclude)
	}
	return NewDomainFilterWithExclusions(cfg.include, cfg.exclude)
}

// Match checks whether a domain can be found in the DomainFilter.
// RegexFilter takes precedence over Filters
func (df *DomainFilter) Match(domain string) bool {
	if df == nil {
		return true // nil filter matches everything
	}
	if df.regex != nil && df.regex.String() != "" || df.regexExclusion != nil && df.regexExclusion.String() != "" {
		return matchRegex(df.regex, df.regexExclusion, domain)
	}

	return matchFilter(df.Filters, domain, true) && !matchFilter(df.exclude, domain, false)
}

// DomainRule explains the first DomainFilter rule that decided one domain.
type DomainRule struct {
	// Configured reports whether the filter holds any rule. A nil or empty
	// filter admits every domain without evaluating a rule.
	Configured bool
	// Matched is the admission decision; it equals the result of Match.
	Matched bool
	// Negative marks an exclusion rule (exclude list or regex exclusion),
	// so a rejection by exclusion is distinguishable from a rejection that
	// merely matched no include rule.
	Negative bool
	// Text is a stable description of the deciding rule, or "" when the
	// filter is not configured.
	Text string
	// Values lists the filter entries participating in the decision, sorted
	// so reordering flag values never changes the explanation.
	Values []string
}

// ExplainMatch mirrors Match without side effects, additionally reporting the
// first rule that decided domain. It never consults the cluster or a provider.
func (df *DomainFilter) ExplainMatch(domain string) DomainRule {
	if df == nil || !df.IsConfigured() {
		return DomainRule{Configured: false, Matched: true}
	}
	if (df.regex != nil && df.regex.String() != "") || (df.regexExclusion != nil && df.regexExclusion.String() != "") {
		return explainRegexRule(df.regex, df.regexExclusion, domain)
	}
	return explainListRule(df.Filters, df.exclude, domain)
}

// matchFilter determines if any `filters` match `domain`.
// If no `filters` are provided, behavior depends on `emptyval`
// (empty `df.filters` matches everything, while empty `df.exclude` excludes nothing)
func matchFilter(filters []string, domain string, emptyval bool) bool {
	if len(filters) == 0 {
		return emptyval
	}

	return len(matchingEntries(filters, domain)) > 0
}

// matchingEntries returns every filter entry admitting domain under the
// suffix/equality rules Match uses. Order follows the configured slice;
// callers that need stable output sort the result.
func matchingEntries(filters []string, domain string) []string {
	strippedDomain := normalizeDomain(domain)
	var matched []string
	for _, filter := range filters {
		if filter == "" {
			continue
		}

		switch {
		case strings.HasPrefix(filter, ".") && strings.HasSuffix(strippedDomain, filter):
			matched = append(matched, filter)
		case strings.Count(strippedDomain, ".") == strings.Count(filter, ".") && strippedDomain == filter:
			matched = append(matched, filter)
		case strings.HasSuffix(strippedDomain, "."+filter):
			matched = append(matched, filter)
		}
	}
	return matched
}

// explainListRule explains a list-based DomainFilter, applying exclusions
// before inclusions, matching Match's evaluation order.
func explainListRule(include, exclude []string, domain string) DomainRule {
	strippedDomain := normalizeDomain(domain)

	if exclusions := matchingEntries(exclude, strippedDomain); len(exclusions) > 0 {
		slices.Sort(exclusions)
		return DomainRule{
			Configured: true,
			Matched:    false,
			Negative:   true,
			Text:       fmt.Sprintf("domain %q matched exclusion %q", strippedDomain, exclusions[0]),
			Values:     exclusions,
		}
	}

	if len(include) == 0 {
		// Exclusion-only filter and nothing fired. Keep the negative-polarity
		// entries visible so this is not mistaken for an unconfigured filter.
		values := append([]string(nil), exclude...)
		slices.Sort(values)
		return DomainRule{
			Configured: true,
			Matched:    true,
			Negative:   true,
			Text:       fmt.Sprintf("domain %q matched no exclusion rule", strippedDomain),
			Values:     values,
		}
	}

	if inclusions := matchingEntries(include, strippedDomain); len(inclusions) > 0 {
		slices.Sort(inclusions)
		return DomainRule{
			Configured: true,
			Matched:    true,
			Text:       fmt.Sprintf("domain %q matched inclusion %q", strippedDomain, inclusions[0]),
			Values:     inclusions,
		}
	}

	values := append([]string(nil), include...)
	slices.Sort(values)
	return DomainRule{
		Configured: true,
		Matched:    false,
		Text:       fmt.Sprintf("domain %q matched no inclusion rule", strippedDomain),
		Values:     values,
	}
}

// explainRegexRule explains a regex-based DomainFilter, checking exclusion
// before inclusion, matching matchRegex's evaluation order.
func explainRegexRule(regex, negativeRegex *regexp.Regexp, domain string) DomainRule {
	strippedDomain := normalizeDomain(domain)

	if negativeRegex != nil && negativeRegex.String() != "" && negativeRegex.MatchString(strippedDomain) {
		pattern := negativeRegex.String()
		return DomainRule{
			Configured: true,
			Matched:    false,
			Negative:   true,
			Text:       fmt.Sprintf("domain %q matched regex exclusion %q", strippedDomain, pattern),
			Values:     []string{pattern},
		}
	}

	if regex != nil && regex.String() != "" {
		pattern := regex.String()
		if regex.MatchString(strippedDomain) {
			return DomainRule{
				Configured: true,
				Matched:    true,
				Text:       fmt.Sprintf("domain %q matched regex inclusion %q", strippedDomain, pattern),
				Values:     []string{pattern},
			}
		}
		return DomainRule{
			Configured: true,
			Matched:    false,
			Text:       fmt.Sprintf("domain %q did not match regex inclusion %q", strippedDomain, pattern),
			Values:     []string{pattern},
		}
	}

	// Only a regex exclusion is configured and it did not match: the domain
	// passes because the negative rule never fired.
	pattern := negativeRegex.String()
	return DomainRule{
		Configured: true,
		Matched:    true,
		Negative:   true,
		Text:       fmt.Sprintf("domain %q did not match regex exclusion %q", strippedDomain, pattern),
		Values:     []string{pattern},
	}
}

// matchRegex determines if a domain matches the configured regular expressions in DomainFilter.
// The function checks exclusion first, then inclusion:
// 1. If negativeRegex is set and matches the domain, return false (excluded)
// 2. If regex is set and matches the domain, return true (included)
// 3. If regex is not set but negativeRegex is set, return true (not excluded, no inclusion filter)
// 4. If regex is set but doesn't match, return false (not included)
func matchRegex(regex *regexp.Regexp, negativeRegex *regexp.Regexp, domain string) bool {
	strippedDomain := normalizeDomain(domain)

	// First check exclusion - if domain matches exclusion, reject it
	if negativeRegex != nil && negativeRegex.String() != "" {
		if negativeRegex.MatchString(strippedDomain) {
			return false
		}
	}

	// Then check inclusion filter if set
	if regex != nil && regex.String() != "" {
		return regex.MatchString(strippedDomain)
	}

	// If only exclusion is set (no inclusion filter), accept the domain
	// since it didn't match the exclusion
	return true
}

// IsConfigured returns true if any inclusion or exclusion rules have been specified.
func (df *DomainFilter) IsConfigured() bool {
	if df == nil {
		return false // nil filter is not configured
	}
	if df.regex != nil && df.regex.String() != "" {
		return true
	} else if df.regexExclusion != nil && df.regexExclusion.String() != "" {
		return true
	}
	return len(df.Filters) > 0 || len(df.exclude) > 0
}

func (df *DomainFilter) MarshalJSON() ([]byte, error) {
	if df == nil {
		// compatibility with nil DomainFilter
		return json.Marshal(domainFilterSerde{
			Include: nil,
			Exclude: nil,
		})
	}
	if df.regex != nil || df.regexExclusion != nil {
		var include, exclude string
		if df.regex != nil {
			include = df.regex.String()
		}
		if df.regexExclusion != nil {
			exclude = df.regexExclusion.String()
		}
		return json.Marshal(domainFilterSerde{
			RegexInclude: include,
			RegexExclude: exclude,
		})
	}
	sort.Strings(df.Filters)
	sort.Strings(df.exclude)
	return json.Marshal(domainFilterSerde{
		Include: df.Filters,
		Exclude: df.exclude,
	})
}

func (df *DomainFilter) UnmarshalJSON(b []byte) error {
	var deserialized domainFilterSerde
	err := json.Unmarshal(b, &deserialized)
	if err != nil {
		return err
	}

	if deserialized.RegexInclude == "" && deserialized.RegexExclude == "" {
		*df = *NewDomainFilterWithExclusions(deserialized.Include, deserialized.Exclude)
		return nil
	}

	if len(deserialized.Include) > 0 || len(deserialized.Exclude) > 0 {
		return errors.New("cannot have both domain list and regex")
	}

	var include, exclude *regexp.Regexp
	if deserialized.RegexInclude != "" {
		include, err = regexp.Compile(deserialized.RegexInclude)
		if err != nil {
			return fmt.Errorf("invalid regexInclude: %w", err)
		}
	}
	if deserialized.RegexExclude != "" {
		exclude, err = regexp.Compile(deserialized.RegexExclude)
		if err != nil {
			return fmt.Errorf("invalid regexExclude: %w", err)
		}
	}
	*df = *NewRegexDomainFilter(include, exclude)
	return nil
}

func (df *DomainFilter) MatchParent(domain string) bool {
	if df == nil {
		return true // nil filter matches everything
	}
	if matchFilter(df.exclude, domain, false) {
		return false
	}
	if len(df.Filters) == 0 {
		return true
	}

	strippedDomain := normalizeDomain(domain)
	for _, filter := range df.Filters {
		if filter == "" || strings.HasPrefix(filter, ".") {
			// We don't check parents if the filter is prefixed with "."
			continue
		}
		if strings.HasSuffix(filter, "."+strippedDomain) {
			return true
		}
	}
	return false
}

// normalizeDomain converts a domain to a canonical form, so that we can filter on it
// it: trim "." suffix, get Unicode version of domain compliant with Section 5 of RFC 5891
func normalizeDomain(domain string) string {
	s, err := idna.Profile.ToUnicode(strings.TrimSuffix(domain, "."))
	if err != nil {
		log.Warnf(`Got error while parsing domain %s: %v`, domain, err)
	}
	return s
}

type DomainFilterOption func(*domainFilterConfig)
type domainFilterConfig struct {
	include       []string
	exclude       []string
	regexInclude  *regexp.Regexp
	regexExclude  *regexp.Regexp
	isRegexFilter bool
}

func WithDomainFilter(filters []string) DomainFilterOption {
	return func(cfg *domainFilterConfig) {
		cfg.include = prepareFilters(filters)
	}
}

func WithDomainExclude(exclude []string) DomainFilterOption {
	return func(cfg *domainFilterConfig) {
		cfg.exclude = prepareFilters(exclude)
	}
}

func WithRegexDomainFilter(regex *regexp.Regexp) DomainFilterOption {
	return func(cfg *domainFilterConfig) {
		cfg.regexInclude = regex
		if regex != nil && regex.String() != "" {
			cfg.isRegexFilter = true
		}
	}
}

func WithRegexDomainExclude(regex *regexp.Regexp) DomainFilterOption {
	return func(cfg *domainFilterConfig) {
		cfg.regexExclude = regex
		if regex != nil && regex.String() != "" {
			cfg.isRegexFilter = true
		}
	}
}
