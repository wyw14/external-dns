/*
Copyright 2026 The Kubernetes Authors.

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

// Package filterchain explains source filtering decisions without performing
// any I/O. Given an in-memory snapshot of an endpoint and the source-object
// metadata it was derived from, Explain replays the namespace, label,
// annotation, and domain filters in their fixed priority order and reports
// the first rule that decides the outcome together with the full stage chain.
//
// The explainer holds no Kubernetes client and no provider handle, so by
// construction it cannot read the cluster or call a DNS provider.
package filterchain

import (
	"fmt"
	"slices"
	"strings"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/internal/sets"
)

// Stage is one position in the fixed filter chain.
type Stage int

const (
	// StageNamespace scopes which Kubernetes namespaces sources watch; it is
	// applied first by the informer factories and cache namespace options.
	StageNamespace Stage = iota
	// StageLabel gates objects on their Kubernetes labels.
	StageLabel
	// StageAnnotation gates objects on their annotations.
	StageAnnotation
	// StageDomain runs last, in the planner, against endpoint DNS names.
	StageDomain
	// StageDefault is the terminal default-allow decision, not a configured filter.
	StageDefault

	stageCount = StageDomain + 1
)

// State is the outcome of one stage for one candidate.
type State string

const (
	// StatePassed means a configured filter admitted the candidate.
	StatePassed State = "passed"
	// StateExcluded means a configured rule rejected the candidate.
	StateExcluded State = "excluded"
	// StateNotConfigured means the stage had an empty filter and evaluated no rule.
	StateNotConfigured State = "not-configured"
	// StateSkipped means the stage was never reached because an earlier stage
	// excluded the candidate.
	StateSkipped State = "skipped"
)

// Polarity marks whether a rule is an inclusion (positive) or exclusion
// (negative) condition. Empty filters carry no polarity.
type Polarity string

const (
	PolarityNone     Polarity = ""
	PolarityPositive Polarity = "positive"
	PolarityNegative Polarity = "negative"
)

// Outcome is the final short-circuit decision for a candidate.
type Outcome string

const (
	OutcomeKept     Outcome = "kept"
	OutcomeExcluded Outcome = "excluded"
)

// Rule describes the first rule that settled a stage for a candidate.
type Rule struct {
	// Text is a stable, human-readable rendering of the rule.
	Text string
	// Polarity distinguishes negative exclusion conditions from positive
	// inclusion conditions. An empty filter carries PolarityNone.
	Polarity Polarity
	// Values lists the configured values participating in the decision,
	// sorted so reordering the input configuration never changes the output.
	Values []string
}

// StageResult records what one filter stage decided about a candidate.
type StageResult struct {
	Stage Stage
	State State
	// Rule is zero-value (empty Text) when State is StateNotConfigured or
	// StateSkipped.
	Rule Rule
}

// Explanation is the short-circuit trace for one candidate endpoint.
type Explanation struct {
	DNSName   string
	Namespace string
	Outcome   Outcome
	// DecidedBy names the stage that produced Outcome: StageDefault when
	// every configured filter passed and default allow applied.
	DecidedBy Stage
	// FirstRule is the excluding rule for OutcomeExcluded, or the
	// default-allow terminal rule for OutcomeKept.
	FirstRule Rule
	// Chain holds one StageResult per real filter stage in fixed priority
	// order: namespace, label, annotation, domain.
	Chain []StageResult
}

// Candidate is the self-contained snapshot Explain evaluates. It carries no
// client or provider handle: the explainer cannot reach the cluster or a DNS
// provider by construction.
type Candidate struct {
	DNSName     string
	Namespace   string
	Labels      map[string]string
	Annotations map[string]string
}

// Config is the immutable filter configuration an Explainer replays.
type Config struct {
	// Namespaces is the watched-namespace list. Empty or containing
	// v1.NamespaceAll means every namespace is admitted.
	Namespaces []string
	// LabelFilter and AnnotationFilter are the parsed source selectors. A
	// nil or empty selector disables the corresponding stage.
	LabelFilter      labels.Selector
	AnnotationFilter labels.Selector
	// DomainFilter is the user-configured domain filter. A nil or empty
	// filter disables the stage. The registry/provider domain filter is
	// deliberately excluded so Explain never depends on a provider.
	DomainFilter *endpoint.DomainFilter
}

// Explainer replays the source filter chain against in-memory candidates.
// It is safe for concurrent use: it never mutates after New returns.
type Explainer struct {
	watchAllNamespaces bool
	namespaces         sets.Set[string]
	labelFilter        labels.Selector
	annotationFilter   labels.Selector
	domainFilter       *endpoint.DomainFilter
}

var stageNames = map[Stage]string{
	StageNamespace:  "namespace",
	StageLabel:      "label",
	StageAnnotation: "annotation",
	StageDomain:     "domain",
	StageDefault:    "default",
}

// String returns the stable name of the stage.
func (s Stage) String() string {
	if name, ok := stageNames[s]; ok {
		return name
	}
	return "unknown"
}

// New builds an Explainer from cfg. Namespace membership is materialized into
// a set up front, so later decisions never depend on the input slice order.
func New(cfg Config) *Explainer {
	e := &Explainer{
		namespaces:       sets.New[string](),
		labelFilter:      cfg.LabelFilter,
		annotationFilter: cfg.AnnotationFilter,
		domainFilter:     cfg.DomainFilter,
	}
	for _, namespace := range cfg.Namespaces {
		if namespace == v1.NamespaceAll {
			e.watchAllNamespaces = true
			return e
		}
		e.namespaces.Insert(namespace)
	}
	if len(cfg.Namespaces) == 0 {
		e.watchAllNamespaces = true
	}
	return e
}

// Explain replays the chain for candidate and returns its trace. Evaluation
// short-circuits at the first excluding stage; every later stage is recorded
// as StateSkipped. The result depends only on candidate and the explainer's
// immutable configuration, so reordering the inputs never changes a decision.
func (e *Explainer) Explain(candidate Candidate) Explanation {
	chain := make([]StageResult, 0, stageCount)
	excluded := false
	for stage := range stageCount {
		if excluded {
			chain = append(chain, StageResult{Stage: stage, State: StateSkipped})
			continue
		}
		var result StageResult
		switch stage {
		case StageNamespace:
			result = e.explainNamespace(candidate.Namespace)
		case StageLabel:
			result = explainSelector(StageLabel, e.labelFilter, candidate.Labels, "label")
		case StageAnnotation:
			result = explainSelector(StageAnnotation, e.annotationFilter, candidate.Annotations, "annotation")
		case StageDomain:
			result = e.explainDomain(candidate.DNSName)
		}
		chain = append(chain, result)
		if result.State == StateExcluded {
			excluded = true
		}
	}

	explanation := Explanation{
		DNSName:   candidate.DNSName,
		Namespace: candidate.Namespace,
		Chain:     chain,
	}
	if excluded {
		deciding := chain[firstExcluded(chain)]
		explanation.Outcome = OutcomeExcluded
		explanation.DecidedBy = deciding.Stage
		explanation.FirstRule = deciding.Rule
		return explanation
	}
	explanation.Outcome = OutcomeKept
	explanation.DecidedBy = StageDefault
	explanation.FirstRule = Rule{
		Text:     "no configured filter excluded the endpoint; retained by default allow",
		Polarity: PolarityNone,
	}
	return explanation
}

// ExplainAll explains every candidate. Output order follows the input; each
// explanation is computed independently, so shuffling the input changes
// nothing about the decisions themselves.
func (e *Explainer) ExplainAll(candidates []Candidate) []Explanation {
	explanations := make([]Explanation, 0, len(candidates))
	for _, candidate := range candidates {
		explanations = append(explanations, e.Explain(candidate))
	}
	return explanations
}

// String renders the explanation on one line for logging.
func (x Explanation) String() string {
	parts := make([]string, 0, len(x.Chain))
	for _, result := range x.Chain {
		parts = append(parts, renderStage(result))
	}
	return fmt.Sprintf("endpoint %q (namespace %q): %s by %s; chain=[%s]",
		x.DNSName, x.Namespace, x.Outcome, x.DecidedBy, strings.Join(parts, " -> "))
}

// explainNamespace evaluates the watched-namespace allow list. An empty or
// all-namespaces configuration disables the stage rather than inventing a
// matching rule.
func (e *Explainer) explainNamespace(namespace string) StageResult {
	if e.watchAllNamespaces {
		return StageResult{Stage: StageNamespace, State: StateNotConfigured}
	}
	values := sets.Sorted(e.namespaces)
	rendered := renderQuoted(values)
	if e.namespaces.Has(namespace) {
		return StageResult{
			Stage: StageNamespace,
			State: StatePassed,
			Rule: Rule{
				Text:     fmt.Sprintf("namespace %q is in the watched set (%s)", namespace, rendered),
				Polarity: PolarityPositive,
				Values:   values,
			},
		}
	}
	return StageResult{
		Stage: StageNamespace,
		State: StateExcluded,
		Rule: Rule{
			Text:     fmt.Sprintf("namespace %q is not in the watched set (%s)", namespace, rendered),
			Polarity: PolarityPositive,
			Values:   values,
		},
	}
}

// explainSelector evaluates one labels.Selector stage against values, which
// is either the object's labels or its annotations. Requirements are evaluated
// in parse order, which is fixed at selector construction and independent of
// the candidate input.
func explainSelector(stage Stage, selector labels.Selector, values map[string]string, kind string) StageResult {
	if selector == nil || selector.Empty() {
		return StageResult{Stage: stage, State: StateNotConfigured}
	}
	requirements, selectable := selector.Requirements()
	if !selectable || len(requirements) == 0 {
		return StageResult{Stage: stage, State: StateNotConfigured}
	}

	set := labels.Set(values)
	for _, requirement := range requirements {
		if requirement.Matches(set) {
			continue
		}
		return StageResult{
			Stage: stage,
			State: StateExcluded,
			Rule: Rule{
				Text:     fmt.Sprintf("%s selector requirement %q is not satisfied", kind, requirement.String()),
				Polarity: requirementPolarity(requirement.Operator()),
				Values:   requirementValues(requirement),
			},
		}
	}

	first := requirements[0]
	return StageResult{
		Stage: stage,
		State: StatePassed,
		Rule: Rule{
			Text:     fmt.Sprintf("%s selector requirement %q is satisfied", kind, first.String()),
			Polarity: requirementPolarity(first.Operator()),
			Values:   requirementValues(first),
		},
	}
}

// explainDomain delegates to endpoint.DomainFilter.ExplainMatch, which
// preserves the exact Match semantics while exposing the deciding rule and
// its polarity.
func (e *Explainer) explainDomain(dnsName string) StageResult {
	rule := e.domainFilter.ExplainMatch(dnsName)
	if !rule.Configured {
		return StageResult{Stage: StageDomain, State: StateNotConfigured}
	}
	state := StatePassed
	if !rule.Matched {
		state = StateExcluded
	}
	polarity := PolarityPositive
	if rule.Negative {
		polarity = PolarityNegative
	}
	return StageResult{
		Stage: StageDomain,
		State: state,
		Rule: Rule{
			Text:     rule.Text,
			Polarity: polarity,
			Values:   rule.Values,
		},
	}
}

// requirementPolarity classifies selector operators: NotIn, NotEquals, and
// DoesNotExist are negative exclusion conditions; everything else is positive.
func requirementPolarity(operator selection.Operator) Polarity {
	switch operator {
	case selection.NotIn, selection.NotEquals, selection.DoesNotExist:
		return PolarityNegative
	default:
		return PolarityPositive
	}
}

// requirementValues returns a sorted copy of the requirement's values, or nil
// for the valueless Exists and DoesNotExist operators.
func requirementValues(requirement labels.Requirement) []string {
	values := requirement.Values().List()
	if len(values) == 0 {
		return nil
	}
	slices.Sort(values)
	return values
}

// firstExcluded returns the index of the first StateExcluded result, or -1.
func firstExcluded(chain []StageResult) int {
	for i, result := range chain {
		if result.State == StateExcluded {
			return i
		}
	}
	return -1
}

// renderQuoted joins values with Go quoting for stable rule text.
func renderQuoted(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, fmt.Sprintf("%q", value))
	}
	return strings.Join(quoted, ", ")
}

// renderStage renders one chain entry, omitting the rule text when the stage
// was not configured or was skipped.
func renderStage(result StageResult) string {
	if result.Rule.Text == "" {
		return fmt.Sprintf("%s:%s", result.Stage, result.State)
	}
	return fmt.Sprintf("%s:%s(%s)", result.Stage, result.State, result.Rule.Text)
}
