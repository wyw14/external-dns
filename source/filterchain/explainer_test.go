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

package filterchain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/external-dns/endpoint"
)

func mustParseSelector(t *testing.T, expr string) labels.Selector {
	t.Helper()
	selector, err := labels.Parse(expr)
	require.NoError(t, err)
	return selector
}

func stageByChain(chain []StageResult, stage Stage) StageResult {
	for _, result := range chain {
		if result.Stage == stage {
			return result
		}
	}
	return StageResult{}
}

func TestExplainEmptyChainKeepsByDefault(t *testing.T) {
	explainer := New(Config{})
	candidate := Candidate{
		DNSName:   "web.example.com",
		Namespace: "default",
		Labels:    map[string]string{"app": "web"},
	}

	explanation := explainer.Explain(candidate)

	require.Len(t, explanation.Chain, 4)
	assert.Equal(t, OutcomeKept, explanation.Outcome)
	assert.Equal(t, StageDefault, explanation.DecidedBy)
	assert.Equal(t, PolarityNone, explanation.FirstRule.Polarity)
	assert.NotEmpty(t, explanation.FirstRule.Text)
	for _, result := range explanation.Chain {
		assert.Equal(t, StateNotConfigured, result.State, result.Stage.String())
		assert.Empty(t, result.Rule.Text)
	}
	assert.Contains(t, explanation.String(), "web.example.com")
}

func TestExplainNamespace(t *testing.T) {
	candidate := Candidate{DNSName: "web.example.com", Namespace: "team-b"}

	t.Run("watched namespace passes with positive rule", func(t *testing.T) {
		explainer := New(Config{Namespaces: []string{"team-a", "team-b"}})
		result := stageByChain(explainer.Explain(candidate).Chain, StageNamespace)
		assert.Equal(t, StatePassed, result.State)
		assert.Equal(t, PolarityPositive, result.Rule.Polarity)
		assert.Equal(t, []string{"team-a", "team-b"}, result.Rule.Values)
	})

	t.Run("unwatched namespace excludes and short-circuits", func(t *testing.T) {
		explainer := New(Config{
			Namespaces:  []string{"team-a"},
			LabelFilter: mustParseSelector(t, "app=web"),
		})
		explanation := explainer.Explain(candidate)
		assert.Equal(t, OutcomeExcluded, explanation.Outcome)
		assert.Equal(t, StageNamespace, explanation.DecidedBy)
		assert.Equal(t, StateExcluded, stageByChain(explanation.Chain, StageNamespace).State)
		assert.Equal(t, StateSkipped, stageByChain(explanation.Chain, StageLabel).State)
		assert.Equal(t, StateSkipped, stageByChain(explanation.Chain, StageAnnotation).State)
		assert.Equal(t, StateSkipped, stageByChain(explanation.Chain, StageDomain).State)
	})

	t.Run("empty and all-namespaces disable the stage", func(t *testing.T) {
		for _, namespaces := range [][]string{nil, {}, {v1.NamespaceAll}} {
			explainer := New(Config{Namespaces: namespaces})
			result := stageByChain(explainer.Explain(candidate).Chain, StageNamespace)
			assert.Equal(t, StateNotConfigured, result.State)
		}
	})

	t.Run("watched-set values are independent of input order", func(t *testing.T) {
		explainer := New(Config{Namespaces: []string{"team-b", "team-a"}})
		result := stageByChain(explainer.Explain(candidate).Chain, StageNamespace)
		assert.Equal(t, []string{"team-a", "team-b"}, result.Rule.Values)
	})
}

func TestExplainLabelSelector(t *testing.T) {
	candidate := Candidate{
		DNSName:   "web.example.com",
		Namespace: "default",
		Labels:    map[string]string{"app": "web", "env": "prod"},
	}

	t.Run("matching positive requirement passes", func(t *testing.T) {
		explainer := New(Config{LabelFilter: mustParseSelector(t, "app=web")})
		result := stageByChain(explainer.Explain(candidate).Chain, StageLabel)
		assert.Equal(t, StatePassed, result.State)
		assert.Equal(t, PolarityPositive, result.Rule.Polarity)
		assert.Contains(t, result.Rule.Text, "app=web")
	})

	t.Run("first failing requirement is reported in parse order", func(t *testing.T) {
		explainer := New(Config{LabelFilter: mustParseSelector(t, "app=web,env=dev")})
		explanation := explainer.Explain(candidate)
		assert.Equal(t, OutcomeExcluded, explanation.Outcome)
		assert.Equal(t, StageLabel, explanation.DecidedBy)
		assert.Equal(t, PolarityPositive, explanation.FirstRule.Polarity)
		assert.Contains(t, explanation.FirstRule.Text, "env=dev")
	})

	t.Run("firing negative requirement is a negative exclusion", func(t *testing.T) {
		explainer := New(Config{LabelFilter: mustParseSelector(t, "env notin (prod)")})
		explanation := explainer.Explain(candidate)
		assert.Equal(t, StageLabel, explanation.DecidedBy)
		assert.Equal(t, PolarityNegative, explanation.FirstRule.Polarity)
	})

	t.Run("DoesNotExist fires when key is present", func(t *testing.T) {
		explainer := New(Config{LabelFilter: mustParseSelector(t, "!dangerous")})
		candidateWithFlag := Candidate{Labels: map[string]string{"dangerous": "true"}}
		explanation := explainer.Explain(candidateWithFlag)
		assert.Equal(t, OutcomeExcluded, explanation.Outcome)
		assert.Equal(t, PolarityNegative, explanation.FirstRule.Polarity)
	})

	t.Run("passing negative requirement stays negative but passes", func(t *testing.T) {
		explainer := New(Config{LabelFilter: mustParseSelector(t, "env notin (dev)")})
		result := stageByChain(explainer.Explain(candidate).Chain, StageLabel)
		assert.Equal(t, StatePassed, result.State)
		assert.Equal(t, PolarityNegative, result.Rule.Polarity)
	})

	t.Run("nil and empty selectors disable the stage", func(t *testing.T) {
		for _, selector := range []labels.Selector{nil, labels.Everything()} {
			explainer := New(Config{LabelFilter: selector})
			result := stageByChain(explainer.Explain(candidate).Chain, StageLabel)
			assert.Equal(t, StateNotConfigured, result.State)
		}
	})

	t.Run("in-operator values are rendered sorted", func(t *testing.T) {
		explainer := New(Config{LabelFilter: mustParseSelector(t, "app in (web, api, worker)")})
		result := stageByChain(explainer.Explain(candidate).Chain, StageLabel)
		require.Equal(t, StatePassed, result.State)
		assert.Equal(t, []string{"api", "web", "worker"}, result.Rule.Values)
	})

	t.Run("numeric Gt requirement is a positive rule", func(t *testing.T) {
		explainer := New(Config{LabelFilter: mustParseSelector(t, "replicas>2")})
		small := Candidate{Labels: map[string]string{"replicas": "1"}}
		assert.Equal(t, StateExcluded, stageByChain(explainer.Explain(small).Chain, StageLabel).State)

		big := Candidate{Labels: map[string]string{"replicas": "5"}}
		result := stageByChain(explainer.Explain(big).Chain, StageLabel)
		assert.Equal(t, StatePassed, result.State)
		assert.Equal(t, PolarityPositive, result.Rule.Polarity)
		assert.Equal(t, []string{"2"}, result.Rule.Values)
	})
}

func TestExplainAnnotationSelector(t *testing.T) {
	candidate := Candidate{
		DNSName:     "web.example.com",
		Namespace:   "default",
		Labels:      map[string]string{"scheme": "internal"},
		Annotations: map[string]string{"scheme": "internet-facing"},
	}

	t.Run("selector reads annotations, not labels", func(t *testing.T) {
		explainer := New(Config{AnnotationFilter: mustParseSelector(t, "scheme=internet-facing")})
		result := stageByChain(explainer.Explain(candidate).Chain, StageAnnotation)
		assert.Equal(t, StatePassed, result.State)
	})

	t.Run("annotation mismatch excludes at the annotation stage", func(t *testing.T) {
		explainer := New(Config{
			LabelFilter:      mustParseSelector(t, "scheme=internal"),
			AnnotationFilter: mustParseSelector(t, "scheme=internal"),
		})
		explanation := explainer.Explain(candidate)
		assert.Equal(t, StageAnnotation, explanation.DecidedBy)
		assert.Equal(t, StatePassed, stageByChain(explanation.Chain, StageLabel).State)
		assert.Equal(t, StateExcluded, stageByChain(explanation.Chain, StageAnnotation).State)
	})

	t.Run("empty selector disables the stage", func(t *testing.T) {
		explainer := New(Config{AnnotationFilter: labels.Everything()})
		result := stageByChain(explainer.Explain(candidate).Chain, StageAnnotation)
		assert.Equal(t, StateNotConfigured, result.State)
	})
}

func TestExplainDomain(t *testing.T) {
	candidate := Candidate{DNSName: "host.api.example.com", Namespace: "default"}

	t.Run("include match passes with positive rule", func(t *testing.T) {
		explainer := New(Config{DomainFilter: endpoint.NewDomainFilter([]string{"example.com"})})
		result := stageByChain(explainer.Explain(candidate).Chain, StageDomain)
		assert.Equal(t, StatePassed, result.State)
		assert.Equal(t, PolarityPositive, result.Rule.Polarity)
	})

	t.Run("include miss excludes at the final stage", func(t *testing.T) {
		explainer := New(Config{DomainFilter: endpoint.NewDomainFilter([]string{"example.org"})})
		explanation := explainer.Explain(candidate)
		assert.Equal(t, StageDomain, explanation.DecidedBy)
		assert.Equal(t, OutcomeExcluded, explanation.Outcome)
	})

	t.Run("exclude hit is a negative exclusion", func(t *testing.T) {
		filter := endpoint.NewDomainFilterWithExclusions([]string{"example.com"}, []string{"api.example.com"})
		explainer := New(Config{DomainFilter: filter})
		explanation := explainer.Explain(candidate)
		assert.Equal(t, StageDomain, explanation.DecidedBy)
		assert.Equal(t, PolarityNegative, explanation.FirstRule.Polarity)
	})

	t.Run("exclude-only non-hit passes but stays distinct from empty filter", func(t *testing.T) {
		filter := endpoint.NewDomainFilterWithExclusions(nil, []string{"internal.example.com"})
		explainer := New(Config{DomainFilter: filter})
		result := stageByChain(explainer.Explain(candidate).Chain, StageDomain)
		assert.Equal(t, StatePassed, result.State)
		assert.Equal(t, PolarityNegative, result.Rule.Polarity)

		emptyResult := stageByChain(New(Config{}).Explain(candidate).Chain, StageDomain)
		assert.Equal(t, StateNotConfigured, emptyResult.State)
	})

	t.Run("nil domain filter disables the stage", func(t *testing.T) {
		explainer := New(Config{})
		result := stageByChain(explainer.Explain(candidate).Chain, StageDomain)
		assert.Equal(t, StateNotConfigured, result.State)
	})
}

func TestExplainStagePriority(t *testing.T) {
	candidate := Candidate{
		DNSName:     "host.internal.example.com",
		Namespace:   "excluded-ns",
		Labels:      map[string]string{"env": "dev"},
		Annotations: map[string]string{"owner": "other"},
	}
	config := Config{
		Namespaces:       []string{"watched-ns"},
		LabelFilter:      mustParseSelector(t, "env=prod"),
		AnnotationFilter: mustParseSelector(t, "owner=team"),
		DomainFilter:     endpoint.NewDomainFilter([]string{"example.org"}),
	}

	explanation := New(config).Explain(candidate)
	assert.Equal(t, StageNamespace, explanation.DecidedBy)
	assert.Equal(t, StateExcluded, stageByChain(explanation.Chain, StageNamespace).State)
	assert.Equal(t, StateSkipped, stageByChain(explanation.Chain, StageLabel).State)
	assert.Equal(t, StateSkipped, stageByChain(explanation.Chain, StageAnnotation).State)
	assert.Equal(t, StateSkipped, stageByChain(explanation.Chain, StageDomain).State)

	// With namespace admitted, label must outrank annotation and domain.
	config.Namespaces = []string{"excluded-ns"}
	explanation = New(config).Explain(candidate)
	assert.Equal(t, StageLabel, explanation.DecidedBy)
	assert.Equal(t, StatePassed, stageByChain(explanation.Chain, StageNamespace).State)
	assert.Equal(t, StateExcluded, stageByChain(explanation.Chain, StageLabel).State)
	assert.Equal(t, StateSkipped, stageByChain(explanation.Chain, StageAnnotation).State)

	// With label admitted too, annotation outranks domain.
	config.LabelFilter = mustParseSelector(t, "env=dev")
	explanation = New(config).Explain(candidate)
	assert.Equal(t, StageAnnotation, explanation.DecidedBy)
	assert.Equal(t, StateSkipped, stageByChain(explanation.Chain, StageDomain).State)

	// Only the domain rule left to fail.
	config.AnnotationFilter = mustParseSelector(t, "owner=other")
	explanation = New(config).Explain(candidate)
	assert.Equal(t, StageDomain, explanation.DecidedBy)
	assert.Equal(t, OutcomeExcluded, explanation.Outcome)

	// All filters pass: retained by default allow.
	config.DomainFilter = endpoint.NewDomainFilter([]string{"example.com"})
	explanation = New(config).Explain(candidate)
	assert.Equal(t, OutcomeKept, explanation.Outcome)
	assert.Equal(t, StageDefault, explanation.DecidedBy)
}

func TestExplainIsDeterministicAcrossInputOrder(t *testing.T) {
	candidates := []Candidate{
		{DNSName: "a.example.com", Namespace: "team-a", Labels: map[string]string{"app": "a"}},
		{DNSName: "b.example.com", Namespace: "team-b", Labels: map[string]string{"app": "b"}},
		{DNSName: "c.example.org", Namespace: "team-a", Labels: map[string]string{"app": "c"}},
		{DNSName: "d.example.com", Namespace: "team-c", Labels: map[string]string{"app": "d"}},
	}
	config := Config{
		Namespaces:  []string{"team-b", "team-a", "team-a"},
		LabelFilter: mustParseSelector(t, "app"),
		DomainFilter: endpoint.NewDomainFilterWithExclusions(
			[]string{"example.com", "example.org"},
			[]string{"c.example.org"},
		),
	}

	explainer := New(config)
	first := explainer.ExplainAll(candidates)

	shuffled := []Candidate{candidates[3], candidates[1], candidates[3], candidates[0], candidates[2]}
	again := New(config).ExplainAll(shuffled)

	byName := func(explanations []Explanation) map[string]Explanation {
		indexed := make(map[string]Explanation, len(explanations))
		for _, explanation := range explanations {
			indexed[explanation.DNSName] = explanation
		}
		return indexed
	}

	firstByName := byName(first)
	for _, explanation := range again {
		expected, ok := firstByName[explanation.DNSName]
		require.True(t, ok)
		assert.Equal(t, expected, explanation)
	}

	// Repeating the same explanation must be stable as well.
	assert.Equal(t, first[0], explainer.Explain(candidates[0]))
}

func TestExplainAgreesWithUnderlyingFilters(t *testing.T) {
	labelSelector := mustParseSelector(t, "app in (web, api),env!=dev")
	annotationSelector := mustParseSelector(t, "owner=team")
	domainFilter := endpoint.NewDomainFilterWithExclusions(
		[]string{"example.com"},
		[]string{"internal.example.com"},
	)
	explainer := New(Config{
		Namespaces:       []string{"team-a", "team-b"},
		LabelFilter:      labelSelector,
		AnnotationFilter: annotationSelector,
		DomainFilter:     domainFilter,
	})

	candidates := []Candidate{
		{
			DNSName:     "web.example.com",
			Namespace:   "team-a",
			Labels:      map[string]string{"app": "web", "env": "prod"},
			Annotations: map[string]string{"owner": "team"},
		},
		{
			DNSName:     "api.example.com",
			Namespace:   "team-c",
			Labels:      map[string]string{"app": "api", "env": "prod"},
			Annotations: map[string]string{"owner": "team"},
		},
		{
			DNSName:     "web.example.com",
			Namespace:   "team-b",
			Labels:      map[string]string{"app": "web", "env": "dev"},
			Annotations: map[string]string{"owner": "team"},
		},
		{
			DNSName:     "web.example.net",
			Namespace:   "team-a",
			Labels:      map[string]string{"app": "web", "env": "prod"},
			Annotations: map[string]string{"owner": "team"},
		},
		{
			DNSName:     "internal.example.com",
			Namespace:   "team-a",
			Labels:      map[string]string{"app": "web", "env": "prod"},
			Annotations: map[string]string{"owner": "team"},
		},
		{
			DNSName:     "web.example.com",
			Namespace:   "team-a",
			Labels:      map[string]string{"app": "web", "env": "prod"},
			Annotations: map[string]string{"owner": "someone-else"},
		},
	}

	for _, candidate := range candidates {
		expectedKept := true
		switch {
		case candidate.Namespace != "team-a" && candidate.Namespace != "team-b":
			expectedKept = false
		case !labelSelector.Matches(labels.Set(candidate.Labels)):
			expectedKept = false
		case !annotationSelector.Matches(labels.Set(candidate.Annotations)):
			expectedKept = false
		case !domainFilter.Match(candidate.DNSName):
			expectedKept = false
		}

		explanation := explainer.Explain(candidate)
		if expectedKept {
			assert.Equal(t, OutcomeKept, explanation.Outcome, candidate.DNSName)
		} else {
			assert.Equal(t, OutcomeExcluded, explanation.Outcome, candidate.DNSName)
		}
	}
}

func TestStageString(t *testing.T) {
	assert.Equal(t, "namespace", StageNamespace.String())
	assert.Equal(t, "label", StageLabel.String())
	assert.Equal(t, "annotation", StageAnnotation.String())
	assert.Equal(t, "domain", StageDomain.String())
	assert.Equal(t, "default", StageDefault.String())
}
