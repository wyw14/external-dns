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

package plan

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/external-dns/endpoint"
)

func TestNormalizeTarget(t *testing.T) {
	for _, tc := range []struct {
		name       string
		recordType string
		target     string
		canonical  string
		port       uint16
		weight     uint16
		hasWeight  bool
	}{
		{
			name:       "IPv4 canonical",
			recordType: endpoint.RecordTypeA,
			target:     "1.2.3.4",
			canonical:  "1.2.3.4",
		},
		{
			name:       "IPv6 uppercase and compression",
			recordType: endpoint.RecordTypeAAAA,
			target:     "2001:DB8:0:0:0:0:0:1",
			canonical:  "2001:db8::1",
		},
		{
			name:       "IPv6 link-local keeps zone",
			recordType: endpoint.RecordTypeAAAA,
			target:     "FE80::1%eth0",
			canonical:  "fe80::1%eth0",
		},
		{
			name:       "CNAME trailing dot and case",
			recordType: endpoint.RecordTypeCNAME,
			target:     "Foo.Example.com.",
			canonical:  "foo.example.com",
		},
		{
			name:       "DNAME trailing dot and case",
			recordType: endpoint.RecordTypeDNAME,
			target:     "Bar.Example.COM.",
			canonical:  "bar.example.com",
		},
		{
			name:       "PTR hostname",
			recordType: endpoint.RecordTypePTR,
			target:     "Host.Example.com.",
			canonical:  "host.example.com",
		},
		{
			name:       "NS hostname",
			recordType: endpoint.RecordTypeNS,
			target:     "NS1.Example.COM",
			canonical:  "ns1.example.com",
		},
		{
			name:       "MX preference and host",
			recordType: endpoint.RecordTypeMX,
			target:     "10 Mail.Example.com.",
			canonical:  "10 mail.example.com",
		},
		{
			name:       "null MX keeps the root dot",
			recordType: endpoint.RecordTypeMX,
			target:     "0 .",
			canonical:  "0 .",
		},
		{
			name:       "SRV parses port and weight",
			recordType: endpoint.RecordTypeSRV,
			target:     "10 20 5060 SIP.Example.com.",
			canonical:  "10 20 5060 sip.example.com.",
			port:       5060,
			weight:     20,
			hasWeight:  true,
		},
		{
			name:       "TLSA hex is lowercased and compacted",
			recordType: endpoint.RecordTypeTLSA,
			target:     "3 1 0 AA:BB CC",
			canonical:  "3 1 0 aabbcc",
		},
		{
			name:       "TXT keeps case and dots",
			recordType: endpoint.RecordTypeTXT,
			target:     "v=spf1 include:Example.COM ~all.",
			canonical:  "v=spf1 include:Example.COM ~all.",
		},
		{
			name:       "unknown type keeps exact text",
			recordType: "X-UNKNOWN",
			target:     "Case-Sensitive.Value.",
			canonical:  "Case-Sensitive.Value.",
		},
		{
			name:       "invalid SRV falls back to trimmed raw text",
			recordType: endpoint.RecordTypeSRV,
			target:     "  not-an-srv  ",
			canonical:  "not-an-srv",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeTarget(tc.recordType, tc.target)
			assert.Equal(t, tc.canonical, got.Canonical)
			assert.Equal(t, tc.target, got.Raw, "raw target must be preserved untouched")
			assert.Equal(t, tc.port, got.Port)
			assert.Equal(t, tc.weight, got.Weight)
			assert.Equal(t, tc.hasWeight, got.HasWeight)
		})
	}
}

func TestNormalizeTargetNAPTRCaseSensitivity(t *testing.T) {
	// Regexp content is case-sensitive: different regexp case must not collapse.
	caseSensitive := NormalizeTarget(endpoint.RecordTypeNAPTR, `100 50 "s" "SIP+D2U" "!^.*$!sip:info@Example.com!" _sip._udp.example.com.`)
	same := NormalizeTarget(endpoint.RecordTypeNAPTR, `100 50 "s" "SIP+D2U" "!^.*$!sip:info@Example.com!" _sip._udp.example.com.`)
	other := NormalizeTarget(endpoint.RecordTypeNAPTR, `100 50 "s" "SIP+D2U" "!^.*$!sip:INFO@example.com!" _sip._udp.example.com.`)

	assert.Equal(t, caseSensitive.Canonical, same.Canonical)
	assert.NotEqual(t, caseSensitive.Canonical, other.Canonical)
}

func TestPlanTargetsEquivalent(t *testing.T) {
	desired := []*endpoint.Endpoint{
		{
			DNSName:    "WWW.Example.com",
			RecordType: endpoint.RecordTypeAAAA,
			Targets:    endpoint.Targets{"2001:DB8::1", "2001:db8:0:0:0:0:0:1"},
		},
		{
			DNSName:    "www.example.com.",
			RecordType: endpoint.RecordTypeAAAA,
			Targets:    endpoint.Targets{"2001:db8::1"},
		},
		{
			DNSName:    "alias.example.com",
			RecordType: endpoint.RecordTypeCNAME,
			Targets:    endpoint.Targets{"Foo.Example.com."},
		},
		{
			DNSName:    "alias.example.com",
			RecordType: endpoint.RecordTypeCNAME,
			Targets:    endpoint.Targets{"foo.example.com"},
		},
	}

	plan := PlanTargets(nil, desired, DefaultTargetPolicy())
	require.Len(t, plan.Groups, 2)

	aaaa := plan.Group("www.example.com", endpoint.RecordTypeAAAA, "")
	require.NotNil(t, aaaa)
	assert.Equal(t, []string{"2001:db8::1"}, aaaa.CommittableTargets())
	assert.Len(t, aaaa.Committable, 1)

	var classes []TargetClass
	for _, target := range aaaa.Targets {
		classes = append(classes, target.Class)
	}
	assert.Contains(t, classes, TargetEquivalent)
	assert.NotContains(t, classes, TargetIncompatible)

	cname := plan.Group("ALIAS.Example.com.", endpoint.RecordTypeCNAME, "")
	require.NotNil(t, cname)
	assert.Equal(t, []string{"foo.example.com"}, cname.CommittableTargets())
	assert.Equal(t, TargetEquivalent, cname.Targets[1].Class)
	assert.Equal(t, reasonDuplicate, cname.Targets[1].Reason)
}

func TestPlanTargetsSingleTargetConflictIsDeterministic(t *testing.T) {
	first := []*endpoint.Endpoint{
		{
			DNSName:    "svc.example.com",
			RecordType: endpoint.RecordTypeCNAME,
			Targets:    endpoint.Targets{"zed.example.com"},
		},
		{
			DNSName:    "svc.example.com",
			RecordType: endpoint.RecordTypeCNAME,
			Targets:    endpoint.Targets{"alpha.example.com"},
		},
	}
	reversed := []*endpoint.Endpoint{first[1], first[0]}

	for _, desired := range [][]*endpoint.Endpoint{first, reversed} {
		plan := PlanTargets(nil, desired, DefaultTargetPolicy())
		group := plan.Group("svc.example.com", endpoint.RecordTypeCNAME, "")
		require.NotNil(t, group)
		assert.Equal(t, []string{"alpha.example.com"}, group.CommittableTargets(),
			"the smallest canonical target wins regardless of input order")

		classes := map[TargetClass]int{}
		for _, target := range group.Targets {
			classes[target.Class]++
		}
		assert.Equal(t, 1, classes[TargetCommittable])
		assert.Equal(t, 1, classes[TargetIncompatible])

		incompatible := slices.IndexFunc(group.Targets, func(t *PlannedTarget) bool {
			return t.Class == TargetIncompatible
		})
		require.GreaterOrEqual(t, incompatible, 0)
		assert.Equal(t, reasonSingleTarget, group.Targets[incompatible].Reason)
	}

	// A records accept multiple distinct targets.
	multiA := PlanTargets(nil, []*endpoint.Endpoint{
		{
			DNSName:    "multi.example.com",
			RecordType: endpoint.RecordTypeA,
			Targets:    endpoint.Targets{"10.0.0.2", "10.0.0.1"},
		},
	}, DefaultTargetPolicy())
	group := multiA.Group("multi.example.com", endpoint.RecordTypeA, "")
	require.NotNil(t, group)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, group.CommittableTargets())
}

func TestPlanTargetsExclusiveNameConflict(t *testing.T) {
	desired := []*endpoint.Endpoint{
		{
			DNSName:    "mix.example.com",
			RecordType: endpoint.RecordTypeCNAME,
			Targets:    endpoint.Targets{"lb.example.com"},
		},
		{
			DNSName:    "mix.example.com",
			RecordType: endpoint.RecordTypeA,
			Targets:    endpoint.Targets{"10.0.0.1"},
		},
	}

	plan := PlanTargets(nil, desired, DefaultTargetPolicy())
	cname := plan.Group("mix.example.com", endpoint.RecordTypeCNAME, "")
	require.NotNil(t, cname)
	assert.Empty(t, cname.Committable)
	assert.Equal(t, TargetIncompatible, cname.Targets[0].Class)
	assert.Equal(t, reasonExclusiveType, cname.Targets[0].Reason)

	a := plan.Group("mix.example.com", endpoint.RecordTypeA, "")
	require.NotNil(t, a)
	assert.Equal(t, []string{"10.0.0.1"}, a.CommittableTargets())

	// Set identifiers separate record sets: no cross-identifier conflict.
	weighted := PlanTargets(nil, []*endpoint.Endpoint{
		{
			DNSName:       "mix.example.com",
			RecordType:    endpoint.RecordTypeCNAME,
			SetIdentifier: "set-a",
			Targets:       endpoint.Targets{"lb.example.com"},
		},
		{
			DNSName:       "mix.example.com",
			RecordType:    endpoint.RecordTypeA,
			SetIdentifier: "set-b",
			Targets:       endpoint.Targets{"10.0.0.1"},
		},
	}, DefaultTargetPolicy())
	require.Len(t, weighted.Groups, 2)
	for _, group := range weighted.Groups {
		assert.Len(t, group.Committable, 1)
	}
}

func TestPlanTargetsSRVPortAndWeight(t *testing.T) {
	desired := []*endpoint.Endpoint{
		{
			DNSName:    "_sip._tcp.example.com",
			RecordType: endpoint.RecordTypeSRV,
			Targets: endpoint.Targets{
				"10 10 5060 sip.example.com.",
				"10 20 5060 SIP.example.com.", // same identity, only weight differs
				"10 10 5061 sip.example.com.", // different port, distinct identity
				"10 10 5060 sip.example.com.", // exact duplicate
			},
		},
	}

	plan := PlanTargets(nil, desired, DefaultTargetPolicy())
	group := plan.Group("_sip._tcp.example.com", endpoint.RecordTypeSRV, "")
	require.NotNil(t, group)
	assert.Equal(t, []string{
		"10 10 5060 sip.example.com.",
		"10 10 5061 sip.example.com.",
	}, group.CommittableTargets())

	classes := map[TargetClass]int{}
	for _, target := range group.Targets {
		classes[target.Class]++
	}
	assert.Equal(t, 2, classes[TargetCommittable])
	assert.Equal(t, 1, classes[TargetWeightOnly])
	assert.Equal(t, 1, classes[TargetEquivalent])

	weightOnly := slices.IndexFunc(group.Targets, func(t *PlannedTarget) bool {
		return t.Class == TargetWeightOnly
	})
	require.GreaterOrEqual(t, weightOnly, 0)
	assert.Equal(t, reasonWeightDiffers, group.Targets[weightOnly].Reason)
	assert.Equal(t, uint16(5060), group.Targets[weightOnly].Port)
}

func TestPlanTargetsProviderWeightProperty(t *testing.T) {
	desired := []*endpoint.Endpoint{
		endpoint.NewEndpoint("w.example.com", endpoint.RecordTypeA, "10.0.0.1").
			WithProviderSpecific(AWSWeightProperty, "10"),
		endpoint.NewEndpoint("w.example.com", endpoint.RecordTypeA, "10.0.0.1").
			WithProviderSpecific(AWSWeightProperty, "20"),
	}

	plan := PlanTargets(nil, desired, DefaultTargetPolicy())
	group := plan.Group("w.example.com", endpoint.RecordTypeA, "")
	require.NotNil(t, group)
	assert.Len(t, group.Committable, 1)
	assert.Equal(t, TargetWeightOnly, group.Targets[1].Class)
	assert.True(t, group.Targets[1].HasWeight)
	assert.Equal(t, uint16(20), group.Targets[1].Weight)

	// Without weight properties configured, the same pair is a plain duplicate.
	policy := DefaultTargetPolicy()
	policy.WeightProperties = nil
	plain := PlanTargets(nil, desired, policy)
	plainGroup := plain.Group("w.example.com", endpoint.RecordTypeA, "")
	require.NotNil(t, plainGroup)
	assert.Equal(t, TargetEquivalent, plainGroup.Targets[1].Class)
	assert.False(t, plainGroup.Targets[1].HasWeight)
}

func TestPlanTargetsCurrentWeightOnlyChange(t *testing.T) {
	current := []*endpoint.Endpoint{
		endpoint.NewEndpoint("w.example.com", endpoint.RecordTypeA, "10.0.0.1").
			WithProviderSpecific(AWSWeightProperty, "10"),
	}
	desired := []*endpoint.Endpoint{
		endpoint.NewEndpoint("w.example.com", endpoint.RecordTypeA, "10.0.0.1").
			WithProviderSpecific(AWSWeightProperty, "20"),
	}

	plan := PlanTargets(current, desired, DefaultTargetPolicy())
	group := plan.Group("w.example.com", endpoint.RecordTypeA, "")
	require.NotNil(t, group)
	require.Len(t, group.Committable, 1)
	assert.Equal(t, TargetWeightOnly, group.Committable[0].Class)
	assert.Contains(t, group.Committable[0].Reason, "10")
	assert.Contains(t, group.Committable[0].Reason, "20")

	// Equal weights: no change at all.
	inSync := PlanTargets(current, current, DefaultTargetPolicy())
	inSyncGroup := inSync.Group("w.example.com", endpoint.RecordTypeA, "")
	require.NotNil(t, inSyncGroup)
	assert.Equal(t, TargetCommittable, inSyncGroup.Committable[0].Class)
	assert.Empty(t, inSyncGroup.Committable[0].Reason)
}

func TestPlanTargetsDoesNotMutateInput(t *testing.T) {
	desired := []*endpoint.Endpoint{
		{
			DNSName:    "WWW.Example.com",
			RecordType: endpoint.RecordTypeAAAA,
			Targets:    endpoint.Targets{"2001:DB8::1", "2001:db8::1"},
			ProviderSpecific: endpoint.ProviderSpecific{
				{Name: AWSWeightProperty, Value: "10"},
			},
		},
	}
	snapshot := desired[0].DeepCopy()

	_ = PlanTargets(nil, desired, DefaultTargetPolicy())

	assert.Equal(t, snapshot.DNSName, desired[0].DNSName)
	assert.Equal(t, endpoint.Targets{"2001:DB8::1", "2001:db8::1"}, desired[0].Targets,
		"target slice content and order must be untouched")
	assert.True(t, slices.EqualFunc(snapshot.ProviderSpecific, desired[0].ProviderSpecific,
		func(a, b endpoint.ProviderSpecificProperty) bool { return a == b }))
}

func TestPlanTargetsOrderingAndEmptyInputs(t *testing.T) {
	desired := []*endpoint.Endpoint{
		nil,
		{DNSName: "zeta.example.com", RecordType: endpoint.RecordTypeA}, // no targets
		{
			DNSName:    "zeta.example.com",
			RecordType: endpoint.RecordTypeA,
			Targets:    endpoint.Targets{"10.0.0.2", "10.0.0.1"},
		},
		{
			DNSName:    "alpha.example.com",
			RecordType: endpoint.RecordTypeA,
			Targets:    endpoint.Targets{"10.0.0.9"},
		},
	}

	plan := PlanTargets(nil, desired, DefaultTargetPolicy())
	require.Len(t, plan.Groups, 2)
	assert.Equal(t, "alpha.example.com", plan.Groups[0].DNSName)
	assert.Equal(t, "zeta.example.com", plan.Groups[1].DNSName)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, plan.Groups[1].CommittableTargets())

	// Empty input yields an empty, non-nil plan.
	empty := PlanTargets(nil, nil, DefaultTargetPolicy())
	require.NotNil(t, empty)
	assert.Empty(t, empty.Groups)
	assert.Nil(t, empty.Group("missing.example.com", endpoint.RecordTypeA, ""))

	// A zero policy imposes neither single-target nor exclusive-name rules.
	permissive := PlanTargets(nil, []*endpoint.Endpoint{
		{
			DNSName:    "free.example.com",
			RecordType: endpoint.RecordTypeCNAME,
			Targets:    endpoint.Targets{"one.example.com", "two.example.com"},
		},
	}, TargetPolicy{})
	group := permissive.Group("free.example.com", endpoint.RecordTypeCNAME, "")
	require.NotNil(t, group)
	assert.Len(t, group.Committable, 2)
}
