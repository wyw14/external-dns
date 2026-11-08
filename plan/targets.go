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
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/internal/idna"
	"sigs.k8s.io/external-dns/internal/sets"
)

// AWSWeightProperty is the provider-specific property carrying the weight of a
// weighted Route53 record set.
const AWSWeightProperty = "aws/weight"

// TargetClass labels the role a normalized target plays inside a TargetPlan.
type TargetClass string

const (
	// TargetCommittable marks a unique target with no conflict. It belongs to
	// the set that can be submitted to a provider.
	TargetCommittable TargetClass = "Committable"
	// TargetEquivalent marks a target whose normalized identity is already
	// represented: another IPv6 spelling, different case, a trailing dot, or a
	// duplicate.
	TargetEquivalent TargetClass = "Equivalent"
	// TargetIncompatible marks a target that cannot coexist with another one,
	// either because its record type accepts a single target or because an
	// exclusive record type (RFC 1034 CNAME) shares the DNS name.
	TargetIncompatible TargetClass = "Incompatible"
	// TargetWeightOnly marks a target whose identity matches another one but
	// whose weight differs. Nothing but the weight changes.
	TargetWeightOnly TargetClass = "WeightOnly"
)

// Machine-readable reasons attached to PlannedTarget.Reason.
const (
	reasonDuplicate     = "duplicate target"
	reasonSingleTarget  = "record type allows at most one target"
	reasonExclusiveType = "record type cannot coexist with another record type at the same DNS name"
	reasonWeightDiffers = "weight differs for an equivalent target"
)

// TargetPolicy describes the DNS rules a provider honors when several targets
// land on the same record. It is plain configuration: PlanTargets never calls
// a provider; the caller translates provider capabilities into a policy once.
type TargetPolicy struct {
	// SingleTargetTypes lists record types whose record accepts at most one
	// target. A second, distinct target in such a group is TargetIncompatible.
	SingleTargetTypes []string
	// ExclusiveNameTypes lists record types that cannot share a DNS name with
	// any other record type (RFC 1034 section 3.6.2 for CNAME). When an
	// exclusive type and another type are both desired for the same name and
	// set identifier, the exclusive type's targets are TargetIncompatible,
	// matching the planner's preference for address records.
	ExclusiveNameTypes []string
	// WeightProperties names provider-specific properties that carry a
	// numeric target weight for non-SRV records (e.g. "aws/weight").
	WeightProperties []string
}

// DefaultTargetPolicy returns the policy implied by the DNS rules external-dns
// assumes regardless of provider: CNAME and DNAME carry a single target,
// CNAME is exclusive at a name, and weighted record sets publish their weight
// through the "aws/weight" property.
func DefaultTargetPolicy() TargetPolicy {
	return TargetPolicy{
		SingleTargetTypes:  []string{endpoint.RecordTypeCNAME, endpoint.RecordTypeDNAME},
		ExclusiveNameTypes: []string{endpoint.RecordTypeCNAME},
		WeightProperties:   []string{AWSWeightProperty},
	}
}

// NormalizedTarget is the canonical view of one endpoint target.
type NormalizedTarget struct {
	// RecordType the target belongs to.
	RecordType string
	// Raw is the target text as it appeared on the input endpoint, untouched.
	Raw string
	// Canonical is the deterministic spelling used for ordering and output.
	Canonical string
	// Identity is the equality spelling. It deliberately excludes the weight so
	// that an SRV target changing only its weight keeps the same identity; for
	// every other type it equals Canonical.
	Identity string
	// Port is the SRV port; zero for every other record type.
	Port uint16
	// Weight is the SRV weight or a provider-specific weight property.
	Weight uint16
	// HasWeight reports whether Weight was explicitly set.
	HasWeight bool
}

// NormalizeTarget canonicalizes a single target of recordType without touching
// the input. IP targets become their netip canonical form, so IPv6 spelling,
// compression and case stop mattering; hostname targets are lowercased and
// lose a redundant trailing dot; structured targets (SRV, MX, TLSA, NAPTR) are
// rendered through their endpoint package parsers. TXT text is case-sensitive
// and stays untouched.
func NormalizeTarget(recordType, target string) NormalizedTarget {
	nt := NormalizedTarget{RecordType: recordType, Raw: target}
	switch recordType {
	case endpoint.RecordTypeA, endpoint.RecordTypeAAAA:
		if addr, err := netip.ParseAddr(strings.TrimSpace(target)); err == nil {
			nt.Canonical = addr.String()
			break
		}
		nt.Canonical = canonicalHostname(target)
	case endpoint.RecordTypeCNAME, endpoint.RecordTypeDNAME, endpoint.RecordTypePTR, endpoint.RecordTypeNS:
		nt.Canonical = canonicalHostname(target)
	case endpoint.RecordTypeMX:
		nt.Canonical = normalizeMX(target)
	case endpoint.RecordTypeSRV:
		return normalizeSRV(target)
	case endpoint.RecordTypeTLSA:
		nt.Canonical = normalizeTLSA(target)
	case endpoint.RecordTypeNAPTR:
		nt.Canonical = normalizeNAPTR(target)
	default: // TXT and unknown types keep their exact, case-sensitive text
		nt.Canonical = target
	}
	nt.Identity = nt.Canonical
	return nt
}

// TargetKey is the equality identity of a target. Two targets with the same
// key are equivalent regardless of raw spelling. Weight is intentionally
// excluded: a changed weight alone must not produce a new identity.
type TargetKey struct {
	DNSName       string
	RecordType    string
	SetIdentifier string
	Target        string
	Port          uint16
}

// PlannedTarget pairs a normalized target with its classification.
type PlannedTarget struct {
	Key       TargetKey
	Raw       string
	Canonical string
	Port      uint16
	Weight    uint16
	HasWeight bool
	Class     TargetClass
	// Reason explains every classification except TargetCommittable.
	Reason string
	// Source is the endpoint the target came from. It is read-only evidence;
	// the planner never mutates it.
	Source *endpoint.Endpoint
}

// TargetGroup gathers the planned targets of one DNS name, record type and
// set identifier.
type TargetGroup struct {
	DNSName       string
	RecordType    string
	SetIdentifier string
	// Targets holds every desired target occurrence in deterministic order.
	Targets []*PlannedTarget
	// Committable holds the unique, conflict-free targets in canonical order;
	// this is the set that can be submitted to the provider.
	Committable []*PlannedTarget
}

// CommittableTargets returns the canonical target strings of the group's
// committable set.
func (g *TargetGroup) CommittableTargets() []string {
	result := make([]string, 0, len(g.Committable))
	for _, t := range g.Committable {
		result = append(result, t.Canonical)
	}
	return result
}

// TargetPlan is the provider-independent result of PlanTargets.
type TargetPlan struct {
	// Groups is ordered by DNS name, set identifier and record type.
	Groups []*TargetGroup
}

// Group returns the group for a DNS name, record type and set identifier, or
// nil when no desired target matches.
func (p *TargetPlan) Group(dnsName, recordType, setIdentifier string) *TargetGroup {
	want := TargetKey{
		DNSName:       strings.TrimSuffix(idna.NormalizeDNSName(dnsName), "."),
		RecordType:    recordType,
		SetIdentifier: setIdentifier,
	}
	for _, g := range p.Groups {
		if g.DNSName == want.DNSName && g.RecordType == want.RecordType && g.SetIdentifier == want.SetIdentifier {
			return g
		}
	}
	return nil
}

// PlanTargets normalizes the targets of desired and returns the committable
// target set with equivalence, incompatibility and weight-only annotations.
// current, when provided, supplies the weights records currently carry, so a
// desired target that differs only in weight is TargetWeightOnly.
//
// PlanTargets is pure: it performs no I/O, never calls a DNS provider and
// never mutates current or desired. All output ordering is deterministic.
func PlanTargets(current, desired []*endpoint.Endpoint, policy TargetPolicy) *TargetPlan {
	b := targetPlanBuilder{
		policy:         policy,
		single:         sets.New(policy.SingleTargetTypes...),
		exclusive:      sets.New(policy.ExclusiveNameTypes...),
		groups:         map[groupKey]*TargetGroup{},
		seen:           map[groupKey]map[TargetKey]*PlannedTarget{},
		currentWeights: map[groupKey]map[TargetKey]NormalizedTarget{},
	}
	b.addCurrent(current)
	for _, ep := range desired {
		b.addDesired(ep)
	}
	return b.build()
}

// groupKey identifies a TargetGroup. The DNS name uses the idna profile so
// names differing only by case or a trailing dot land in the same group.
type groupKey struct {
	dnsName       string
	recordType    string
	setIdentifier string
}

type targetPlanBuilder struct {
	policy         TargetPolicy
	single         sets.Set[string]
	exclusive      sets.Set[string]
	order          []groupKey
	groups         map[groupKey]*TargetGroup
	seen           map[groupKey]map[TargetKey]*PlannedTarget
	currentWeights map[groupKey]map[TargetKey]NormalizedTarget
}

func (b *targetPlanBuilder) addCurrent(endpoints []*endpoint.Endpoint) {
	for _, ep := range endpoints {
		if ep == nil || len(ep.Targets) == 0 {
			continue
		}
		gk := b.keyOf(ep)
		if b.currentWeights[gk] == nil {
			b.currentWeights[gk] = map[TargetKey]NormalizedTarget{}
		}
		for _, raw := range ep.Targets {
			nt := b.normalize(ep, raw)
			b.currentWeights[gk][b.identityOf(ep, nt)] = nt
		}
	}
}

func (b *targetPlanBuilder) addDesired(ep *endpoint.Endpoint) {
	if ep == nil || len(ep.Targets) == 0 {
		return
	}
	gk := b.keyOf(ep)
	group, ok := b.groups[gk]
	if !ok {
		group = &TargetGroup{
			DNSName:       strings.TrimSuffix(gk.dnsName, "."),
			RecordType:    gk.recordType,
			SetIdentifier: gk.setIdentifier,
		}
		b.groups[gk] = group
		b.seen[gk] = map[TargetKey]*PlannedTarget{}
		b.order = append(b.order, gk)
	}

	for _, raw := range ep.Targets {
		nt := b.normalize(ep, raw)
		key := b.identityOf(ep, nt)
		planned := &PlannedTarget{
			Key:       key,
			Raw:       nt.Raw,
			Canonical: nt.Canonical,
			Port:      nt.Port,
			Weight:    nt.Weight,
			HasWeight: nt.HasWeight,
			Class:     TargetCommittable,
			Source:    ep,
		}
		if first, dup := b.seen[gk][key]; dup {
			planned.Class = TargetEquivalent
			planned.Reason = reasonDuplicate
			if first.HasWeight != nt.HasWeight || first.Weight != nt.Weight {
				planned.Class = TargetWeightOnly
				planned.Reason = reasonWeightDiffers
			}
		} else {
			b.seen[gk][key] = planned
		}
		group.Targets = append(group.Targets, planned)
	}
}

func (b *targetPlanBuilder) build() *TargetPlan {
	b.markSingleTargetConflicts()
	b.markExclusiveNameConflicts()
	b.markCurrentWeightChanges()

	for _, gk := range b.order {
		group := b.groups[gk]
		slices.SortFunc(group.Targets, comparePlannedTarget)
		group.Committable = b.committable(group)
	}

	groups := make([]*TargetGroup, 0, len(b.order))
	for _, gk := range b.sortedGroupKeys() {
		groups = append(groups, b.groups[gk])
	}
	return &TargetPlan{Groups: groups}
}

// markSingleTargetConflicts keeps one deterministic winner for single-target
// record types and marks every other distinct target incompatible.
func (b *targetPlanBuilder) markSingleTargetConflicts() {
	for gk, representatives := range b.seen {
		if !b.single.Has(gk.recordType) || len(representatives) <= 1 {
			continue
		}
		keys := make([]TargetKey, 0, len(representatives))
		for key := range representatives {
			keys = append(keys, key)
		}
		slices.SortFunc(keys, compareTargetKey)
		for _, key := range keys[1:] {
			representatives[key].Class = TargetIncompatible
			representatives[key].Reason = reasonSingleTarget
		}
	}
}

// markExclusiveNameConflicts flags exclusive record types (e.g. CNAME) that
// share a DNS name and set identifier with another type.
func (b *targetPlanBuilder) markExclusiveNameConflicts() {
	clusterTypes := map[string]sets.Set[string]{}
	for _, gk := range b.order {
		nameKey := gk.dnsName + "\x00" + gk.setIdentifier
		if clusterTypes[nameKey] == nil {
			clusterTypes[nameKey] = sets.New(gk.recordType)
		} else {
			clusterTypes[nameKey].Insert(gk.recordType)
		}
	}

	for _, gk := range b.order {
		nameKey := gk.dnsName + "\x00" + gk.setIdentifier
		if !b.exclusive.Has(gk.recordType) || len(clusterTypes[nameKey]) <= 1 {
			continue
		}
		for _, t := range b.groups[gk].Targets {
			t.Class = TargetIncompatible
			t.Reason = reasonExclusiveType
		}
	}
}

// markCurrentWeightChanges reclassifies a committable desired target as
// weight-only when the same identity currently exists with another weight.
func (b *targetPlanBuilder) markCurrentWeightChanges() {
	for gk, current := range b.currentWeights {
		group, ok := b.groups[gk]
		if !ok {
			continue
		}
		for _, t := range group.Targets {
			if t.Class != TargetCommittable {
				continue
			}
			existing, ok := current[t.Key]
			if !ok || (existing.HasWeight == t.HasWeight && existing.Weight == t.Weight) {
				continue
			}
			t.Class = TargetWeightOnly
			t.Reason = fmt.Sprintf("weight changed from %d to %d", existing.Weight, t.Weight)
		}
	}
}

// committable collects the unique representatives that are neither equivalent
// duplicates nor incompatible, in canonical order.
func (b *targetPlanBuilder) committable(group *TargetGroup) []*PlannedTarget {
	known := sets.New[TargetKey]()
	result := make([]*PlannedTarget, 0, len(group.Targets))
	for _, t := range group.Targets {
		if t.Class == TargetEquivalent || t.Class == TargetIncompatible || known.Has(t.Key) {
			continue
		}
		known.Insert(t.Key)
		result = append(result, t)
	}
	return result
}

func (b *targetPlanBuilder) sortedGroupKeys() []groupKey {
	keys := slices.Clone(b.order)
	slices.SortFunc(keys, func(a, c groupKey) int {
		return cmp.Or(
			strings.Compare(a.dnsName, c.dnsName),
			strings.Compare(a.setIdentifier, c.setIdentifier),
			strings.Compare(a.recordType, c.recordType),
		)
	})
	return keys
}

func (b *targetPlanBuilder) keyOf(ep *endpoint.Endpoint) groupKey {
	return groupKey{
		dnsName:       idna.NormalizeDNSName(ep.DNSName),
		recordType:    ep.RecordType,
		setIdentifier: ep.SetIdentifier,
	}
}

func (b *targetPlanBuilder) identityOf(ep *endpoint.Endpoint, nt NormalizedTarget) TargetKey {
	return TargetKey{
		DNSName:       strings.TrimSuffix(idna.NormalizeDNSName(ep.DNSName), "."),
		RecordType:    ep.RecordType,
		SetIdentifier: ep.SetIdentifier,
		Target:        nt.Identity,
		Port:          nt.Port,
	}
}

// normalize canonicalizes a target and attaches its weight. SRV targets carry
// the weight and port in the target itself; other types read a configured
// provider-specific weight property.
func (b *targetPlanBuilder) normalize(ep *endpoint.Endpoint, raw string) NormalizedTarget {
	nt := NormalizeTarget(ep.RecordType, raw)
	if ep.RecordType != endpoint.RecordTypeSRV {
		if weight, ok := b.weightFromProperties(ep); ok {
			nt.Weight = weight
			nt.HasWeight = true
		}
	}
	return nt
}

func (b *targetPlanBuilder) weightFromProperties(ep *endpoint.Endpoint) (uint16, bool) {
	for _, name := range b.policy.WeightProperties {
		value, ok := ep.GetProviderSpecificProperty(name)
		if !ok {
			continue
		}
		weight, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			log.Debugf("Ignoring non-numeric weight property %q=%q on %s: %v", name, value, ep.DNSName, err)
			return 0, false
		}
		return uint16(weight), true
	}
	return 0, false
}

// canonicalHostname lowercases a DNS hostname and removes the trailing dot so
// that "Foo.Example.com." and "foo.example.com" compare equal.
func canonicalHostname(target string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target), "."))
}

func normalizeMX(target string) string {
	mx, err := endpoint.NewMXRecord(target)
	if err != nil {
		return canonicalHostname(target)
	}
	host := strings.ToLower(mx.GetHost())
	// The null MX "0 ." (RFC 7505) keeps the root dot; every other host is
	// rendered relative, matching endpoint.NormalizeMXTarget.
	if host != "." {
		host = strings.TrimSuffix(host, ".")
	}
	return fmt.Sprintf("%d %s", *mx.GetPriority(), host)
}

func normalizeSRV(target string) NormalizedTarget {
	nt := NormalizedTarget{RecordType: endpoint.RecordTypeSRV, Raw: target}
	srv, err := endpoint.NewSRVRecord(target)
	if err != nil {
		nt.Canonical = strings.TrimSpace(target)
		nt.Identity = nt.Canonical
		return nt
	}
	nt.Port = srv.GetPort()
	nt.Weight = srv.GetWeight()
	nt.HasWeight = true
	host := strings.ToLower(srv.GetHost())
	// The host must stay absolute for SRV; only its case is canonicalized.
	nt.Canonical = fmt.Sprintf("%d %d %d %s", srv.GetPriority(), srv.GetWeight(), srv.GetPort(), host)
	// Identity drops priority and weight: host plus the port in TargetKey
	// fully determines the target, so a weight-only change stays equivalent.
	nt.Identity = host
	return nt
}

func normalizeTLSA(target string) string {
	tlsa, err := endpoint.NewTLSARecord(target)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(target))
	}
	return tlsa.String()
}

func normalizeNAPTR(target string) string {
	naptr, err := endpoint.NewNAPTRRecord(target)
	if err != nil {
		// Regexp and flags are case-sensitive, so an unparseable target keeps
		// its exact text.
		return strings.TrimSpace(target)
	}
	return naptr.String()
}

func compareTargetKey(a, b TargetKey) int {
	return cmp.Or(
		strings.Compare(a.DNSName, b.DNSName),
		strings.Compare(a.RecordType, b.RecordType),
		strings.Compare(a.SetIdentifier, b.SetIdentifier),
		strings.Compare(a.Target, b.Target),
		cmp.Compare(a.Port, b.Port),
	)
}

func comparePlannedTarget(a, b *PlannedTarget) int {
	return cmp.Or(
		strings.Compare(a.Canonical, b.Canonical),
		cmp.Compare(a.Port, b.Port),
		strings.Compare(a.Raw, b.Raw),
	)
}
