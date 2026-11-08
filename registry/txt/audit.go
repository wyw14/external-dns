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

package txt

import (
	"cmp"
	"slices"
	"strings"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/internal/sets"
)

const (
	// IssueMissing means a DNS record has no ownership TXT record associated with it.
	IssueMissing OwnerRecordIssueKind = "Missing"
	// IssueDuplicate means more than one ownership TXT entry resolves to the same DNS record.
	IssueDuplicate OwnerRecordIssueKind = "Duplicate"
	// IssueStale means an ownership TXT entry has no matching DNS record in the fetched state.
	IssueStale OwnerRecordIssueKind = "Stale"
	// IssueOwnerConflict means ownership TXT entries for the same DNS record carry different owner IDs.
	IssueOwnerConflict OwnerRecordIssueKind = "OwnerConflict"
)

// OwnerRecordIssueKind classifies a single ownership consistency finding.
type OwnerRecordIssueKind string

// OwnerRecordIssue describes one consistency problem for a single DNS record.
// Raw TXT payloads are deliberately not part of this struct: they may contain
// encrypted label data, and the owner IDs below are sufficient to act on a finding.
type OwnerRecordIssue struct {
	// Kind is the classified issue type.
	Kind OwnerRecordIssueKind
	// Zone is the hosted zone name the record belongs to, "" when no given zone matched.
	Zone string
	// DNSName is the normalized (lower-case, no trailing dot) name of the owned DNS record.
	DNSName string
	// RecordType is the upper-case record type; "" for legacy untyped ownership TXTs.
	RecordType string
	// SetIdentifier distinguishes routing-policy variants sharing the same name and type.
	SetIdentifier string
	// OwnerIDs are the distinct owner IDs observed on the associated ownership TXT entries,
	// sorted for stable output. Empty for Missing.
	OwnerIDs []string
	// OwnerTXTCount is the number of ownership TXT entries associated with the record.
	OwnerTXTCount int
}

// OwnershipAuditReport holds the findings of an AuditOwnership run. Issues are
// sorted deterministically by zone, record identity and issue kind.
type OwnershipAuditReport struct {
	Issues []OwnerRecordIssue
}

// auditRecordKey identifies a DNS record independently of the spelling of its name.
type auditRecordKey struct {
	zone          string
	dnsName       string
	recordType    string
	setIdentifier string
}

// zoneResolver attributes a normalized DNS name to the longest matching hosted zone.
type zoneResolver struct {
	zones []string
}

func newZoneResolver(zoneNames []string) zoneResolver {
	zones := sets.New[string]()
	for _, zoneName := range zoneNames {
		if zoneName = normalizeDNSName(zoneName); zoneName != "" {
			zones.Insert(zoneName)
		}
	}
	sorted := sets.Sorted(zones)
	// Longest suffix wins so that records under a more specific zone are not
	// attributed to its parent zone.
	slices.SortFunc(sorted, func(a, b string) int {
		return cmp.Or(cmp.Compare(len(b), len(a)), cmp.Compare(a, b))
	})
	return zoneResolver{zones: sorted}
}

func (r zoneResolver) zoneOf(name string) string {
	for _, zone := range r.zones {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return zone
		}
	}
	return ""
}

// normalizeDNSName lower-cases and strips the trailing dot: DNS names are
// case-insensitive and absolute/relative spellings must compare equal.
func normalizeDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// AuditOwnership cross-checks already-fetched DNS records against the TXT ownership
// records found in the same record set, associating them by zone, record name and
// owner ID. It is strictly read-only: the provider is never called and the passed
// endpoints are neither modified nor retained.
//
// zoneNames lists the hosted zones used to attribute records via longest-suffix
// matching; records matching none of them report an empty Zone. TXT contents are
// compared through their parsed labels under the same heritage and encryption
// rules as Records(), so quote and token-order differences do not matter.
func (im *TXTRegistry) AuditOwnership(records []*endpoint.Endpoint, zoneNames []string) OwnershipAuditReport {
	zones := newZoneResolver(zoneNames)

	dnsRecords := make(map[auditRecordKey]struct{})
	ownerClaims := make(map[auditRecordKey][]string)

	for _, record := range records {
		if record == nil {
			continue
		}
		key := auditRecordKey{
			zone:          zones.zoneOf(normalizeDNSName(record.DNSName)),
			dnsName:       normalizeDNSName(record.DNSName),
			recordType:    strings.ToUpper(record.RecordType),
			setIdentifier: record.SetIdentifier,
		}

		if record.RecordType != endpoint.RecordTypeTXT {
			dnsRecords[key] = struct{}{}
			continue
		}

		// A targetless TXT cannot carry ownership labels; the record it would
		// protect surfaces as Missing instead.
		if len(record.Targets) == 0 {
			continue
		}
		endpointName, recordType := im.mapper.ToEndpointName(record.DNSName)
		if endpointName == "" {
			// TXT not following the configured registry affix: not an ownership record.
			continue
		}
		key.dnsName = normalizeDNSName(endpointName)
		key.recordType = strings.ToUpper(recordType)

		for _, target := range record.Targets {
			labels, err := endpoint.NewLabelsFromString(target, im.txtEncryptAESKey)
			if err != nil {
				// ErrInvalidHeritage marks an unrelated user TXT; any other parse
				// failure likewise yields no ownership claim.
				continue
			}
			ownerClaims[key] = append(ownerClaims[key], labels[endpoint.OwnerLabelKey])
		}
	}

	report := OwnershipAuditReport{Issues: []OwnerRecordIssue{}}

	for key := range dnsRecords {
		claims := ownerClaims[key]
		if len(claims) == 0 {
			report.Issues = append(report.Issues, newOwnerRecordIssue(IssueMissing, key, nil))
			continue
		}
		report.appendMultiplicityIssues(key, claims)
	}

	for key, claims := range ownerClaims {
		if _, ok := dnsRecords[key]; ok {
			continue
		}
		report.Issues = append(report.Issues, newOwnerRecordIssue(IssueStale, key, claims))
		report.appendMultiplicityIssues(key, claims)
	}

	slices.SortFunc(report.Issues, compareOwnerRecordIssue)
	return report
}

// appendMultiplicityIssues reports duplicate ownership TXT entries and, when
// those entries disagree on the owner, cross-owner conflicts.
func (r *OwnershipAuditReport) appendMultiplicityIssues(key auditRecordKey, claims []string) {
	owners := sets.Sorted(sets.New(claims...))
	if len(claims) > 1 {
		r.Issues = append(r.Issues, newOwnerRecordIssue(IssueDuplicate, key, claims))
	}
	if len(owners) > 1 {
		r.Issues = append(r.Issues, newOwnerRecordIssue(IssueOwnerConflict, key, claims))
	}
}

func newOwnerRecordIssue(kind OwnerRecordIssueKind, key auditRecordKey, claims []string) OwnerRecordIssue {
	issue := OwnerRecordIssue{
		Kind:          kind,
		Zone:          key.zone,
		DNSName:       key.dnsName,
		RecordType:    key.recordType,
		SetIdentifier: key.setIdentifier,
		OwnerTXTCount: len(claims),
	}
	if len(claims) > 0 {
		issue.OwnerIDs = sets.Sorted(sets.New(claims...))
	}
	return issue
}

func compareOwnerRecordIssue(a, b OwnerRecordIssue) int {
	return cmp.Or(
		cmp.Compare(a.Zone, b.Zone),
		cmp.Compare(a.DNSName, b.DNSName),
		cmp.Compare(a.RecordType, b.RecordType),
		cmp.Compare(a.SetIdentifier, b.SetIdentifier),
		cmp.Compare(string(a.Kind), string(b.Kind)),
		slices.Compare(a.OwnerIDs, b.OwnerIDs),
	)
}
