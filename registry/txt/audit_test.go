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
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
	"sigs.k8s.io/external-dns/provider/inmemory"
)

const auditTestKey = "passphrasewhichneedstobe32bytes!"

func newAuditRegistry(t *testing.T, prefix, suffix string, encrypt bool) *TXTRegistry {
	t.Helper()
	var aesKey []byte
	if encrypt {
		aesKey = []byte(auditTestKey)
	}
	r, err := newRegistry(inmemory.NewInMemoryProvider(), prefix, suffix, "local-owner", 0, "", nil, nil, encrypt, aesKey, "")
	require.NoError(t, err)
	return r
}

func ownershipTXTTarget(owner string) string {
	return endpoint.Labels{endpoint.OwnerLabelKey: owner}.SerializePlain(false)
}

func ownershipTXT(r *TXTRegistry, ownedName, recordType, setIdentifier, owner string) *endpoint.Endpoint {
	txt := endpoint.NewEndpoint(r.mapper.ToTXTName(ownedName, recordType), endpoint.RecordTypeTXT, ownershipTXTTarget(owner))
	txt.SetIdentifier = setIdentifier
	return txt
}

func auditIssue(kind OwnerRecordIssueKind, zone, name, recordType, setIdentifier string, count int, owners ...string) OwnerRecordIssue {
	return OwnerRecordIssue{
		Kind:          kind,
		Zone:          zone,
		DNSName:       name,
		RecordType:    recordType,
		SetIdentifier: setIdentifier,
		OwnerIDs:      owners,
		OwnerTXTCount: count,
	}
}

func TestAuditOwnership_EmptyInputs(t *testing.T) {
	r := newAuditRegistry(t, "", "", false)

	assert.Empty(t, r.AuditOwnership(nil, nil).Issues)
	assert.Empty(t, r.AuditOwnership([]*endpoint.Endpoint{}, []string{"example.org"}).Issues)
	assert.Empty(t, r.AuditOwnership([]*endpoint.Endpoint{nil}, nil).Issues)
}

func TestAuditOwnership_HealthyRecords(t *testing.T) {
	r := newAuditRegistry(t, "", "", false)

	records := []*endpoint.Endpoint{
		// Upper-case name and trailing dot must match the lower-case TXT name.
		endpoint.NewEndpoint("WWW.Example.ORG.", endpoint.RecordTypeA, "1.2.3.4"),
		endpoint.NewEndpoint("a-www.example.org", endpoint.RecordTypeTXT, ownershipTXTTarget("owner-1")),
		// Routing-policy variant keyed by set identifier.
		newEndpointWithOwner("policy.example.org", "lb.example.net", endpoint.RecordTypeCNAME, "owner-2"),
	}
	policyTXT := ownershipTXT(r, "policy.example.org", endpoint.RecordTypeCNAME, "eu", "owner-2")
	records[2].SetIdentifier = "eu"
	records = append(records, policyTXT)

	report := r.AuditOwnership(records, []string{"example.org"})
	assert.Empty(t, report.Issues)
}

func TestAuditOwnership_Missing(t *testing.T) {
	r := newAuditRegistry(t, "", "", false)

	records := []*endpoint.Endpoint{
		endpoint.NewEndpoint("no-txt.example.org", endpoint.RecordTypeA, "1.2.3.4"),
		endpoint.NewEndpoint("empty-targets.example.org", endpoint.RecordTypeA, "1.2.3.5"),
		endpoint.NewEndpoint("a-empty-targets.example.org", endpoint.RecordTypeTXT),
		// Unrelated user TXT (no external-dns heritage) must be ignored entirely.
		endpoint.NewEndpoint("spf.example.org", endpoint.RecordTypeTXT, "v=spf1 -all"),
	}

	report := r.AuditOwnership(records, []string{"example.org"})
	expected := []OwnerRecordIssue{
		auditIssue(IssueMissing, "example.org", "empty-targets.example.org", endpoint.RecordTypeA, "", 0),
		auditIssue(IssueMissing, "example.org", "no-txt.example.org", endpoint.RecordTypeA, "", 0),
	}
	assert.Equal(t, expected, report.Issues)
}

func TestAuditOwnership_Stale(t *testing.T) {
	r := newAuditRegistry(t, "", "", false)

	records := []*endpoint.Endpoint{
		ownershipTXT(r, "gone.example.org", endpoint.RecordTypeA, "", "owner-1"),
	}

	report := r.AuditOwnership(records, []string{"example.org"})
	expected := []OwnerRecordIssue{
		auditIssue(IssueStale, "example.org", "gone.example.org", endpoint.RecordTypeA, "", 1, "owner-1"),
	}
	assert.Equal(t, expected, report.Issues)
}

func TestAuditOwnership_Duplicate(t *testing.T) {
	r := newAuditRegistry(t, "", "", false)

	records := []*endpoint.Endpoint{
		endpoint.NewEndpoint("dup.example.org", endpoint.RecordTypeA, "1.2.3.4"),
		ownershipTXT(r, "dup.example.org", endpoint.RecordTypeA, "", "owner-1"),
		ownershipTXT(r, "dup.example.org", endpoint.RecordTypeA, "", "owner-1"),
		endpoint.NewEndpoint("multi.example.org", endpoint.RecordTypeCNAME, "lb.example.net"),
	}
	multiTXT := endpoint.NewEndpoint(r.mapper.ToTXTName("multi.example.org", endpoint.RecordTypeCNAME), endpoint.RecordTypeTXT,
		ownershipTXTTarget("owner-2"), ownershipTXTTarget("owner-2"))
	records = append(records, multiTXT)

	report := r.AuditOwnership(records, []string{"example.org"})
	expected := []OwnerRecordIssue{
		auditIssue(IssueDuplicate, "example.org", "dup.example.org", endpoint.RecordTypeA, "", 2, "owner-1"),
		auditIssue(IssueDuplicate, "example.org", "multi.example.org", endpoint.RecordTypeCNAME, "", 2, "owner-2"),
	}
	assert.Equal(t, expected, report.Issues)
}

func TestAuditOwnership_CrossOwnerConflict(t *testing.T) {
	r := newAuditRegistry(t, "", "", false)

	records := []*endpoint.Endpoint{
		endpoint.NewEndpoint("conflict.example.org", endpoint.RecordTypeA, "1.2.3.4"),
		ownershipTXT(r, "conflict.example.org", endpoint.RecordTypeA, "", "owner-b"),
		ownershipTXT(r, "conflict.example.org", endpoint.RecordTypeA, "", "owner-a"),
	}

	report := r.AuditOwnership(records, []string{"example.org"})
	expected := []OwnerRecordIssue{
		auditIssue(IssueDuplicate, "example.org", "conflict.example.org", endpoint.RecordTypeA, "", 2, "owner-a", "owner-b"),
		auditIssue(IssueOwnerConflict, "example.org", "conflict.example.org", endpoint.RecordTypeA, "", 2, "owner-a", "owner-b"),
	}
	assert.Equal(t, expected, report.Issues)
}

func TestAuditOwnership_OwnerIDIsCaseSensitive(t *testing.T) {
	r := newAuditRegistry(t, "", "", false)

	records := []*endpoint.Endpoint{
		endpoint.NewEndpoint("case.example.org", endpoint.RecordTypeA, "1.2.3.4"),
		ownershipTXT(r, "case.example.org", endpoint.RecordTypeA, "", "Owner"),
		ownershipTXT(r, "case.example.org", endpoint.RecordTypeA, "", "owner"),
	}

	report := r.AuditOwnership(records, []string{"example.org"})
	require.Len(t, report.Issues, 2)
	assert.Equal(t, IssueDuplicate, report.Issues[0].Kind)
	assert.Equal(t, IssueOwnerConflict, report.Issues[1].Kind)
	assert.Equal(t, []string{"Owner", "owner"}, report.Issues[1].OwnerIDs)
}

func TestAuditOwnership_MultipleOwnersDifferentRecords(t *testing.T) {
	r := newAuditRegistry(t, "", "", false)

	records := []*endpoint.Endpoint{
		endpoint.NewEndpoint("alpha.example.org", endpoint.RecordTypeA, "1.2.3.4"),
		ownershipTXT(r, "alpha.example.org", endpoint.RecordTypeA, "", "owner-a"),
		endpoint.NewEndpoint("beta.example.org", endpoint.RecordTypeA, "1.2.3.5"),
		ownershipTXT(r, "beta.example.org", endpoint.RecordTypeA, "", "owner-b"),
	}

	assert.Empty(t, r.AuditOwnership(records, []string{"example.org"}).Issues)
}

func TestAuditOwnership_ZoneAttribution(t *testing.T) {
	r := newAuditRegistry(t, "", "", false)

	records := []*endpoint.Endpoint{
		endpoint.NewEndpoint("host.sub.example.org", endpoint.RecordTypeA, "1.2.3.4"),
		endpoint.NewEndpoint("host.example.net", endpoint.RecordTypeA, "1.2.3.5"),
	}

	report := r.AuditOwnership(records, []string{"example.org", "sub.example.org"})
	expected := []OwnerRecordIssue{
		// Longest matching zone wins; no matching zone leaves Zone empty and sorts first.
		auditIssue(IssueMissing, "", "host.example.net", endpoint.RecordTypeA, "", 0),
		auditIssue(IssueMissing, "sub.example.org", "host.sub.example.org", endpoint.RecordTypeA, "", 0),
	}
	assert.Equal(t, expected, report.Issues)
}

func TestAuditOwnership_SetIdentifierDistinguishesRecords(t *testing.T) {
	r := newAuditRegistry(t, "", "", false)

	records := []*endpoint.Endpoint{
		newEndpointWithOwner("policy.example.org", "lb-eu.example.net", endpoint.RecordTypeCNAME, "owner-1"),
		newEndpointWithOwner("policy.example.org", "lb-us.example.net", endpoint.RecordTypeCNAME, "owner-1"),
		ownershipTXT(r, "policy.example.org", endpoint.RecordTypeCNAME, "eu", "owner-1"),
	}
	records[0].SetIdentifier = "eu"
	records[1].SetIdentifier = "us"

	report := r.AuditOwnership(records, []string{"example.org"})
	expected := []OwnerRecordIssue{
		auditIssue(IssueMissing, "example.org", "policy.example.org", endpoint.RecordTypeCNAME, "us", 0),
	}
	assert.Equal(t, expected, report.Issues)
}

func TestAuditOwnership_CustomAffix(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		suffix string
	}{
		{name: "custom prefix", prefix: "txt-"},
		{name: "custom suffix", suffix: "-txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newAuditRegistry(t, tt.prefix, tt.suffix, false)

			records := []*endpoint.Endpoint{
				endpoint.NewEndpoint("foo.example.org", endpoint.RecordTypeA, "1.2.3.4"),
				endpoint.NewEndpoint(r.mapper.ToTXTName("foo.example.org", endpoint.RecordTypeA), endpoint.RecordTypeTXT, ownershipTXTTarget("owner-1")),
				// Stale entry under the same affix convention.
				endpoint.NewEndpoint(r.mapper.ToTXTName("bar.example.org", endpoint.RecordTypeA), endpoint.RecordTypeTXT, ownershipTXTTarget("owner-1")),
			}

			report := r.AuditOwnership(records, []string{"example.org"})
			expected := []OwnerRecordIssue{
				auditIssue(IssueStale, "example.org", "bar.example.org", endpoint.RecordTypeA, "", 1, "owner-1"),
			}
			assert.Equal(t, expected, report.Issues)
		})
	}
}

func TestAuditOwnership_EncryptedPayloadParsedAndNotExposed(t *testing.T) {
	r := newAuditRegistry(t, "", "", true)

	ep := newEndpointWithOwner("secure.example.org", "1.2.3.4", endpoint.RecordTypeA, "owner-1")
	txts := r.generateTXTRecord(ep)
	require.Len(t, txts, 1)
	encryptedTarget := txts[0].Targets[0]

	report := r.AuditOwnership([]*endpoint.Endpoint{ep, txts[0]}, []string{"example.org"})
	assert.Empty(t, report.Issues)

	rendered := fmt.Sprintf("%#v", report)
	assert.NotContains(t, rendered, encryptedTarget)
	assert.NotContains(t, rendered, auditTestKey)
}

// callTrackingProvider fails and counts every provider call so tests can prove
// the audit never reaches the provider.
type callTrackingProvider struct {
	provider.BaseProvider
	calls int
}

func (p *callTrackingProvider) Records(context.Context) ([]*endpoint.Endpoint, error) {
	p.calls++
	return nil, assert.AnError
}

func (p *callTrackingProvider) ApplyChanges(context.Context, *plan.Changes) error {
	p.calls++
	return assert.AnError
}

func TestAuditOwnership_DoesNotCallProviderOrMutateInputs(t *testing.T) {
	p := &callTrackingProvider{}
	r, err := newRegistry(p, "", "", "local-owner", 0, "", nil, nil, false, nil, "")
	require.NoError(t, err)

	records := []*endpoint.Endpoint{
		endpoint.NewEndpoint("mutate.example.org", endpoint.RecordTypeA, "1.2.3.4"),
		ownershipTXT(r, "mutate.example.org", endpoint.RecordTypeA, "", "owner-1"),
	}
	snapshot := make([]*endpoint.Endpoint, len(records))
	for i, ep := range records {
		snapshot[i] = ep.DeepCopy()
	}

	report := r.AuditOwnership(records, []string{"example.org"})
	assert.Empty(t, report.Issues)
	assert.Zero(t, p.calls)
	for i := range records {
		assert.True(t, endpoint.Equal(snapshot[i], records[i]))
	}
}

func TestAuditOwnership_StableSorting(t *testing.T) {
	r := newAuditRegistry(t, "", "", false)

	records := []*endpoint.Endpoint{
		endpoint.NewEndpoint("mid.example.net", endpoint.RecordTypeA, "1.2.3.9"),
		ownershipTXT(r, "mid.example.net", endpoint.RecordTypeA, "", "owner-b"),
		ownershipTXT(r, "mid.example.net", endpoint.RecordTypeA, "", "owner-a"),
		ownershipTXT(r, "zzz.example.org", endpoint.RecordTypeA, "", "owner-1"),
		endpoint.NewEndpoint("aaa.example.org", endpoint.RecordTypeA, "1.2.3.4"),
		nil,
	}

	want := []OwnerRecordIssue{
		auditIssue(IssueDuplicate, "example.net", "mid.example.net", endpoint.RecordTypeA, "", 2, "owner-a", "owner-b"),
		auditIssue(IssueOwnerConflict, "example.net", "mid.example.net", endpoint.RecordTypeA, "", 2, "owner-a", "owner-b"),
		auditIssue(IssueMissing, "example.org", "aaa.example.org", endpoint.RecordTypeA, "", 0),
		auditIssue(IssueStale, "example.org", "zzz.example.org", endpoint.RecordTypeA, "", 1, "owner-1"),
	}

	first := r.AuditOwnership(records, []string{"example.org", "example.net"})
	second := r.AuditOwnership(records, []string{"example.net", "example.org"})
	assert.Equal(t, want, first.Issues)
	assert.Equal(t, first.Issues, second.Issues)
}
