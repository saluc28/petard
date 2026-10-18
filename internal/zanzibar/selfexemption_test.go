package zanzibar

import (
	"slices"
	"testing"
)

// exemptionSchema has a viewer held to an address allowlist, an owner, and a
// tag that no permission reads. view reads viewer, so fixing the allowlist on a
// viewer raises view.
func exemptionSchema(t *testing.T) *Model {
	t.Helper()
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "owner", Allowed: []Allowed{{Type: "user"}}},
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}, {Type: "user", Caveat: "ip_allowlist"}}},
			{Name: "tag", Allowed: []Allowed{{Type: "user", Caveat: "ip_allowlist"}}},
		},
		Permissions: []*Permission{
			{Name: "edit", Expr: Computed{Name: "owner"}},
			{Name: "view", Expr: Union{Children: []Expr{Computed{Name: "viewer"}, Computed{Name: "edit"}}}},
		},
	}
	caveats := []*Caveat{
		{Name: "ip_allowlist", Parameters: []Parameter{{Name: "user_ip", Type: "ipaddress"}, {Name: "cidr", Type: "string"}}},
	}
	m, err := NewModel([]*Type{{Name: "user"}, document}, caveats)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSelfAssertedExemptions(t *testing.T) {
	model := exemptionSchema(t)
	attacker := Object{Type: "user", ID: "attacker"}

	// shareRule writes viewer, held by edit, with the ip_allowlist caveat and
	// the given fillers.
	shareRule := func(userIP, cidr Filler) *WriteRule {
		return &WriteRule{
			Resource: "document", Relation: "viewer", Operations: []Operation{Create, Touch},
			Gate: Gate{Holds: "edit"}, Subject: SubjectSpec{Types: []string{"user"}},
			Caveats: []CaveatWrite{{Name: "ip_allowlist", Parameters: map[string]Filler{"user_ip": userIP, "cidr": cidr}}},
			Via:     "POST /share",
		}
	}

	tests := []struct {
		name string
		rule *WriteRule
		want []string
	}{
		{
			name: "application parameter is a finding",
			rule: shareRule(FillerApplication, FillerWriter),
			want: []string{"document#viewer, user_ip of caveat ip_allowlist"},
		},
		{
			name: "writer parameters only are not a finding",
			rule: shareRule(FillerWriter, FillerWriter),
			want: nil,
		},
		{
			name: "a service gate is out of reach",
			rule: &WriteRule{
				Resource: "document", Relation: "viewer", Operations: []Operation{Create},
				Gate: Gate{Service: "sharing"}, Subject: SubjectSpec{Types: []string{"user"}},
				Caveats: []CaveatWrite{{Name: "ip_allowlist", Parameters: map[string]Filler{"user_ip": FillerApplication}}},
			},
			want: nil,
		},
		{
			name: "a relation no permission reads is not a finding",
			rule: &WriteRule{
				Resource: "document", Relation: "tag", Operations: []Operation{Create},
				Gate: Gate{Anyone: true}, Subject: SubjectSpec{Types: []string{"user"}},
				Caveats: []CaveatWrite{{Name: "ip_allowlist", Parameters: map[string]Filler{"user_ip": FillerApplication}}},
			},
			want: nil,
		},
		{
			name: "a caveat the relation does not carry is not a finding",
			rule: &WriteRule{
				Resource: "document", Relation: "owner", Operations: []Operation{Create},
				Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true},
				Caveats: []CaveatWrite{{Name: "ip_allowlist", Parameters: map[string]Filler{"user_ip": FillerApplication}}},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{tt.rule}}
			var got []string
			for _, m := range SelfAssertedExemptions(model, wm, attacker, Options{}) {
				if m.PatternID != SelfAssertedExemptionID || m.Verdict != Finding {
					t.Errorf("%s: %s %s, want a finding of %s", m.Subject, m.PatternID, m.Verdict, SelfAssertedExemptionID)
				}
				got = append(got, m.Subject)
			}
			slices.Sort(got)
			slices.Sort(tt.want)
			if !slices.Equal(got, tt.want) {
				t.Errorf("findings = %v, want %v", got, tt.want)
			}
		})
	}
}

// With a write model, Run upgrades the candidate of a covered parameter to a
// finding and drops the duplicate candidate, while a parameter no write rule
// covers stays a candidate.
func TestRunUpgradesCoveredCandidates(t *testing.T) {
	model := exemptionSchema(t)
	// A sample that leaves user_ip to the check on a viewer, the evidence the
	// heuristic reads for a candidate.
	sample := Sample{
		Model: model,
		Relationships: []Relationship{
			{Resource: Object{Type: "document", ID: "readme"}, Relation: "viewer",
				Subject: Subject{Object: Object{Type: "user", ID: "vic"}}, Caveat: &CaveatUse{Name: "ip_allowlist", Context: map[string]any{"cidr": "10.0.0.0/8"}}},
		},
		Assertions: []Assertion{
			{Resource: Object{Type: "document", ID: "readme"}, Name: "view",
				Subject: Subject{Object: Object{Type: "user", ID: "vic"}}, Context: map[string]any{"user_ip": "10.1.2.3"}, Level: Yes},
		},
		Caveats: stubCaveats{},
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Holds: "edit"},
			Subject: SubjectSpec{Types: []string{"user"}},
			Caveats: []CaveatWrite{{Name: "ip_allowlist", Parameters: map[string]Filler{"user_ip": FillerApplication}}}},
	}}

	const viewer = "document#viewer, user_ip of caveat ip_allowlist"
	asFinding, asCandidate := false, false
	for _, m := range Run(sample, wm) {
		if m.Subject != viewer {
			continue
		}
		switch m.Verdict {
		case Finding:
			asFinding = true
		case Candidate:
			asCandidate = true
		}
	}
	if !asFinding {
		t.Error("the covered parameter should be a finding")
	}
	if asCandidate {
		t.Error("the finding should supersede the candidate of the same relation and parameter")
	}
}

// stubCaveats answers every caveat as conditional, enough for the heuristic's
// witness search in this test.
type stubCaveats struct{}

func (stubCaveats) Evaluate(string, map[string]any) (Level, error) { return Conditional, nil }
