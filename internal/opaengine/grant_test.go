package opaengine

import "testing"

// residual builds a residual set from the queries of its conditions, the way
// partial evaluation leaves them, so the tests read one decision against
// another the way the analysis does.
func residual(conditions ...string) *ResidualSet {
	rs := &ResidualSet{}
	for _, query := range conditions {
		rs.Conditions = append(rs.Conditions, Condition{Query: query, Value: "true"})
	}
	return rs
}

// The escalation the whole comparison exists for: a principal who grants a
// single action, joined into a decision that grants any action, reaches beyond
// what it held; the one who already grants any action reaches nothing new by
// joining the narrower one. Counting the conditions cannot tell the two apart,
// because each goes from one condition to two.
func TestGrantContentBeyondSeparatesGainFromWiderCount(t *testing.T) {
	anyAction := grantContentTestCase{
		query: "__local1__ = input.action; __local2__ = input.resource",
	}
	oneAction := grantContentTestCase{
		query: `"iam:policyMembers:create" = input.action; __local2__ = input.resource`,
	}

	before := residual(oneAction.query)
	afterJoiningAny := residual(anyAction.query, oneAction.query)
	beyond, certain := GrantContentOf(afterJoiningAny).Beyond(GrantContentOf(before))
	if !beyond || !certain {
		t.Errorf("narrow principal joining the any grant: beyond=%t certain=%t, want true true", beyond, certain)
	}

	beforeAny := residual(anyAction.query)
	afterJoiningOne := residual(anyAction.query, oneAction.query)
	beyond, certain = GrantContentOf(afterJoiningOne).Beyond(GrantContentOf(beforeAny))
	if beyond || !certain {
		t.Errorf("any principal joining the narrow grant: beyond=%t certain=%t, want false true", beyond, certain)
	}
}

type grantContentTestCase struct{ query string }

func TestGrantContentBeyond(t *testing.T) {
	tests := []struct {
		name        string
		grant       []string
		other       []string
		wantBeyond  bool
		wantCertain bool
	}{
		{
			name:        "always reaches beyond a condition",
			grant:       nil, // always is set below
			other:       []string{`"read" = input.action`},
			wantBeyond:  true,
			wantCertain: true,
		},
		{
			name:        "nothing reaches beyond always",
			grant:       []string{`"read" = input.action`},
			other:       nil, // always is set below
			wantBeyond:  false,
			wantCertain: true,
		},
		{
			name:        "a different value is a gain",
			grant:       []string{`"write" = input.action`},
			other:       []string{`"read" = input.action`},
			wantBeyond:  true,
			wantCertain: true,
		},
		{
			name:        "the same value is no gain",
			grant:       []string{`"read" = input.action`},
			other:       []string{`"read" = input.action`},
			wantBeyond:  false,
			wantCertain: true,
		},
		{
			name:        "a wider project membership covers a narrower one",
			grant:       []string{`"read" = input.action; "proj-x" = input.projects[_]`},
			other:       []string{`__local__ = input.action; __p__ = input.projects[_]`},
			wantBeyond:  false,
			wantCertain: true,
		},
		{
			name:        "a project the other does not reach is a gain",
			grant:       []string{`__a__ = input.action; "proj-y" = input.projects[_]`},
			other:       []string{`__a__ = input.action; "proj-x" = input.projects[_]`},
			wantBeyond:  true,
			wantCertain: true,
		},
		{
			// An extra truth test only narrows the grant, so it stays covered
			// by the broader one: the opaque field is not one the other pins.
			name:        "an extra truth test still covered",
			grant:       []string{`"read" = input.action; input.mfa`},
			other:       []string{`"read" = input.action`},
			wantBeyond:  false,
			wantCertain: true,
		},
		{
			// The grant leaves the action open while the other pins it, so it
			// reaches actions the other does not, whatever the prefix match
			// says about the resource.
			name:        "an open field escapes a pinned one",
			grant:       []string{`startswith(input.resource, "team/")`},
			other:       []string{`"read" = input.action`},
			wantBeyond:  true,
			wantCertain: true,
		},
		{
			// A wildcard match reads as a prefix: a value that starts with it is
			// covered, and the empty prefix a match against "*" leaves is any.
			name:        "a value is covered by a prefix of it",
			grant:       []string{`"iam:policies:get" = input.action`},
			other:       []string{`startswith(input.action, "iam:")`},
			wantBeyond:  false,
			wantCertain: true,
		},
		{
			name:        "the empty prefix covers any action",
			grant:       []string{`"anything" = input.action`},
			other:       []string{`startswith(input.action, "")`},
			wantBeyond:  false,
			wantCertain: true,
		},
		{
			name:        "a prefix reaches past a narrower value",
			grant:       []string{`startswith(input.action, "iam:")`},
			other:       []string{`"iam:policies:get" = input.action`},
			wantBeyond:  true,
			wantCertain: true,
		},
		{
			name:        "a derivation of the request is not a constraint",
			grant:       []string{`__p__ = split(input.action, ":"); __r__ = input.resource`},
			other:       []string{`__a__ = input.action; __r__ = input.resource`},
			wantBeyond:  false,
			wantCertain: true,
		},
		{
			// A request path held against a list is read element by element, so
			// two paths that differ at a fixed segment are told apart even when
			// one ends in a wildcard: deleting a team is not deleting one of its
			// members, whatever the member's id.
			name:        "a path differing at a fixed segment is a gain",
			grant:       []string{`input.path = ["api", "v1", "teams", "t-1"]`},
			other:       []string{`input.path = ["api", "v1", "users", "u-1", "tokens", _]`},
			wantBeyond:  true,
			wantCertain: true,
		},
		{
			name:        "the same path is no gain",
			grant:       []string{`input.path = ["api", "v1", "teams", "t-1"]`},
			other:       []string{`input.path = ["api", "v1", "teams", "t-1"]`},
			wantBeyond:  false,
			wantCertain: true,
		},
		{
			// A shorter path leaves the segments past its end open, so a longer
			// path under it reaches a request the shorter one does not name.
			name:        "a longer path escapes a shorter one",
			grant:       []string{`input.path = ["api", "v1", "teams", "t-1", "members"]`},
			other:       []string{`input.path = ["api", "v1", "teams", "t-1"]`},
			wantBeyond:  true,
			wantCertain: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grant := GrantContentOf(residual(tt.grant...))
			other := GrantContentOf(residual(tt.other...))
			if tt.grant == nil {
				grant.always = true
			}
			if tt.other == nil {
				other.always = true
			}

			beyond, certain := grant.Beyond(other)
			if beyond != tt.wantBeyond || certain != tt.wantCertain {
				t.Errorf("Beyond() = (%t, %t), want (%t, %t)", beyond, certain, tt.wantBeyond, tt.wantCertain)
			}
		})
	}
}

// A residual the bound cut short cannot prove coverage: a condition that would
// cover another may be the one that was dropped.
func TestGrantContentTruncatedIsNotCertain(t *testing.T) {
	other := residual(`"read" = input.action`)
	other.Truncated = true

	_, certain := GrantContentOf(residual(`"write" = input.action`)).Beyond(GrantContentOf(other))
	if certain {
		t.Error("a gain measured against a truncated residual is reported certain")
	}
}
