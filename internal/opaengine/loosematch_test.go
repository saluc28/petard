package opaengine

import "testing"

// How much of a value a regex has to cover is in its pattern: the ends it pins,
// in every branch of its alternations, and whether an end pinned is opened
// again by a run of any character.
func TestRegexForm(t *testing.T) {
	tests := []struct {
		pattern string
		form    matchForm
	}{
		{`admin`, formEmbedded},
		{`/public/.*`, formEmbedded},
		{`^/admin$`, formWhole},
		{`\A/admin\z`, formWhole},
		{`^(get|head)$`, formWhole},
		{`^/a$|^/b$`, formWhole},
		{`^/admin`, formAffix},
		{`/admin$`, formAffix},
		{`^/api/.*$`, formAffix},
		{`^(extensions|networking.k8s.io)/`, formAffix},
		{`^/public|/health$`, formAffix},
		// The dollar is escaped, so only the start is pinned.
		{`^/price\$`, formAffix},
		// One branch pins nothing.
		{`^/a$|b`, formEmbedded},
		{`^.*admin.*$`, formEmbedded},
		{`^.+admin`, formEmbedded},
		// Under (?m) ^ and $ match at every line of the value.
		{`(?m)^/admin$`, formEmbedded},
		// OPA refuses a pattern that does not parse.
		{`(`, formEmbedded},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			if got := regexForm(tt.pattern); got != tt.form {
				t.Errorf("regexForm(%q) = %d, want %d", tt.pattern, got, tt.form)
			}
		})
	}
}

// A glob with no wildcard matches itself, one with a wildcard at each end
// matches whatever holds what is between them, and any other is a wildcard a
// route is usually written with.
func TestGlobForm(t *testing.T) {
	tests := []struct {
		pattern string
		form    matchForm
	}{
		{`/admin`, formWhole},
		{`/do/**`, formAffix},
		{`*.example.com`, formAffix},
		{`/a/*/b`, formAffix},
		{`/status**`, formAffix},
		{`*admin*`, formEmbedded},
		{`**/admin/**`, formEmbedded},
		// A wildcard and nothing else matches anything, and embeds nothing.
		{`**`, formAffix},
		// An escape or a class is a pattern, whatever it turns out to match.
		{`/a\*`, formAffix},
		{`/a[bc]`, formAffix},
		{`/{a,b}`, formAffix},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			if got := globForm(tt.pattern); got != tt.form {
				t.Errorf("globForm(%q) = %d, want %d", tt.pattern, got, tt.form)
			}
		})
	}
}
