package opaengine

import (
	"slices"
	"strings"
)

// This file reads the write surface a policy guards: the branches of a decision
// that grant on a write method and a path, the shape of an endpoint that changes
// state. They are what a write model's authorized_by points at, so surfacing them
// turns writing that block by hand into picking one the policy already describes.

// writeMethods are the HTTP methods that change state, the ones a write endpoint
// is guarded by. A GET branch guards a read and is no write surface.
var writeMethods = []string{"PUT", "POST", "PATCH", "DELETE"}

// WriteEndpoint is one branch of a decision that grants on a write method, with
// the path it fixes when it fixes one. It is the request shape of a write the
// policy authorizes: the method, the path, and the decision that lets it through.
type WriteEndpoint struct {
	// Decision is the granting decision the branch belongs to.
	Decision string

	// Method is the write verb the branch holds the request to: PUT, POST,
	// PATCH or DELETE.
	Method string

	// Path is the value the branch holds the request path against, as Rego, and
	// empty when the branch fixes no path.
	Path string

	File string
	Line int
}

// WriteEndpoints finds the write endpoints a bundle's decisions guard: for each
// physical branch that grants on a write method, the method, the path it fixes,
// and the decision it grants.
//
// The checks of one branch are grouped by Block, the physical rule, since every
// allow block of a package shares one rule path and only the block tells one
// endpoint from the next. A branch under a negation is left out: it refuses on
// the method rather than granting on it.
func WriteEndpoints(reads *ReadSet) []WriteEndpoint {
	byBlock := map[string][]Check{}
	var blocks []string
	for _, check := range reads.Checks {
		if check.Block == "" {
			continue
		}
		if _, seen := byBlock[check.Block]; !seen {
			blocks = append(blocks, check.Block)
		}
		byBlock[check.Block] = append(byBlock[check.Block], check)
	}

	var endpoints []WriteEndpoint
	for _, block := range blocks {
		method, methodCheck, found := writeMethodOf(byBlock[block])
		if !found {
			continue
		}
		path := pathOf(byBlock[block])
		if path == "" {
			// No constant path, but the branch may still fix a path that holds
			// variables, kept as a shape rather than a check.
			path = reads.pathShapes[block]
		}
		for _, decision := range methodCheck.Decisions {
			if !decision.Grants {
				continue
			}
			endpoints = append(endpoints, WriteEndpoint{
				Decision: decision.Name,
				Method:   method,
				Path:     path,
				File:     methodCheck.File,
				Line:     methodCheck.Line,
			})
		}
	}

	slices.SortFunc(endpoints, func(a, b WriteEndpoint) int {
		return strings.Compare(a.key(), b.key())
	})
	return slices.CompactFunc(endpoints, func(a, b WriteEndpoint) bool { return a.key() == b.key() })
}

func (e WriteEndpoint) key() string {
	return e.Decision + "\x00" + e.Method + "\x00" + e.Path
}

// writeMethodOf returns the write verb a branch holds the request method to, the
// check that does it, and whether there is one.
func writeMethodOf(checks []Check) (string, Check, bool) {
	for _, check := range checks {
		if check.Operator != CheckEqual || check.UnderNegation || !isRequestField(check.Request, "method") {
			continue
		}
		if verb, ok := writeVerb(check.Value); ok {
			return verb, check, true
		}
	}
	return "", Check{}, false
}

// pathOf returns the path a branch fixes, as Rego, or the empty string.
func pathOf(checks []Check) string {
	for _, check := range checks {
		if check.Operator == CheckEqual && !check.UnderNegation && isRequestField(check.Request, "path") {
			return check.Value
		}
	}
	return ""
}

// isRequestField reports whether a request path names a given field: input.method
// or a method nested under another name, such as input.attributes.request.method.
func isRequestField(request, field string) bool {
	return request == "input."+field || strings.HasSuffix(request, "."+field)
}

// writeVerb returns the write method a check value names, if it is one. The value
// is a Rego string, so it comes quoted, and the method is compared without case.
func writeVerb(value string) (string, bool) {
	verb := strings.ToUpper(strings.Trim(value, `"`))
	if slices.Contains(writeMethods, verb) {
		return verb, true
	}
	return "", false
}
