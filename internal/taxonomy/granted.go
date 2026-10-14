package taxonomy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
)

// ErrNotGranted is returned when a request given as one the decisions grant is
// granted by none of them.
//
// It is an error and not a request left aside. Whoever gave it holds something
// to be true of the policy and the data, and a run that went on without saying
// it is not would report on a question it never asked.
var ErrNotGranted = errors.New("taxonomy: no decision grants the request")

// GrantedRequest is a request given from outside as one the decisions grant.
//
// Some questions start from a request a decision grants, and ask what the
// decision says once one part of it changes. Such a request is built from the
// conditions partial evaluation leaves, and a decision that holds a part of the
// request against something it computes, split(input.path, "/")[1] == "public",
// leaves nothing to build one from. A request somebody already knows is
// granted, the one a test of the policy sends or one out of an access log, is
// then where the question starts.
//
// It belongs to the policy and the data together, and not to the product that
// asks: the same product in front of another policy is granted other requests.
type GrantedRequest struct {
	// File is where the request was read from.
	File string

	// Input is the request, as the policy reads it.
	Input map[string]any

	// Decisions are the decisions that grant it, sorted. They were asked when
	// the request was loaded, against the data of the analysis.
	Decisions []string
}

// loadGranted reads the requests given as granted, and asks every granting
// decision about each. A request none of them grants is an error.
//
// A decision is asked against the data of the analysis, and against no document
// at all when there is none: what a decision that reads documents grants
// without them is nothing, and the error says so.
func loadGranted(ctx context.Context, a Analysis, files []string) ([]GrantedRequest, error) {
	if len(files) == 0 {
		return nil, nil
	}
	data := a.Data
	if data == nil {
		data = opaengine.NoData()
	}
	decisions := grantingDecisions(a.Reads)

	var granted []GrantedRequest
	for _, file := range files {
		input, err := opaengine.LoadRequest(file)
		if err != nil {
			return nil, err
		}
		request := GrantedRequest{File: file, Input: input}
		for _, decision := range decisions {
			holds, err := opaengine.Holds(ctx, a.Bundle, data, decision, input)
			var panicked *opaengine.EvaluatorPanicError
			if errors.As(err, &panicked) {
				// A decision OPA panics on answers nothing, this request included.
				continue
			}
			if err != nil {
				return nil, err
			}
			if holds {
				request.Decisions = append(request.Decisions, decision)
			}
		}
		if len(request.Decisions) == 0 {
			return nil, fmt.Errorf("%w in %s%s", ErrNotGranted, file, whyNotGranted(a, decisions))
		}
		granted = append(granted, request)
	}
	return granted, nil
}

// whyNotGranted says what is known about why no decision grants a request, when
// it is more than the request itself: there is no decision to grant it, or the
// ones there are read documents nobody gave.
func whyNotGranted(a Analysis, decisions []string) string {
	if len(decisions) == 0 {
		return ": every decision of the bundle is declared to deny"
	}
	if a.Data != nil {
		return ""
	}
	if !slices.ContainsFunc(decisions, func(decision string) bool { return decisionReadsData(a.Reads, decision) }) {
		return ""
	}
	return ": no data was given, and a decision that reads documents grants nothing without them"
}

// grantedBy returns the requests given as granted that one decision grants.
func (a Analysis) grantedBy(decision string) []map[string]any {
	var requests []map[string]any
	for _, request := range a.Granted {
		if slices.Contains(request.Decisions, decision) {
			requests = append(requests, request.Input)
		}
	}
	return requests
}

// inputValue returns what a request holds at a part of it named whole, as
// input.request.path, and whether it holds anything there.
func inputValue(request map[string]any, part string) (any, bool) {
	var at any = request
	for _, field := range strings.Split(strings.TrimPrefix(part, "input."), ".") {
		object, isObject := at.(map[string]any)
		if !isObject {
			return nil, false
		}
		next, found := object[field]
		if !found {
			return nil, false
		}
		at = next
	}
	return at, true
}
