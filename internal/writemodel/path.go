// Package writemodel reads the declaration of who can write what in the system
// around OPA.
//
// It is the one part of the analysis that no policy can supply. Whether a
// decision is sound depends on who can write the data it reads, and that fact
// lives in a profile API, a signup form, an IdP sync, a CSV import. Nobody can
// infer it from Rego, so somebody declares it, and this package reads what they
// declared.
//
// The world is closed: what is not declared is not writable. That way an
// incomplete model produces false negatives rather than false positives, which
// is the right direction to be wrong in for a tool whose output goes into a
// report. The price is that the gaps have to be visible, which is what the
// coverage number is for.
package writemodel

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SegmentKind says what a path segment matches.
type SegmentKind int

const (
	// SegmentLiteral matches itself and nothing else: users, profile.
	SegmentLiteral SegmentKind = iota

	// SegmentCapture matches any one segment. In a write model entry it is
	// written {owner} and the name matters, because a writer can refer back to
	// it; in a read it is written [_] and there is nothing to name.
	SegmentCapture

	// SegmentSubtree matches everything below, and can only be last. It is how
	// a model says that a whole record is writable without listing its fields.
	SegmentSubtree
)

// Segment is one step of a path.
type Segment struct {
	Kind SegmentKind

	// Name is the literal, or the name of the capture, and is empty for an
	// unnamed capture and for a subtree.
	Name string
}

// Path is a path into data, split into segments.
//
// One type reads both notations, the model's data.users.{owner}.profile and
// the engine's data.users[_].profile, because they are the same path said
// twice and matching them has to be a comparison, not a translation.
type Path struct {
	Segments []Segment
}

// ParsePath reads a path in either notation.
//
// A key in brackets and quotes is one segment whatever it holds, the way OPA
// parses a reference: data.inventory.cluster["storage.k8s.io/v1"] has five
// segments, and the fourth is storage.k8s.io/v1. OPA writes a key that way
// whenever it is not a bare name, so a read of the inventory Gatekeeper
// replicates arrives in this form.
func ParsePath(path string) (Path, error) {
	if path == "" {
		return Path{}, fmt.Errorf("writemodel: empty path")
	}

	segments, err := parseSegments(path)
	if err != nil {
		return Path{}, fmt.Errorf("writemodel: in path %q: %w", path, err)
	}

	for i, segment := range segments {
		if segment.Kind == SegmentSubtree && i != len(segments)-1 {
			return Path{}, fmt.Errorf("writemodel: in path %q: * has to be last, there is nothing below a subtree", path)
		}
	}
	return Path{Segments: segments}, nil
}

// parseSegments reads the names of a path and the indices after each one:
// users[_] is the collection and the index that follows it, git[_][_] is a
// collection of collections with one index for each level, and a dot inside a
// quoted key does not separate anything.
func parseSegments(path string) ([]Segment, error) {
	var segments []Segment
	rest := path
	for {
		end := strings.IndexAny(rest, ".[")
		if end < 0 {
			end = len(rest)
		}
		if end == 0 {
			return nil, fmt.Errorf("empty segment")
		}
		segments = append(segments, segmentOf(rest[:end]))
		rest = rest[end:]

		for strings.HasPrefix(rest, "[") {
			segment, after, err := parseIndex(rest)
			if err != nil {
				return nil, err
			}
			segments = append(segments, segment)
			rest = after
		}

		if rest == "" {
			return segments, nil
		}
		if rest[0] != '.' {
			return nil, fmt.Errorf("%q follows an index, where a dot or another index goes", rest)
		}
		rest = rest[1:]
	}
}

// parseIndex reads the index at the start of rest and returns what follows it.
//
// A quoted key is a literal, read as OPA reads a string: in double quotes with
// JSON escapes, or raw in backquotes. It is the same segment the key would be
// written bare, so data.users["profile"] is data.users.profile, and it never
// means anything else: ["*"] is a key called *, not a subtree.
func parseIndex(rest string) (Segment, string, error) {
	switch {
	case strings.HasPrefix(rest, `["`):
		closing := closingQuote(rest[2:])
		if closing < 0 {
			return Segment{}, "", fmt.Errorf("unclosed quote in %q", rest)
		}
		quoted := rest[1 : 2+closing+1]
		var key string
		if err := json.Unmarshal([]byte(quoted), &key); err != nil {
			return Segment{}, "", fmt.Errorf("key %s: %w", quoted, err)
		}
		return literalIndex(key, rest[len(quoted)+1:])

	case strings.HasPrefix(rest, "[`"):
		key, after, closed := strings.Cut(rest[2:], "`")
		if !closed {
			return Segment{}, "", fmt.Errorf("unclosed quote in %q", rest)
		}
		return literalIndex(key, after)
	}

	index, after, closed := strings.Cut(rest[1:], "]")
	if !closed {
		return Segment{}, "", fmt.Errorf("unclosed [ in %q", rest)
	}
	if index != "_" {
		// A concrete index would be a path to one document, and the model
		// speaks about shapes. Writing it out is almost certainly a mistake.
		return Segment{}, "", fmt.Errorf("index [%s]: only [_] is a path, a concrete index names one document", index)
	}
	return Segment{Kind: SegmentCapture}, after, nil
}

// closingQuote returns where the double quote that ends a string sits in s,
// which starts right after the opening one, or -1 when nothing ends it.
func closingQuote(s string) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return -1
}

// literalIndex is a quoted key that the closing bracket has to follow.
func literalIndex(key, rest string) (Segment, string, error) {
	after, closed := strings.CutPrefix(rest, "]")
	if !closed {
		return Segment{}, "", fmt.Errorf("the key %q is not followed by ]", key)
	}
	return Segment{Kind: SegmentLiteral, Name: key}, after, nil
}

func segmentOf(name string) Segment {
	switch {
	case name == "*":
		return Segment{Kind: SegmentSubtree}
	case strings.HasPrefix(name, "{") && strings.HasSuffix(name, "}"):
		return Segment{Kind: SegmentCapture, Name: strings.Trim(name, "{}")}
	default:
		return Segment{Kind: SegmentLiteral, Name: name}
	}
}

// String writes the path back in the model's notation. A literal that would
// read back as something else written bare, one with a dot in it or one
// called *, goes in brackets and quotes.
func (p Path) String() string {
	var out strings.Builder
	for i, segment := range p.Segments {
		if segment.Kind == SegmentLiteral && !readsBackBare(segment.Name) {
			// A string always encodes, so there is no error to handle.
			quoted, _ := json.Marshal(segment.Name)
			out.WriteString("[" + string(quoted) + "]")
			continue
		}
		if i > 0 {
			out.WriteByte('.')
		}
		switch segment.Kind {
		case SegmentSubtree:
			out.WriteString("*")
		case SegmentCapture:
			out.WriteString("{" + segment.Name + "}")
		default:
			out.WriteString(segment.Name)
		}
	}
	return out.String()
}

// readsBackBare reports whether a literal written without quotes parses as the
// same literal.
func readsBackBare(name string) bool {
	if name == "" || strings.ContainsAny(name, ".[]") {
		return false
	}
	return segmentOf(name) == Segment{Kind: SegmentLiteral, Name: name}
}

// Matches reports whether this path covers the other one.
//
// Captures match any single segment, and a trailing subtree matches whatever
// is left. The direction matters: a model entry covers a read, not the other
// way round.
func (p Path) Matches(other Path) bool {
	for i, segment := range p.Segments {
		if segment.Kind == SegmentSubtree {
			// Everything below is covered, including nothing at all.
			return true
		}
		if i >= len(other.Segments) {
			return false
		}
		if segment.Kind == SegmentCapture {
			continue
		}
		if other.Segments[i].Kind != SegmentLiteral || other.Segments[i].Name != segment.Name {
			return false
		}
	}
	return len(p.Segments) == len(other.Segments)
}

// Fill replaces every capture named in a template with the segment one
// document holds there, and is how a request the endpoint fills in itself
// turns into the request it sends for one document.
//
// The segments are counted from the data root, the way a capture position is:
// data.policies.{policy}.members against the segments of
// data.policies.readers.members puts readers where {policy} stands.
func (p Path) Fill(template string, segments []string) (string, error) {
	filled := template
	for _, capture := range capturesIn(template) {
		position, found := p.CapturePosition(capture)
		if !found {
			return "", fmt.Errorf("writemodel: %q names {%s}, and the path has no such capture", template, capture)
		}
		if position >= len(segments) {
			return "", fmt.Errorf("writemodel: {%s} sits at segment %d, past the end of the document", capture, position)
		}
		filled = strings.ReplaceAll(filled, "{"+capture+"}", segments[position])
	}
	return filled, nil
}

// capturesIn returns the captures a template names, in the order they appear.
func capturesIn(template string) []string {
	var captures []string
	rest := template
	for {
		_, after, found := strings.Cut(rest, "{")
		if !found {
			return captures
		}
		name, remainder, closed := strings.Cut(after, "}")
		if !closed {
			return captures
		}
		captures = append(captures, name)
		rest = remainder
	}
}

// CapturePosition returns where a named capture sits in the path.
//
// It is what makes the third signal of the self write pattern computable: the
// model says {owner} writes this field, the position says which segment of the
// read that is, and the read says the term standing there.
func (p Path) CapturePosition(name string) (int, bool) {
	for i, segment := range p.Segments {
		if segment.Kind == SegmentCapture && segment.Name == name {
			return i, true
		}
	}
	return 0, false
}
