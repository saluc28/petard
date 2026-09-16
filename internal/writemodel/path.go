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
func ParsePath(path string) (Path, error) {
	if path == "" {
		return Path{}, fmt.Errorf("writemodel: empty path")
	}

	var segments []Segment
	for _, part := range strings.Split(path, ".") {
		parsed, err := parseSegments(part)
		if err != nil {
			return Path{}, fmt.Errorf("writemodel: in path %q: %w", path, err)
		}
		segments = append(segments, parsed...)
	}

	for i, segment := range segments {
		if segment.Kind == SegmentSubtree && i != len(segments)-1 {
			return Path{}, fmt.Errorf("writemodel: in path %q: * has to be last, there is nothing below a subtree", path)
		}
	}
	return Path{Segments: segments}, nil
}

// parseSegments reads one dot separated part, which may carry indices:
// users[_] is the collection and the index that follows it, and git[_][_] is a
// collection of collections, with one index for each level.
func parseSegments(part string) ([]Segment, error) {
	if part == "" {
		return nil, fmt.Errorf("empty segment")
	}

	name, indices, hasIndex := strings.Cut(part, "[")
	segments := []Segment{segmentOf(name)}
	if !hasIndex {
		return segments, nil
	}

	indices, ok := strings.CutSuffix(indices, "]")
	if !ok {
		return nil, fmt.Errorf("unclosed [ in %q", part)
	}
	for index := range strings.SplitSeq(indices, "][") {
		if index != "_" {
			// A concrete index would be a path to one document, and the model
			// speaks about shapes. Writing it out is almost certainly a mistake.
			return nil, fmt.Errorf("index [%s] in %q: only [_] is a path, a concrete index names one document", index, part)
		}
		segments = append(segments, Segment{Kind: SegmentCapture})
	}
	return segments, nil
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

// String writes the path back in the model's notation.
func (p Path) String() string {
	parts := make([]string, 0, len(p.Segments))
	for _, segment := range p.Segments {
		switch segment.Kind {
		case SegmentSubtree:
			parts = append(parts, "*")
		case SegmentCapture:
			if segment.Name == "" {
				parts = append(parts, "{}")
				continue
			}
			parts = append(parts, "{"+segment.Name+"}")
		default:
			parts = append(parts, segment.Name)
		}
	}
	return strings.Join(parts, ".")
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
