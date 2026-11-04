package zanzibar

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/saluc28/petard/internal/graph"
)

// A state answers a check of its object exactly as the whole sample does, so it holds
// the tuples on the object and on everything they name, however far.
func TestAStateHoldsWhatACheckOfItsObjectReads(t *testing.T) {
	states, _ := weighedStates(Sample{Relationships: []Relationship{
		rel("document:plan", "viewer", "user:vic"),
		rel("document:roadmap", "parent", "folder:a"),
		rel("folder:a", "parent", "folder:b"),
		rel("folder:b", "viewer", "user:erin"),
		rel("folder:unrelated", "viewer", "user:dana"),
	}}, nil)

	var roadmap *weighedState
	for i := range states {
		if states[i].object == (Object{Type: "document", ID: "roadmap"}) {
			roadmap = &states[i]
		}
	}
	if roadmap == nil {
		t.Fatal("no state for document:roadmap")
	}
	has := func(resource, relation string) bool {
		return slices.ContainsFunc(roadmap.tuples, func(r Relationship) bool {
			return r.Resource.String() == resource && r.Relation == relation
		})
	}
	for _, want := range [][2]string{{"document:roadmap", "parent"}, {"folder:a", "parent"}, {"folder:b", "viewer"}} {
		if !has(want[0], want[1]) {
			t.Errorf("the state does not hold %s#%s: %v", want[0], want[1], roadmap.tuples)
		}
	}
	for _, other := range [][2]string{{"document:plan", "viewer"}, {"folder:unrelated", "viewer"}} {
		if has(other[0], other[1]) {
			t.Errorf("the state holds %s#%s, which no check of it reads: %v", other[0], other[1], roadmap.tuples)
		}
	}
}

// What a creation can start from comes along: of its type, one object of each shape, the
// one that brings the least, and how many others it stands for is said. A type no creation
// starts from brings nothing, since no witness can use an object no check of it reads.
func TestAStateBringsOneObjectOfEachShapeACreationCanStartFrom(t *testing.T) {
	sample := Sample{Relationships: []Relationship{
		rel("document:roadmap", "viewer", "user:vic"),
		rel("folder:b-private", "viewer", "user:erin"),
		rel("folder:c-private", "viewer", "user:dana"),
		rel("folder:public", "viewer", "user:*"),
		rel("team:t", "member", "user:tess"),
		rel("document:z-holds-a-folder", "parent", "folder:c-private"),
	}}
	onFolder := &WriteModel{Creates: []*CreationRule{{Creates: "document", On: []OnSpec{{Type: "folder"}}}}}
	foldersOf := func(wm *WriteModel) ([]string, int) {
		states, leftOut := weighedStates(sample, wm)
		if states[0].object != (Object{Type: "document", ID: "roadmap"}) {
			t.Fatalf("the first state is for %s", states[0].object)
		}
		var others []string
		for _, r := range states[0].tuples {
			if r.Resource != states[0].object {
				others = append(others, r.Resource.ID)
			}
		}
		return others, leftOut
	}

	others, leftOut := foldersOf(onFolder)
	if want := []string{"b-private", "public"}; !slices.Equal(others, want) {
		t.Errorf("the state brings %v, want one folder of each shape: %v", others, want)
	}
	if leftOut != 1 {
		t.Errorf("it says %d folders were stood for, want 1", leftOut)
	}

	for name, wm := range map[string]*WriteModel{"no write model": nil, "no creation on an object": {Creates: []*CreationRule{{Creates: "folder"}}}} {
		if others, leftOut := foldersOf(wm); len(others) != 0 || leftOut != 0 {
			t.Errorf("%s: the state brings %v and says %d were stood for", name, others, leftOut)
		}
	}
}

// A store can name an object as a subject and hold no tuple on it, and a creation can start
// from that too. What names it comes along, since nothing else puts it in the state, and
// two such objects of two types have no shape to tell them apart but their type.
func TestAnObjectWithNoTuplesComesAlongByWhatNamesIt(t *testing.T) {
	states, _ := weighedStates(Sample{Relationships: []Relationship{
		rel("document:a", "parent", "folder:f"),
		rel("document:b", "owner", "org:o"),
		rel("document:c", "viewer", "user:vic"),
	}}, &WriteModel{Creates: []*CreationRule{
		{Creates: "document", On: []OnSpec{{Type: "folder"}}},
		{Creates: "document", On: []OnSpec{{Type: "org"}}},
	}})
	state := states[2]
	if state.object.ID != "c" {
		t.Fatalf("the third state is for %s", state.object)
	}
	var subjects []string
	for _, r := range state.tuples {
		subjects = append(subjects, r.Subject.Object.String())
	}
	slices.Sort(subjects)
	if want := []string{"folder:f", "org:o", "user:vic"}; !slices.Equal(subjects, want) {
		t.Errorf("the state names %v, want %v", subjects, want)
	}
}

// A creation on an existing folder gives the coalition what that folder grants, so which
// folder matters: the first one by name grants nothing, the public one everybody. What the
// states find has to be what a search of the whole store finds.
func TestAWitnessThroughAnObjectACreationStartsFromIsFound(t *testing.T) {
	folder := &Type{
		Name: "folder",
		Relations: []*Relation{
			{Name: "parent", Allowed: []Allowed{{Type: "folder"}}},
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}, {Type: "user", Wildcard: true}}},
		},
		Permissions: []*Permission{{Name: "view", Expr: Union{Children: []Expr{Computed{Name: "viewer"}, Arrow{Through: "parent", Target: "view"}}}}},
	}
	document := &Type{
		Name:        "document",
		Relations:   []*Relation{{Name: "parent", Allowed: []Allowed{{Type: "folder"}}}, {Name: "owner", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "read", Expr: Union{Children: []Expr{Computed{Name: "owner"}, Arrow{Through: "parent", Target: "view"}}}}},
	}
	model, err := NewModel([]*Type{{Name: "user"}, folder, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wm := &WriteModel{
		SchemaVersion: 1,
		Kind:          "relationship-writes",
		Writes: []*WriteRule{
			{Resource: "document", Relation: "parent", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}},
		},
		Creates: []*CreationRule{{
			Creates: "folder",
			Gate:    Gate{Anyone: true},
			On:      []OnSpec{{Type: "folder", Gate: Gate{Anyone: true}}},
			Writes:  []CreationWrite{{Resource: CreatedPlaceholder, Relation: "parent", Subject: "folder"}},
		}},
	}
	sample := Sample{
		Model: model,
		Relationships: []Relationship{
			rel("document:roadmap", "owner", "user:zed"),
			rel("folder:a-private", "viewer", "user:olivia"),
			rel("folder:public", "viewer", "user:*"),
		},
		Now: time.Unix(0, 0),
	}

	attacker := Object{Type: "user", ID: "attacker"}
	whole, err := Escalations(model, wm, nil, sample.Relationships, []Object{attacker}, Options{Now: sample.Now})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(whole, func(e Escalation) bool { return e.Object.ID == "roadmap" && e.Permission == "read" }) {
		t.Fatalf("the search of the whole store does not raise read on the document: %v", whole)
	}
	matches, _ := RunWithLimits(sample, wm)
	if !slices.ContainsFunc(matches, func(m Match) bool {
		return m.Raise != nil && m.Raise.Type == "document" && m.Raise.Permission == "read"
	}) {
		t.Error("the search of the whole store raises read on the document, and the report does not")
	}

	// A second private folder has its shape, so the first stands for it, and the run says so.
	sample.Relationships = append(sample.Relationships, rel("folder:b-private", "viewer", "user:erin"))
	if _, limits := RunWithLimits(sample, wm); limits.StartsLeftOut != 1 {
		t.Errorf("the run says %d folders were stood for, want 1", limits.StartsLeftOut)
	}
}

// A state's tuples keep the order the sample has them in, and two runs build the same
// states, since a report and a graph are diffed.
func TestStatesAreTheSameOnEveryRun(t *testing.T) {
	sample := Sample{Relationships: []Relationship{
		rel("document:b", "viewer", "user:vic"),
		rel("document:a", "viewer", "user:erin"),
		rel("team:x", "member", "user:dana"),
		rel("document:a", "editor", "user:dana"),
	}}
	first, _ := weighedStates(sample, nil)
	for range 20 {
		again, _ := weighedStates(sample, nil)
		if len(again) != len(first) {
			t.Fatalf("%d states, then %d", len(first), len(again))
		}
		for i := range first {
			if first[i].object != again[i].object || !slices.Equal(tupleKeys(first[i].tuples), tupleKeys(again[i].tuples)) {
				t.Fatalf("two runs differ on state %d: %v and %v", i, first[i], again[i])
			}
		}
	}
	if got := first[0].object.String(); got != "document:a" {
		t.Errorf("the first state is for %s, the objects are sorted", got)
	}
}

func tupleKeys(tuples []Relationship) []string {
	out := make([]string, 0, len(tuples))
	for _, r := range tuples {
		out = append(out, tupleKey(r))
	}
	return out
}

// Two states that differ in nothing but names have one shape, so the second need not be
// weighed. Anything a check reads tells them apart: a relation, a subject of another
// type, a caveat, what the caveat carries.
func TestShapeOfTellsApartWhatAnswersACheck(t *testing.T) {
	withContext := func(value string) Relationship {
		r := rel("document:a", "viewer", "user:vic")
		r.Caveat = &CaveatUse{Name: "held", Context: map[string]any{"limit": value}}
		return r
	}
	base := []Relationship{rel("document:a", "viewer", "user:vic")}
	tests := []struct {
		name  string
		other []Relationship
		same  bool
	}{
		{name: "other names", other: []Relationship{rel("document:b", "viewer", "user:erin")}, same: true},
		{name: "another relation", other: []Relationship{rel("document:a", "editor", "user:vic")}},
		{name: "another type of subject", other: []Relationship{rel("document:a", "viewer", "team:vic")}},
		{name: "a wildcard", other: []Relationship{rel("document:a", "viewer", "user:*")}},
		{name: "a caveat", other: []Relationship{withContext("1")}},
		{name: "one more tuple", other: append(slices.Clone(base), rel("document:a", "editor", "user:vic"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shapeOf(tt.other) == shapeOf(base); got != tt.same {
				t.Errorf("same shape = %v, want %v:\n%s\n%s", got, tt.same, shapeOf(tt.other), shapeOf(base))
			}
		})
	}
	if shapeOf([]Relationship{withContext("1")}) == shapeOf([]Relationship{withContext("2")}) {
		t.Error("two contexts read as one shape, and a condition can answer differently on each")
	}
	repeat := []Relationship{rel("document:a", "viewer", "user:vic"), rel("document:b", "viewer", "user:vic")}
	apart := []Relationship{rel("document:a", "viewer", "user:vic"), rel("document:b", "viewer", "user:erin")}
	if shapeOf(repeat) == shapeOf(apart) {
		t.Error("one subject twice reads like two subjects, and a write for it reaches both objects")
	}
}

// The analysis of a store has to finish on the store. With an open rule the search
// weighs every sequence of writes, and over all the objects of a store it does not end;
// a run over objects of a few shapes takes a moment however many there are. The findings
// are the ones a single document of each shape gives.
func TestTheAnalysisFinishesOnAStore(t *testing.T) {
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Holds: "view"}, Subject: SubjectSpec{Self: true}},
	}}
	store := func(documents int) Sample {
		s := Sample{Now: time.Unix(0, 0)}
		for i := range documents {
			s.Relationships = append(s.Relationships, rel(fmt.Sprintf("document:d%d", i), "owner", fmt.Sprintf("user:u%d", i)))
		}
		return s
	}
	model := documents(t)
	subjects := func(s Sample) map[string]bool {
		s.Model = model
		out := map[string]bool{}
		for _, m := range Run(s, wm) {
			out[m.PatternID+" "+m.Subject] = true
		}
		return out
	}

	one := subjects(store(1))
	if len(one) == 0 {
		t.Fatal("no finding on one document")
	}
	done := make(chan map[string]bool, 1)
	go func() { done <- subjects(store(500)) }()
	select {
	case many := <-done:
		if !maps.Equal(many, one) {
			t.Errorf("500 documents of one shape report\n%v\nand one reports\n%v", many, one)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the analysis of 500 documents has not finished after a minute")
	}
}

// Some raises only a real subject shows. One who is both a viewer and banned deletes the
// ban, and no account the analysis supposes holds both, so a report that read the supposed
// attacker alone would miss it. The report and the graph say the same.
func TestTheReportSaysWhatARealSubjectCanRaise(t *testing.T) {
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "banned", Operations: []Operation{Delete}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}},
	}}
	sample := Sample{
		Model: bannable(t),
		Relationships: []Relationship{
			rel("document:roadmap", "viewer", "user:mallory"),
			rel("document:roadmap", "banned", "user:mallory"),
		},
		Now: time.Unix(0, 0),
	}
	matches := Run(sample, wm)
	if !slices.ContainsFunc(matches, func(m Match) bool {
		return m.PatternID == "PTD-ZAN-002" && m.Raise != nil && m.Raise.Permission == "access"
	}) {
		t.Errorf("the report does not say the banned viewer can lift the ban: %+v", matches)
	}

	// Told once, however many subjects show it.
	sample.Relationships = append(sample.Relationships,
		rel("document:roadmap", "viewer", "user:trudy"),
		rel("document:roadmap", "banned", "user:trudy"))
	again := Run(sample, wm)
	if len(again) != len(matches) {
		t.Errorf("a second subject that shows the same raise adds a finding: %d, then %d", len(matches), len(again))
	}
}

// A search stopped at its limit gives what it found, and says it stopped. Every witness it
// gives still raises the permission, so a limit costs coverage and never invents a finding.
func TestASearchStoppedAtItsLimitHoldsWhatItFound(t *testing.T) {
	folder := &Type{
		Name:        "folder",
		Relations:   []*Relation{{Name: "viewer", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "view", Expr: Computed{Name: "viewer"}}},
	}
	model, err := NewModel([]*Type{{Name: "user"}, folder}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var tuples []Relationship
	for i := range 12 {
		tuples = append(tuples, rel(fmt.Sprintf("folder:f%d", i), "viewer", "user:olivia"))
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "folder", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}}
	mallory := Object{Type: "user", ID: "mallory"}

	whole, err := Escalations(model, wm, nil, tuples, []Object{mallory}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatal(err)
	}
	cut := 0
	stopped, err := Escalations(model, wm, nil, tuples, []Object{mallory}, Options{Now: time.Unix(0, 0), maxStates: 5, cut: &cut})
	if err != nil {
		t.Fatal(err)
	}
	if cut != 1 {
		t.Errorf("the search stopped %d times, want 1", cut)
	}
	if len(stopped) == 0 || len(stopped) > len(whole) {
		t.Errorf("the stopped search found %d of %d", len(stopped), len(whole))
	}
	for _, esc := range stopped {
		checker := NewChecker(model, append(slices.Clone(tuples), esc.Writes[len(esc.Writes)-1].Relationship), nil, time.Unix(0, 0))
		got, err := checker.Check(esc.Object, esc.Permission, Subject{Object: mallory}, nil)
		if err != nil || got.Level != Yes {
			t.Errorf("a witness of the stopped search does not raise %s on %s: %v, %v", esc.Permission, esc.Object, got.Level, err)
		}
	}

	cut = 0
	if _, err := Escalations(model, wm, nil, tuples, []Object{mallory}, Options{Now: time.Unix(0, 0), maxStates: 1 << 30, cut: &cut}); err != nil {
		t.Fatal(err)
	}
	if cut != 0 {
		t.Errorf("a search under its limit says it stopped %d times", cut)
	}
}

// The work on what real subjects can raise has a limit, spent on the smallest states, and
// what is left out is counted so the graph does not read as complete.
func TestTheWorkOnSubjectsIsCounted(t *testing.T) {
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Holds: "view"}, Subject: SubjectSpec{Self: true}},
	}}
	sample := Sample{
		Model: documents(t),
		Relationships: []Relationship{
			rel("document:big", "viewer", "user:a"),
			rel("document:big", "viewer", "user:b"),
			rel("document:big", "viewer", "user:c"),
			rel("document:small", "viewer", "user:d"),
		},
		Now: time.Unix(0, 0),
	}

	all, limits := subjectEscalations(sample, wm, maxSubjectWork)
	if limits.SubjectsLeftOut != 0 {
		t.Errorf("under the limit, %d subjects are left out", limits.SubjectsLeftOut)
	}
	some, limits := subjectEscalations(sample, wm, 1)
	if limits.SubjectsLeftOut != 3 {
		t.Errorf("past the limit, %d subjects are left out, want 3", limits.SubjectsLeftOut)
	}
	if len(some) == 0 || len(some) >= len(all) {
		t.Fatalf("past the limit it weighs %d of %d", len(some), len(all))
	}
	for _, f := range some {
		if f.esc.Object.ID != "small" {
			t.Errorf("the limit was not spent on the smallest state first: %s", f.esc.Object)
		}
	}
}

// An object a coalition makes takes no name of the store. If it did, making a folder would
// hand the coalition the folder of that name, its owner written on it, and with the folder
// whatever hangs off it: a raise on the document no write could reach.
func TestACreationDoesNotTakeAnObjectOfTheStore(t *testing.T) {
	folder := &Type{
		Name: "folder",
		Relations: []*Relation{
			{Name: "owner", Allowed: []Allowed{{Type: "user"}}},
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "manage", Expr: Computed{Name: "owner"}},
			{Name: "view", Expr: Computed{Name: "viewer"}},
		},
	}
	document := &Type{
		Name:        "document",
		Relations:   []*Relation{{Name: "parent", Allowed: []Allowed{{Type: "folder"}}}},
		Permissions: []*Permission{{Name: "read", Expr: Arrow{Through: "parent", Target: "view"}}},
	}
	model, err := NewModel([]*Type{{Name: "user"}, folder, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wm := &WriteModel{
		SchemaVersion: 1,
		Kind:          "relationship-writes",
		Writes: []*WriteRule{
			{Resource: "folder", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Holds: "manage"}, Subject: SubjectSpec{Self: true}},
		},
		Creates: []*CreationRule{{
			Creates: "folder",
			Gate:    Gate{Anyone: true},
			Writes:  []CreationWrite{{Resource: CreatedPlaceholder, Relation: "owner", Subject: CreatorPlaceholder}},
		}},
	}
	sample := Sample{Relationships: []Relationship{rel("document:roadmap", "parent", "folder:created-0")}}
	attacker := Object{Type: "user", ID: "attacker"}
	escalations, err := Escalations(model, wm, nil, sample.Relationships, []Object{attacker}, Options{Now: time.Unix(0, 0), taken: namedObjects(sample)})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range escalations {
		t.Errorf("no write opens the store's folder, and the search raises %s on %s", e.Permission, e.Object)
	}
}

// A sample too large to search whole gives what the search found and says it stopped, and
// the report and the graph say the same. A coalition can join any of thirty teams, and that
// is more sets of up to four teams than the limit weighs.
func TestASampleTooLargeToSearchSaysSo(t *testing.T) {
	team := &Type{Name: "team", Relations: []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}}}}}
	document := &Type{
		Name:        "document",
		Relations:   []*Relation{{Name: "viewer", Allowed: []Allowed{{Type: "team", Relation: "member"}}}, {Name: "owner", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "view", Expr: Computed{Name: "viewer"}}},
	}
	model, err := NewModel([]*Type{{Name: "user"}, team, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "team", Relation: "member", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}}
	sample := Sample{Model: model, Relationships: []Relationship{rel("document:roadmap", "owner", "user:vic")}, Now: time.Unix(0, 0)}
	for i := range 30 {
		sample.Relationships = append(sample.Relationships, Relationship{
			Resource: Object{Type: "document", ID: "roadmap"},
			Relation: "viewer",
			Subject:  Subject{Object: Object{Type: "team", ID: fmt.Sprintf("t%d", i)}, Relation: "member"},
		})
	}

	matches, limits := RunWithLimits(sample, wm)
	if limits.SearchesStopped == 0 {
		t.Error("the report does not say the search stopped")
	}
	if _, ofSubjects := subjectEscalations(sample, wm, maxSubjectWork); ofSubjects.SearchesStopped != 1 {
		t.Errorf("the search of the one subject stopped %d times, want 1", ofSubjects.SearchesStopped)
	}
	if !slices.ContainsFunc(matches, func(m Match) bool {
		return m.PatternID == "PTD-ZAN-005" && m.Raise.Permission == "view"
	}) {
		t.Errorf("the stopped search lost the raise it found: %+v", matches)
	}
	graphLimits, err := AddEscalations(graph.New(), []GraphInput{{Sample: sample, WriteModel: wm}})
	if err != nil {
		t.Fatal(err)
	}
	if graphLimits != limits {
		t.Errorf("the graph says %+v and the report %+v", graphLimits, limits)
	}
}

// The work on what an account with nothing can raise has a limit, for a store of many shapes
// that would take hours. It goes to the smallest state first, what it leaves out is counted,
// and a position generated from the schema is weighed whatever is left.
func TestTheWorkOnTheSupposedAttackerIsCounted(t *testing.T) {
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}}
	sample := Sample{
		Model: documents(t),
		Relationships: []Relationship{
			rel("document:a-large", "owner", "user:olivia"),
			rel("document:a-large", "editor", "user:erin"),
			rel("document:a-large", "editor", "user:dana"),
			rel("document:b-small", "owner", "user:vic"),
		},
		Now: time.Unix(0, 0),
	}
	objects := func(found []attackerEscalation) []string {
		var out []string
		for _, f := range found {
			if !f.position {
				out = append(out, f.esc.Object.ID)
			}
		}
		slices.Sort(out)
		return slices.Compact(out)
	}

	all, limits := classifiedWithin(sample, wm, maxSupposedWork)
	if limits.SupposedLeftOut != 0 {
		t.Errorf("under the limit it leaves out %d", limits.SupposedLeftOut)
	}
	if got := objects(all); !slices.Equal(got, []string{"b-small"}) {
		t.Errorf("a raise any account can make is shown on %v, want the smallest state", got)
	}

	some, limits := classifiedWithin(sample, wm, 1)
	// The user attacker spends the work on the smaller state and leaves the larger one out.
	// Each type has work of its own, and the team attacker raises nothing, so spends none.
	if limits.SupposedLeftOut != 1 {
		t.Errorf("past the limit it leaves out %d, want 1", limits.SupposedLeftOut)
	}
	if got := objects(some); !slices.Equal(got, []string{"b-small"}) {
		t.Errorf("past the limit it shows %v, want the smallest state", got)
	}

	// What takes holding view shows only from a position, since an account with nothing
	// holds no view on the objects of the store.
	gated := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Holds: "view"}, Subject: SubjectSpec{Self: true}},
	}}
	fromPositions, _ := classifiedWithin(sample, gated, 0)
	if !slices.ContainsFunc(fromPositions, func(f attackerEscalation) bool { return f.position && f.esc.Permission == "edit" }) {
		t.Errorf("with no work left the positions are not weighed: %+v", fromPositions)
	}
}

// A search is part of the work, so a state whose searches are large spends the limit
// faster than one where they are small. Counting only the subjects would let a store of
// many subjects behind an open rule take hours within it.
func TestASearchSpendsTheWork(t *testing.T) {
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Holds: "view"}, Subject: SubjectSpec{Self: true}},
	}}
	sample := Sample{
		Model: documents(t),
		Relationships: []Relationship{
			rel("document:plan", "viewer", "user:a"),
			rel("document:plan", "viewer", "user:b"),
		},
		Now: time.Unix(0, 0),
	}
	// Enough for two subjects if each cost only its two tuples, and the first one's
	// search spends what the second needed.
	if _, limits := subjectEscalations(sample, wm, 4); limits.SubjectsLeftOut != 1 {
		t.Errorf("%d subjects are left out, want 1", limits.SubjectsLeftOut)
	}
}

func TestLimitsSayWhatStoppedShort(t *testing.T) {
	if got := (Limits{}).Lines(); len(got) != 0 {
		t.Errorf("nothing stopped short, and it says %v", got)
	}
	lines := Limits{SearchesStopped: 1, SubjectsLeftOut: 3, HoldingsLeftOut: 2, SupposedLeftOut: 7, StartsLeftOut: 4}.Lines()
	if len(lines) != 5 || !strings.HasPrefix(lines[0], "1 search ") || !strings.HasPrefix(lines[1], "3 questions ") ||
		!strings.HasPrefix(lines[2], "2 objects not asked") || !strings.HasPrefix(lines[3], "7 questions of what an account") ||
		!strings.HasPrefix(lines[4], "4 objects a witness") {
		t.Errorf("Lines = %v", lines)
	}
	if got := (Limits{SearchesStopped: 2}).Lines(); !strings.HasPrefix(got[0], "2 searches ") {
		t.Errorf("Lines = %v", got)
	}
	total := Limits{SearchesStopped: 1}
	total.Add(Limits{SearchesStopped: 2, SubjectsLeftOut: 4, HoldingsLeftOut: 5, SupposedLeftOut: 7, StartsLeftOut: 6})
	if total != (Limits{SearchesStopped: 3, SubjectsLeftOut: 4, HoldingsLeftOut: 5, SupposedLeftOut: 7, StartsLeftOut: 6}) {
		t.Errorf("Add = %+v", total)
	}
}

// What a real subject can raise reaches the objects whose checks name it, and a raise any
// account can make stays with the attacker the analysis supposes, so a store of many
// subjects draws what is theirs and not one edge per subject and object.
func TestASubjectIsWeighedWhereItIsNamed(t *testing.T) {
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Holds: "view"}, Subject: SubjectSpec{Self: true}},
	}}
	got, _ := subjectEscalations(Sample{
		Model: documents(t),
		Relationships: []Relationship{
			rel("document:plan", "viewer", "user:vic"),
			rel("document:roadmap", "owner", "user:olivia"),
		},
		Now: time.Unix(0, 0),
	}, wm, maxSubjectWork)
	var raises []string
	for _, f := range got {
		raises = append(raises, f.attacker.String()+" "+f.esc.Permission+" "+f.esc.Object.String())
	}
	if !slices.Contains(raises, "user:vic edit document:plan") {
		t.Errorf("a viewer who can write itself an editor does not raise edit: %v", raises)
	}
	for _, raise := range raises {
		if strings.Contains(raise, "user:vic") && strings.Contains(raise, "document:roadmap") {
			t.Errorf("a subject raises something on an object no check of which names it: %s", raise)
		}
	}
}

// An object that comes along for a creation to start from brings its subjects into the
// state, and they stay what they are on the object weighed: accounts like any other, and on
// the object that came along too. Whichever object came along would otherwise decide who is
// drawn, and only its subjects would be.
func TestASubjectOfAnObjectLinkedInIsNotWeighedThere(t *testing.T) {
	folder := &Type{
		Name:        "folder",
		Relations:   []*Relation{{Name: "viewer", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "view", Expr: Computed{Name: "viewer"}}},
	}
	document := &Type{
		Name:        "document",
		Relations:   []*Relation{{Name: "viewer", Allowed: []Allowed{{Type: "user"}}}, {Name: "editor", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "edit", Expr: Computed{Name: "editor"}}},
	}
	model, err := NewModel([]*Type{{Name: "user"}, folder, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "folder", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}, Creates: []*CreationRule{{Creates: "document", Gate: Gate{Anyone: true}, On: []OnSpec{{Type: "folder", Gate: Gate{Anyone: true}}}}}}
	got, _ := subjectEscalations(Sample{
		Model: model,
		Relationships: []Relationship{
			rel("folder:shared", "viewer", "user:olivia"),
			rel("document:plan", "viewer", "user:vic"),
		},
		Now: time.Unix(0, 0),
	}, wm, maxSubjectWork)
	var raises []string
	for _, f := range got {
		raises = append(raises, f.attacker.String()+" "+f.esc.Permission+" "+f.esc.Object.String())
	}
	slices.Sort(raises)
	want := []string{"user:vic edit document:plan"}
	if !slices.Equal(raises, want) {
		t.Errorf("subjectEscalations = %v, want %v", raises, want)
	}
}

// What a write can link to comes along like what a creation starts from: a userset it can
// grant to, an object across a relation an arrow walks, one of each shape. A plain subject
// on a relation no arrow walks grants that subject alone, so nothing comes along for it.
func TestAStateBringsWhatAWriteCanLinkTo(t *testing.T) {
	sample := Sample{
		Model: gapModel(t),
		Relationships: []Relationship{
			rel("document:roadmap", "editor", "user:olivia"),
			rel("document:roadmap", "viewer", "user:vic"),
			rel("folder:a", "viewer", "user:erin"),
			rel("folder:b", "viewer", "user:dana"),
			rel("team:design", "member", "user:tess"),
		},
	}
	broughtBy := func(rules ...*WriteRule) []string {
		states, _ := weighedStates(sample, &WriteModel{Writes: rules})
		var others []string
		for _, r := range states[0].tuples {
			if r.Resource != states[0].object {
				others = append(others, r.Resource.String())
			}
		}
		return others
	}
	write := func(relation string, subject SubjectSpec) *WriteRule {
		return &WriteRule{Resource: "document", Relation: relation, Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: subject}
	}
	tests := []struct {
		name     string
		rule     *WriteRule
		expected []string
	}{
		{name: "across an arrow", rule: write("parent", SubjectSpec{Any: true}), expected: []string{"folder:a"}},
		{name: "a userset", rule: write("viewer", SubjectSpec{Types: []string{"team#member"}}), expected: []string{"team:design"}},
		{name: "a plain subject no arrow walks", rule: write("editor", SubjectSpec{Any: true})},
		{name: "the writer itself", rule: write("parent", SubjectSpec{Self: true})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := broughtBy(tt.rule); !slices.Equal(got, tt.expected) {
				t.Errorf("the state brings %v, want %v", got, tt.expected)
			}
		})
	}
}
