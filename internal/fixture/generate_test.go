package fixture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A seed has to be a world, not a hint at one. Somebody rerunning a finding
// months later gets the same documents byte for byte, or the finding is not
// reproducible and the number attached to it means nothing.
func TestGenerateIsReproducible(t *testing.T) {
	first, err := Generate(Small(99))
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	again, err := Generate(Small(99))
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if string(mustMarshal(t, first)) != string(mustMarshal(t, again)) {
		t.Error("the same seed produced two different worlds")
	}

	other, err := Generate(Small(100))
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if string(mustMarshal(t, first)) == string(mustMarshal(t, other)) {
		t.Error("two seeds produced the same world, so the seed decides nothing")
	}
}

// The promises the truth rests on, checked against the documents rather than
// assumed from the code that wrote them.
//
// Every one of these is what makes a planted coordinate true: a principal who
// owns a document is not an escalation, and one who ends up with nothing by
// accident would be an escalation nobody wrote down, counted against the engine
// as an invention when it was a real one.
func TestGenerateKeepsThePromisesTheTruthMakes(t *testing.T) {
	dataset, err := Generate(Medium(7))
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	users := collection(t, dataset, "users")
	projects := collection(t, dataset, "projects")
	documents := collection(t, dataset, "documents")
	tenants := collection(t, dataset, "tenants")

	owners := map[string]bool{}
	for _, document := range documents {
		owners[field(t, document, "owner").(string)] = true
	}
	members := map[string]bool{}
	for _, project := range projects {
		for _, member := range field(t, project, "members").([]string) {
			members[member] = true
		}
	}

	for _, planted := range dataset.Truth.Escalating {
		if owners[planted] {
			t.Errorf("%s was planted holding nothing and owns a document", planted)
		}
		if members[planted] {
			t.Errorf("%s was planted holding nothing and is a member of a project", planted)
		}
		profile := field(t, users[planted], "profile").(map[string]any)
		if department := profile["department"]; department == privilegedDepartment || department == rootDepartment {
			t.Errorf("%s was planted with the department %q, which already grants", planted, department)
		}
	}

	if owners[dataset.Truth.Rooted] {
		t.Errorf("%s stands in the root and owns documents, so what the position is worth cannot be measured",
			dataset.Truth.Rooted)
	}
	root := field(t, projects["p-0000"], "members").([]string)
	if !slices.Equal(root, []string{dataset.Truth.Rooted}) {
		t.Errorf("the root holds %v, want only %s", root, dataset.Truth.Rooted)
	}

	// Everybody who is not a plant and not the one in the root owns something,
	// which is what keeps them out of the truth honestly.
	for name := range users {
		if slices.Contains(dataset.Truth.Escalating, name) || name == dataset.Truth.Rooted {
			continue
		}
		if !owners[name] {
			t.Errorf("%s owns nothing and was not planted, so the truth is incomplete", name)
		}
	}

	for name, tenant := range tenants {
		_, hasPolicy := tenant.(map[string]any)["policy"]
		planted := slices.Contains(dataset.Truth.UncoveredTenants, name)
		if planted == hasPolicy {
			t.Errorf("tenant %s: planted uncovered = %v, has the field = %v", name, planted, hasPolicy)
		}
		if field(t, tenant, "status") != "active" {
			t.Errorf("tenant %s has no status, and the counter case of the check needs one", name)
		}
	}
}

// Every project is a key of the graph, the root included, which is the trap of
// section 5 of the hand written fixture seen from the generator: a hierarchy
// whose root has no entry of its own stops one level short and nobody is told.
//
// And nothing sits deeper than the depth that was asked for, which is the part
// that decides how much a position near the top is worth.
func TestGeneratePutsEveryProjectInTheGraph(t *testing.T) {
	params := Medium(3)
	dataset, err := Generate(params)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	projects := collection(t, dataset, "projects")
	for name := range projects {
		steps := 0
		for at := name; at != "p-0000"; steps++ {
			parent, hasParent := projects[at].(map[string]any)["parent"]
			if !hasParent {
				t.Fatalf("%s never reaches the root", name)
			}
			at = parent.(string)
			if steps > params.Depth {
				t.Fatalf("%s sits more than %d steps below the root", name, params.Depth)
			}
		}
	}

	for name, project := range projects {
		if _, hasMembers := project.(map[string]any)["members"]; !hasMembers {
			t.Errorf("project %s has no members list", name)
		}
		parent, hasParent := project.(map[string]any)["parent"]
		if name == "p-0000" {
			if hasParent {
				t.Error("the root has a parent")
			}
			continue
		}
		if !hasParent {
			t.Errorf("project %s hangs off nothing", name)
			continue
		}
		if _, exists := projects[parent.(string)]; !exists {
			t.Errorf("project %s hangs off %s, which does not exist", name, parent)
		}
	}
}

// A world where the truth would not hold is refused rather than generated, and
// the message says which promise could not be kept.
func TestGenerateRefusesAWorldTheTruthWouldNotFit(t *testing.T) {
	tests := []struct {
		name   string
		params Params
	}{
		{name: "nobody left holding anything", params: Params{Users: 4, Escalations: 3, Projects: 4, Documents: 4, Tenants: 2, Depth: 2}},
		{name: "not enough documents to go round", params: Params{Users: 10, Escalations: 2, Projects: 4, Documents: 3, Tenants: 2, Depth: 2}},
		{name: "every tenant uncovered", params: Params{Users: 10, Escalations: 2, Projects: 4, Documents: 20, Tenants: 2, UncoveredTenants: 2, Depth: 2}},
		{name: "a hierarchy with no levels", params: Params{Users: 10, Escalations: 2, Projects: 4, Documents: 20, Tenants: 2, Depth: 0}},
		{name: "a world too small to hold anything", params: Params{Users: 2, Escalations: 1, Projects: 1, Documents: 1, Tenants: 1, Depth: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Generate(tt.params); err == nil {
				t.Error("Generate() accepted a world where the planted coordinates would not hold")
			}
		})
	}
}

// The documents land on disk the way the analysis reads them: one file per
// collection, in the layout opa eval takes as a -d.
func TestWriteProducesTheCollections(t *testing.T) {
	dataset, err := Generate(Tiny(1))
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	dir := filepath.Join(t.TempDir(), "data")
	if err := dataset.Write(dir); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	for _, name := range []string{"users", "projects", "documents", "tenants"} {
		content, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		var document map[string]any
		if err := json.Unmarshal(content, &document); err != nil {
			t.Errorf("%s.json does not parse: %v", name, err)
		}
		if _, mounted := document[name]; !mounted {
			t.Errorf("%s.json does not hold a %s document, so it would mount in the wrong place", name, name)
		}
	}
}

func mustMarshal(t *testing.T, dataset *Dataset) []byte {
	t.Helper()

	content, err := json.Marshal(dataset)
	if err != nil {
		t.Fatalf("marshalling the dataset: %v", err)
	}
	return content
}

// collection returns one collection of a dataset, by the name it mounts under.
func collection(t *testing.T, dataset *Dataset, name string) map[string]any {
	t.Helper()

	document, held := dataset.Documents[name]
	if !held {
		t.Fatalf("the dataset holds no %s", name)
	}
	inner, isCollection := document[name].(map[string]any)
	if !isCollection {
		t.Fatalf("%s does not hold a collection", name)
	}
	return inner
}

// field returns one field of a document.
func field(t *testing.T, document any, name string) any {
	t.Helper()

	object, isObject := document.(map[string]any)
	if !isObject {
		t.Fatalf("expected a document, got %T", document)
	}
	value, held := object[name]
	if !held {
		t.Fatalf("the document has no %s", name)
	}
	return value
}
