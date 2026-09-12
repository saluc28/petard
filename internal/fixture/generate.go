// Package fixture generates the data an analysis is measured against, with the
// facts about it written down.
//
// The hand written bundle answers one question, "does the engine find that
// one?", and it is the wrong question to stop at: a pattern that reports
// everything finds that one too. What separates a tool from a noise generator
// is how much it invents, and nothing invented can be counted without knowing
// what was true to begin with.
//
// So the generator emits documents and, next to them, what holds about them:
// which principals hold nothing and could write their way in, which tenants the
// MFA check does not cover. Those are the coordinates a run is scored against,
// and they are true by construction rather than by inspection.
//
// The documents have the shape the fixture policy reads, because the policy is
// what turns data into decisions: generating a world the policy cannot read
// would measure nothing. The other half of the risk, a world invented by us,
// is covered on the policy side by running the engine over policies other
// people wrote.
package fixture

import (
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
)

// Params say how much data to make, and how much of it is a plant.
//
// The sizes below are the ones to reach for. These fields exist because the
// number that stresses partial evaluation is the cardinality of the data, and
// choosing it is the whole point of generating instead of collecting.
type Params struct {
	// Seed fixes the world. Two runs with the same seed produce the same
	// documents, byte for byte, which is what lets a finding be reproduced by
	// somebody who was not there when it was found.
	Seed uint64

	Tenants   int
	Users     int
	Projects  int
	Documents int

	// Depth is how many levels the project hierarchy has below its root.
	Depth int

	// MemberDensity is the share of projects that carry members, between 0 and
	// 1. It is what makes a hierarchy sparse or crowded, and a sparse one is
	// where a position high up is worth the most.
	MemberDensity float64

	// Escalations is K: how many principals are planted holding nothing at all,
	// so that writing the one field they control is their way in. They are the
	// coordinates recall is measured against.
	Escalations int

	// UncoveredTenants is how many tenants are planted without the field the
	// MFA check reads, which is the same absence the fixture holds once.
	UncoveredTenants int
}

// The four sizes. Small is for tests that run on every change, medium is the
// one the definition of done names, and large is where the bounds of section
// 6.4 start to matter rather than being defaults nobody has pushed on.
func Tiny(seed uint64) Params {
	return Params{Seed: seed, Tenants: 3, Users: 6, Projects: 4, Documents: 12,
		Depth: 2, MemberDensity: 0.5, Escalations: 1, UncoveredTenants: 1}
}

func Small(seed uint64) Params {
	return Params{Seed: seed, Tenants: 6, Users: 16, Projects: 12, Documents: 40,
		Depth: 3, MemberDensity: 0.4, Escalations: 3, UncoveredTenants: 2}
}

func Medium(seed uint64) Params {
	return Params{Seed: seed, Tenants: 12, Users: 40, Projects: 30, Documents: 120,
		Depth: 4, MemberDensity: 0.35, Escalations: 6, UncoveredTenants: 4}
}

func Large(seed uint64) Params {
	return Params{Seed: seed, Tenants: 30, Users: 120, Projects: 80, Documents: 500,
		Depth: 5, MemberDensity: 0.3, Escalations: 15, UncoveredTenants: 9}
}

// Truth is what holds about a generated world, by construction.
//
// It is not a prediction of what the engine will report: it is what is the case,
// and the gap between the two is the measurement. A principal listed here that
// the engine misses is a false negative; one the engine reports that is not
// here is a false positive.
type Truth struct {
	// Escalating are the principals who get nothing out of the decision as the
	// data stands, and whose one writable field is a way into the hierarchy.
	Escalating []string

	// UncoveredTenants are the tenants where the MFA check does not apply,
	// because the field it reads is not there.
	UncoveredTenants []string

	// Rooted is the principal planted in the root of the hierarchy: the
	// position worth taking, and the far end of every escalation.
	Rooted string
}

// Dataset is a generated world: the documents, and what is true about them.
type Dataset struct {
	Params    Params
	Truth     Truth
	Documents map[string]map[string]any
}

// Two departments the generator keeps for itself, because the fixture policy
// gives them meaning: one grants outright, and one is what membership in the
// root is derived from. Nobody is generated holding either.
const (
	privilegedDepartment = "security"
	rootDepartment       = "platform"
)

// Generate builds a world and says what holds in it.
func Generate(p Params) (*Dataset, error) {
	if err := p.check(); err != nil {
		return nil, err
	}

	// Two streams from one seed, so that the same Params always produce the
	// same world however the code below is reordered later.
	random := rand.New(rand.NewPCG(p.Seed, p.Seed^0x9e3779b97f4a7c15))

	tenants, uncovered := generateTenants(p)
	projects, leaves := generateProjects(p, random)
	users, holders, escalating, rooted := generateUsers(p, random)
	assignMembers(p, random, projects, holders, rooted)
	documents := generateDocuments(p, random, leaves, holders)

	return &Dataset{
		Params: p,
		Truth: Truth{
			Escalating:       escalating,
			UncoveredTenants: uncovered,
			Rooted:           rooted,
		},
		Documents: map[string]map[string]any{
			"tenants":   {"tenants": tenants},
			"projects":  {"projects": projects},
			"users":     {"users": users},
			"documents": {"documents": documents},
		},
	}, nil
}

// check refuses the combinations that would make the truth untrue.
//
// The plants only hold if the rest of the world is dense enough to give
// everybody else a way in: a principal who ends up with nothing by accident is
// a real escalation the truth does not list, and it would be counted as a false
// positive of the engine rather than as a defect of the generator.
func (p Params) check() error {
	// One principal stands in the root and owns nothing, so it is neither a
	// plant nor a holder.
	holders := p.Users - p.Escalations - 1
	switch {
	case p.Users < 3 || p.Projects < 2 || p.Documents < 1 || p.Tenants < 1:
		return fmt.Errorf("fixture: a world needs at least three users, two projects, a document and a tenant")
	case p.Escalations < 1 || holders < 1:
		return fmt.Errorf("fixture: %d escalations out of %d users leaves nobody holding anything, once one of them stands in the root",
			p.Escalations, p.Users)
	case p.Documents < holders:
		return fmt.Errorf("fixture: %d documents cannot give one each to %d principals, and a principal with none is an escalation nobody planted",
			p.Documents, holders)
	case p.UncoveredTenants >= p.Tenants:
		return fmt.Errorf("fixture: %d uncovered tenants out of %d leaves no covered one, and the counter case would be gone",
			p.UncoveredTenants, p.Tenants)
	case p.Depth < 1:
		return fmt.Errorf("fixture: a hierarchy with no level below the root propagates nothing")
	}
	return nil
}

// generateTenants makes the tenants, some of them without the field the MFA
// check reads. The status is there for all of them: it is the counter case, and
// a world where both checks have holes would not tell them apart.
func generateTenants(p Params) (map[string]any, []string) {
	tenants := make(map[string]any, p.Tenants)
	var uncovered []string

	for i := range p.Tenants {
		name := fmt.Sprintf("t-%04d", i)
		tenant := map[string]any{"status": "active"}
		if i < p.UncoveredTenants {
			uncovered = append(uncovered, name)
		} else {
			tenant["policy"] = map[string]any{"require_mfa": true}
		}
		tenants[name] = tenant
	}
	slices.Sort(uncovered)
	return tenants, uncovered
}

// generateProjects builds the hierarchy and returns the projects that hold no
// child, which are where documents can live.
//
// Every project is a key of the graph, root included, and the root gets an
// empty parent list rather than no entry: it is the trap of section 5 of the
// fixture, and a generator that walked into it would produce a world where the
// hierarchy quietly stops one level short.
func generateProjects(p Params, random *rand.Rand) (map[string]any, []string) {
	// levels[i] holds the projects sitting i steps below the root, so that a
	// new one is only ever hung off a level that still has room underneath it
	// and the hierarchy never grows past Depth.
	levels := [][]string{{"p-0000"}}

	projects := map[string]any{
		"p-0000": map[string]any{"department": rootDepartment, "members": []string{}},
	}
	parents := map[string]bool{}

	for i := 1; i < p.Projects; i++ {
		name := fmt.Sprintf("p-%04d", i)

		above := random.IntN(min(len(levels), p.Depth))
		parent := levels[above][random.IntN(len(levels[above]))]
		projects[name] = map[string]any{"parent": parent, "members": []string{}}
		parents[parent] = true

		if at := above + 1; at == len(levels) {
			levels = append(levels, []string{name})
		} else {
			levels[at] = append(levels[at], name)
		}
	}

	var leaves []string
	for name := range projects {
		if !parents[name] {
			leaves = append(leaves, name)
		}
	}
	slices.Sort(leaves)
	return projects, leaves
}

// generateUsers makes the principals in three kinds: the ones planted holding
// nothing, the one standing in the root, and the ones who own documents.
//
// The one in the root owns nothing of its own, and that is deliberate rather
// than tidy: a position is worth measuring only when what it reaches comes from
// the hierarchy and not from what its holder was given directly. It is what
// makes dave dave in the hand written fixture.
func generateUsers(p Params, random *rand.Rand) (users map[string]any, holders, escalating []string, rooted string) {
	users = make(map[string]any, p.Users)

	for i := range p.Users {
		name := fmt.Sprintf("u-%04d", i)
		// A department nobody shares with a project and which grants nothing:
		// the plants have to be able to write their way in, not to be already
		// in. Everybody gets the same treatment, so that what a principal holds
		// comes from documents and membership and from nothing else.
		users[name] = map[string]any{
			"tenant":  fmt.Sprintf("t-%04d", random.IntN(p.Tenants)),
			"roles":   []string{"viewer"},
			"profile": map[string]any{"department": fmt.Sprintf("dep-%04d", i)},
		}

		switch {
		case i < p.Escalations:
			escalating = append(escalating, name)
		case i == p.Escalations:
			rooted = name
		default:
			holders = append(holders, name)
		}
	}

	slices.Sort(escalating)
	slices.Sort(holders)
	return users, holders, escalating, rooted
}

// assignMembers puts principals into projects, and one of them into the root.
//
// The one in the root is the position the transitive pattern is meant to find:
// the root holds no document of its own, so what it is worth is entirely what
// hangs below it.
func assignMembers(p Params, random *rand.Rand, projects map[string]any, holders []string, rooted string) {
	for _, name := range slices.Sorted(maps.Keys(projects)) {
		project, _ := projects[name].(map[string]any)
		if name == "p-0000" {
			project["members"] = []string{rooted}
			continue
		}
		if random.Float64() >= p.MemberDensity {
			continue
		}
		project["members"] = []string{holders[random.IntN(len(holders))]}
	}
}

// generateDocuments hands every holder at least one document, then spreads the
// rest.
//
// Every holder owning something is what makes the truth true: the policy grants
// an owner their own document, so nobody outside the plants gets nothing, and a
// principal reported with nothing is the generator's fault rather than the
// engine's.
func generateDocuments(p Params, random *rand.Rand, leaves, holders []string) map[string]any {
	documents := make(map[string]any, p.Documents)
	for i := range p.Documents {
		// The first pass hands one document to each holder in turn, and only
		// then does chance get a say: a holder left with none would be an
		// escalation the truth does not list.
		owner := holders[random.IntN(len(holders))]
		if i < len(holders) {
			owner = holders[i]
		}
		documents[fmt.Sprintf("d-%04d", i)] = map[string]any{
			"project":        leaves[random.IntN(len(leaves))],
			"owner":          owner,
			"classification": "internal",
		}
	}
	return documents
}

// Write puts the documents in a directory, one file per collection, the way the
// hand written fixture is laid out and the way opa eval reads a -d.
func (d *Dataset) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("fixture: making %s: %w", dir, err)
	}

	for _, collection := range slices.Sorted(maps.Keys(d.Documents)) {
		content, err := json.MarshalIndent(d.Documents[collection], "", "  ")
		if err != nil {
			return fmt.Errorf("fixture: writing %s: %w", collection, err)
		}
		path := filepath.Join(dir, collection+".json")
		if err := os.WriteFile(path, append(content, '\n'), 0o600); err != nil {
			return fmt.Errorf("fixture: writing %s: %w", path, err)
		}
	}
	return nil
}
