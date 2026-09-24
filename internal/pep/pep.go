// Package pep reads the declarations of enforcement points: which decisions a
// policy engine is asked by a given product, and who puts each part of the
// request there.
//
// A policy reads input.session.teams and cannot say where the teams came from.
// The enforcement point that builds the request can: Spacelift copies the names
// of the GitHub teams of the user, and the MCP Gateway of Kuadrant writes the
// name of the tool a client called into a header. Whether a check on the
// request can be met by whoever sends it, or by whoever can make an issuer say
// something, rests on that, and only the product says which. So it is declared,
// once per product, in pep-registry, with where each fact was read.
package pep

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/saluc28/petard/internal/writemodel"
	pepregistry "github.com/saluc28/petard/pep-registry"
)

// SchemaVersion is the version of the format this package reads.
const SchemaVersion = 1

// ErrInvalid is returned for a declaration that does not hold together.
var ErrInvalid = errors.New("pep: invalid declaration")

// Side is what a decision answering yes does to the request.
type Side string

const (
	// SideGrants is a decision the enforcement point lets the request through
	// on.
	SideGrants Side = "grants"

	// SideDenies is a decision the enforcement point refuses the request on
	// when it holds or collects anything.
	SideDenies Side = "denies"
)

// SetBy says who puts a part of the request there.
type SetBy string

const (
	// SetByCaller is a part whoever sends the request chooses: the body, the
	// headers, the name of the tool an MCP client calls.
	SetByCaller SetBy = "caller"

	// SetByEnforcementPoint is a part the enforcement point computes from its
	// own state or observes itself: the time, the address the connection came
	// from, a flag it looks up.
	SetByEnforcementPoint SetBy = "enforcement-point"

	// SetByIssuer is a part the enforcement point copies from somebody it
	// trusts to say it: the claims of a token, the teams of an identity
	// provider, an identity a certificate proved. The issuer vouches for it,
	// and what the issuer lets people choose, they choose.
	SetByIssuer SetBy = "issuer"
)

// Identifier says what kind of value an issuer puts in a part of the request,
// when that part names somebody or a group of them.
type Identifier string

const (
	// IdentifierName is a name somebody picks: a team called "DevOps", a
	// username. Whoever can create or rename the thing it names can make the
	// issuer say it, and a name let go can be taken by somebody else.
	IdentifierName Identifier = "name"

	// IdentifierID is a value the issuer assigns and nobody picks, never given
	// to anything else.
	IdentifierID Identifier = "id"
)

// EnforcementPoint is one product that asks a policy engine for decisions.
type EnforcementPoint struct {
	// File is where the declaration was read from, which is how a report
	// sends a reader to it.
	File string `yaml:"-"`

	SchemaVersion int    `yaml:"schema_version"`
	ID            string `yaml:"id"`
	Title         string `yaml:"title"`
	Engine        string `yaml:"engine"`

	// Source says what the declaration was verified against: the source code
	// at a tag, or the documentation of a product whose source is closed.
	Source Source `yaml:"source"`

	// Decisions are the rules the product asks for, by name, and what each
	// answering yes does.
	Decisions []Decision `yaml:"decisions"`

	// Subject is the part of the request that names who is asking.
	Subject string `yaml:"subject"`

	// Fields are the parts of the request and who puts each there. The first
	// entry that covers a part is the one that answers for it, so the more
	// specific entries come first.
	Fields []Field `yaml:"fields"`
}

// Source is what a declaration was read from.
type Source struct {
	// Kind is "source" or "documentation".
	Kind string `yaml:"kind"`
	Note string `yaml:"note"`
}

// Decision is one rule the product asks for.
type Decision struct {
	// Rule is the name of the rule, in whichever package the policy declares:
	// the product asks for it by that name.
	Rule string `yaml:"rule"`
	Side Side   `yaml:"side"`
	Note string `yaml:"note"`
}

// Field is one part of the request.
type Field struct {
	// Path is the part, in the notation of the write model:
	// input.session.teams[_], input.request.headers["x-mcp-toolname"],
	// input.auth.identity.* for everything below.
	Path string `yaml:"path"`

	SetBy SetBy `yaml:"set_by"`

	// Issuer names who vouches for the value, when SetBy is SetByIssuer.
	Issuer string `yaml:"issuer"`

	// Identifier is the kind of value the issuer puts there, when it names
	// somebody, and empty when it does not or when nothing verified says.
	Identifier Identifier `yaml:"identifier"`

	Note string `yaml:"note"`

	// Evidence is where each claim of the entry was read: a file and a line at
	// a tag, or a page of documentation and the day it was consulted.
	Evidence []string `yaml:"evidence"`

	path writemodel.Path
}

// Load reads a declaration from a file.
func Load(path string) (*EnforcementPoint, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pep: reading %s: %w", path, err)
	}
	return parse(filepath.ToSlash(path), content)
}

// Find reads the declaration with the given id from a filesystem holding the
// registry, one file per enforcement point named after its id, and files it
// where the registry sits in a checkout.
func Find(fsys fs.FS, id string) (*EnforcementPoint, error) {
	content, err := fs.ReadFile(fsys, id+".yaml")
	if err != nil {
		return nil, fmt.Errorf("pep: no enforcement point %q in the registry: %w", id, err)
	}
	return parse(pepregistry.Dir+"/"+id+".yaml", content)
}

// Resolve reads a declaration named on a command line: the id of one in the
// registry, or the path to a file of somebody's own.
func Resolve(fsys fs.FS, named string) (*EnforcementPoint, error) {
	if strings.HasSuffix(named, ".yaml") || strings.HasSuffix(named, ".yml") {
		return Load(named)
	}
	return Find(fsys, named)
}

// List reads every declaration of a registry, in the order the files sort.
func List(fsys fs.FS) ([]*EnforcementPoint, error) {
	files, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, fmt.Errorf("pep: listing the registry: %w", err)
	}
	points := make([]*EnforcementPoint, 0, len(files))
	for _, file := range files {
		content, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, fmt.Errorf("pep: reading %s: %w", file, err)
		}
		point, err := parse(pepregistry.Dir+"/"+file, content)
		if err != nil {
			return nil, err
		}
		points = append(points, point)
	}
	return points, nil
}

func parse(file string, content []byte) (*EnforcementPoint, error) {
	var point EnforcementPoint
	if err := yaml.Unmarshal(content, &point); err != nil {
		return nil, fmt.Errorf("pep: parsing %s: %w", file, err)
	}
	point.File = file
	if err := point.validate(); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalid, file, err)
	}
	return &point, nil
}

func (p *EnforcementPoint) validate() error {
	if p.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema version %d, this reads %d", p.SchemaVersion, SchemaVersion)
	}
	if p.ID == "" {
		return errors.New("no id")
	}
	if len(p.Decisions) == 0 {
		return errors.New("no decision: an enforcement point that asks for nothing declares nothing")
	}
	for _, decision := range p.Decisions {
		if decision.Rule == "" || strings.ContainsAny(decision.Rule, "./") {
			return fmt.Errorf("decision %q is not the name of a rule", decision.Rule)
		}
		if decision.Side != SideGrants && decision.Side != SideDenies {
			return fmt.Errorf("decision %s: side %q is neither %s nor %s", decision.Rule, decision.Side, SideGrants, SideDenies)
		}
	}
	if p.Subject != "" && !strings.HasPrefix(p.Subject, "input.") {
		return fmt.Errorf("subject %q is not a part of the request", p.Subject)
	}

	for i := range p.Fields {
		field := &p.Fields[i]
		if !strings.HasPrefix(field.Path, "input.") {
			return fmt.Errorf("field %q is not a part of the request", field.Path)
		}
		parsed, err := writemodel.ParsePath(field.Path)
		if err != nil {
			return err
		}
		field.path = parsed

		switch field.SetBy {
		case SetByCaller, SetByEnforcementPoint:
			if field.Issuer != "" || field.Identifier != "" {
				return fmt.Errorf("field %s: an issuer and an identifier belong to a part an issuer sets", field.Path)
			}
		case SetByIssuer:
			if field.Issuer == "" {
				return fmt.Errorf("field %s: set by an issuer, and the issuer is not named", field.Path)
			}
			if field.Identifier != "" && field.Identifier != IdentifierName && field.Identifier != IdentifierID {
				return fmt.Errorf("field %s: identifier %q is neither %s nor %s", field.Path, field.Identifier, IdentifierName, IdentifierID)
			}
		default:
			return fmt.Errorf("field %s: set_by %q is none of %s, %s, %s", field.Path, field.SetBy, SetByCaller, SetByEnforcementPoint, SetByIssuer)
		}
		if len(field.Evidence) == 0 {
			return fmt.Errorf("field %s: no evidence, and every field says where it was read", field.Path)
		}
	}
	return nil
}

// FieldFor returns the declaration that answers for a part of the request, the
// first one that covers it.
func (p *EnforcementPoint) FieldFor(path string) (Field, bool) {
	if p == nil {
		return Field{}, false
	}
	parsed, err := writemodel.ParsePath(path)
	if err != nil {
		return Field{}, false
	}
	for _, field := range p.Fields {
		if field.path.Matches(parsed) {
			return field, true
		}
	}
	return Field{}, false
}

// Entrypoints turns the decisions into the ones a bundle holds, given how the
// bundle answers which of its rules have a name, and splits them by side.
func (p *EnforcementPoint) Entrypoints(rulesNamed func(string) []string) (grants, denies []string) {
	for _, decision := range p.Decisions {
		for _, rule := range rulesNamed(decision.Rule) {
			if decision.Side == SideDenies {
				denies = append(denies, rule)
				continue
			}
			grants = append(grants, rule)
		}
	}
	return grants, denies
}
