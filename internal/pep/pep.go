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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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
	// username, what a tool declares about itself. Whoever can create or rename
	// the thing it names can make the issuer say it, and a name let go can be
	// taken by somebody else.
	IdentifierName Identifier = "name"

	// IdentifierID is a value the issuer assigns and nobody picks, never given
	// to anything else.
	IdentifierID Identifier = "id"
)

// Authority says what kind of authority a part of the request carries, for a
// decision that grants a delegated principal more or less of it.
type Authority string

const (
	// AuthorityRequested is the authority a principal asks for, the scopes or
	// the role a delegated agent requests. It is sound only when it is bounded
	// by the authority the delegator holds, which BoundedBy names.
	AuthorityRequested Authority = "requested"

	// AuthorityCeiling is an authority that bounds a requested one: the scopes
	// the delegation edge carries, or the role grant a principal already holds.
	AuthorityCeiling Authority = "ceiling"
)

// Canonicalization is one thing done to a part of the request between the
// decision and the action taken on it, which turns two different values into
// the same one.
type Canonicalization string

const (
	// CanonicalDotSegments collapses the "." and ".." segments of a path, as
	// RFC 3986 removes them from a URL (5.2.4): /do/../admin becomes /admin.
	CanonicalDotSegments Canonicalization = "dot-segments"

	// CanonicalPercentEncoding decodes percent-encoded characters before the
	// value is used, so %2e%2e is read as two dots.
	CanonicalPercentEncoding Canonicalization = "percent-encoding"
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

	// Action and Resource are the parts of the request that name what is asked
	// for, where the product puts them somewhere no field name gives away: the
	// path of a call under input.request.remainder_path. Either may be left
	// out, and with both left out they are recognized.
	Action   string `yaml:"action"`
	Resource string `yaml:"resource"`

	// Fields are the parts of the request and who puts each there. The first
	// entry that covers a part is the one that answers for it, so the more
	// specific entries come first: input.user.note ahead of input.user, when
	// the note is the one field of the user the caller writes.
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

	// Field is the part of what the rule returns that the product reads, for a
	// rule that answers with an object: decision, in {"decision": "allow"}, or
	// status.allowed for one inside another. It is empty when the product reads
	// the whole answer.
	Field string `yaml:"field"`

	// Answers are the values the decision is on its side for, when the product
	// acts on some of the values the rule gives and not on others: allowed and
	// clean, of a verdict that also says blocked and scan. Each is a string, a
	// number or a boolean. Empty for a decision that is on its side whenever it
	// holds.
	Answers []any `yaml:"answers"`

	Note string `yaml:"note"`
}

// fieldPath is a field of an answer the way a declaration writes it: names
// joined by dots.
var fieldPath = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)

// validate checks one decision: a rule by its name, a side, a field written as
// names, and answers that are values a request could be decided on.
func (d Decision) validate() error {
	if d.Rule == "" || strings.ContainsAny(d.Rule, "./") {
		return fmt.Errorf("decision %q is not the name of a rule", d.Rule)
	}
	if d.Side != SideGrants && d.Side != SideDenies {
		return fmt.Errorf("decision %s: side %q is neither %s nor %s", d.Rule, d.Side, SideGrants, SideDenies)
	}
	if d.Field != "" && !fieldPath.MatchString(d.Field) {
		return fmt.Errorf("decision %s: field %q is not a field of what the rule returns, written as names joined by dots", d.Rule, d.Field)
	}
	for _, answer := range d.Answers {
		switch answer.(type) {
		case string, bool, int, int64, uint64, float64:
		default:
			return fmt.Errorf("decision %s: the answer %v is not a string, a number or a boolean", d.Rule, answer)
		}
	}
	return nil
}

// entrypoints spells the decision the way the engine takes one, for a rule of a
// bundle that carries its name: the path of the rule, the field the product
// reads when it reads one, and once for each answer when it acts on some of
// them, as data.app.result.decision="allow".
func (d Decision) entrypoints(rule string) []string {
	path := rule
	if d.Field != "" {
		path += "." + d.Field
	}
	if len(d.Answers) == 0 {
		return []string{path}
	}
	spelled := make([]string, 0, len(d.Answers))
	for _, answer := range d.Answers {
		// The answers were checked to be scalars, which always encode.
		written, _ := json.Marshal(answer)
		spelled = append(spelled, path+"="+string(written))
	}
	return spelled
}

// Assumption is one principal that can assume or mint an identity, and how.
//
// It is to an identity what a writer is to a document: who, declared outside the
// policy, can bring themselves into the identity a decision trusts. Who can
// deploy the service account a SPIFFE id names, or obtain the credential an
// agent principal rests on, is a fact about another layer, and the policy that
// grants on the identity cannot see it.
type Assumption struct {
	// Principal is who can become the identity, in the terms of the system
	// around OPA: a role, a group, a service account with the right to deploy.
	Principal string `yaml:"principal"`

	// Via is how the assumption happens, deploying a workload under the service
	// account or issuing its credential. A finding without the how is not
	// actionable.
	Via string `yaml:"via"`

	Note string `yaml:"note"`
}

// Field is one part of the request.
type Field struct {
	// Path is the part, in the notation of the write model:
	// input.session.teams[_], input.request.headers["x-mcp-toolname"]. The
	// entry speaks for the part and for whatever is inside it, so input.user
	// and input.user.* say the same thing, and input.* is everything an earlier
	// entry did not name.
	Path string `yaml:"path"`

	SetBy SetBy `yaml:"set_by"`

	// Issuer names who vouches for the value, when SetBy is SetByIssuer.
	Issuer string `yaml:"issuer"`

	// Identifier is the kind of value the issuer puts there, when it names
	// somebody, and empty when it does not or when nothing verified says.
	Identifier Identifier `yaml:"identifier"`

	// Identity marks a part of the request as a runtime identity a decision may
	// grant on: a workload's SPIFFE id, an agent principal, a process lineage.
	// It belongs on a part an issuer or the enforcement point sets, since a
	// caller who writes an identity forges it, which is a name a decision grants
	// on and not an identity to assume.
	Identity bool `yaml:"identity"`

	// Pinned says the assumption of the identity is constrained, as a credential
	// the enforcement point verifies pins it: nobody below the grant can become
	// it. It belongs only on an identity, and an identity it is set on is left
	// alone rather than reported.
	Pinned bool `yaml:"pinned"`

	// AssumableBy names who can assume or mint the identity in another layer,
	// whoever can deploy the service account it names or obtain its credential.
	// It is the fact no policy contains, the identity-side counterpart of the
	// write model, and it is what turns a grant on an identity into a finding.
	AssumableBy []Assumption `yaml:"assumable_by"`

	// Authority marks a part of the request as an authority a delegated
	// principal carries: a requested authority is what the principal asks for, a
	// ceiling is what bounds it. It is the authority leg of the identity model,
	// beside the Identity above, and a field is one leg or the other, never
	// both.
	Authority Authority `yaml:"authority"`

	// BoundedBy names the ceilings a requested authority must sit under: every
	// element the principal asks for has to be an element of each. It is the
	// fact no policy contains on its own, that the requested authority is a
	// subset of the delegated one, and it belongs only on a requested authority.
	// A ceiling is a part of the request an issuer sets, or a document in the
	// data; with none named the grant is a candidate asking what bounds it.
	BoundedBy []string `yaml:"bounded_by"`

	// CanonicalizedAfterDecision lists what is done to the value after the
	// policy has decided on it and before it is acted on. The decision saw the
	// value as the caller wrote it, and what is served is the value it resolves
	// to: a path handed on to an HTTP client that collapses its dot segments is
	// one. It belongs on a part the caller sets, named whole, and it is what
	// PTD-OPA-012 asks the decision about. A value canonicalized before the
	// policy is asked is not declared here: the decision then sees what is
	// served.
	CanonicalizedAfterDecision []Canonicalization `yaml:"canonicalized_after_decision"`

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
	if err := writemodel.DecodeStrict(content, &point); err != nil {
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
		if err := decision.validate(); err != nil {
			return err
		}
	}
	for _, part := range []struct{ role, path string }{
		{"subject", p.Subject},
		{"action", p.Action},
		{"resource", p.Resource},
	} {
		if part.path != "" && !strings.HasPrefix(part.path, "input.") {
			return fmt.Errorf("%s %q is not a part of the request", part.role, part.path)
		}
	}

	for i := range p.Fields {
		if err := p.Fields[i].validate(); err != nil {
			return err
		}
	}
	return nil
}

// validate checks one field and parses its path, which FieldFor then matches
// against.
func (f *Field) validate() error {
	if !strings.HasPrefix(f.Path, "input.") {
		return fmt.Errorf("field %q is not a part of the request", f.Path)
	}
	parsed, err := writemodel.ParsePath(f.Path)
	if err != nil {
		return err
	}
	f.path = parsed

	switch f.SetBy {
	case SetByCaller, SetByEnforcementPoint:
		if f.Issuer != "" || f.Identifier != "" {
			return fmt.Errorf("field %s: an issuer and an identifier belong to a part an issuer sets", f.Path)
		}
	case SetByIssuer:
		if f.Issuer == "" {
			return fmt.Errorf("field %s: set by an issuer, and the issuer is not named", f.Path)
		}
		if f.Identifier != "" && f.Identifier != IdentifierName && f.Identifier != IdentifierID {
			return fmt.Errorf("field %s: identifier %q is neither %s nor %s", f.Path, f.Identifier, IdentifierName, IdentifierID)
		}
	default:
		return fmt.Errorf("field %s: set_by %q is none of %s, %s, %s", f.Path, f.SetBy, SetByCaller, SetByEnforcementPoint, SetByIssuer)
	}
	if err := f.validateIdentity(); err != nil {
		return err
	}
	if err := f.validateAuthority(); err != nil {
		return err
	}
	if err := f.validateCanonicalization(); err != nil {
		return err
	}
	if len(f.Evidence) == 0 {
		return fmt.Errorf("field %s: no evidence, and every field says where it was read", f.Path)
	}
	return nil
}

// validateAuthority checks the authority side of a field: the kind is one of
// the two, an identity is not also an authority, and only a requested authority
// names the ceilings that bound it, each of them a part of the request or a
// document.
func (f *Field) validateAuthority() error {
	switch f.Authority {
	case "", AuthorityRequested, AuthorityCeiling:
	default:
		return fmt.Errorf("field %s: authority %q is neither %s nor %s", f.Path, f.Authority, AuthorityRequested, AuthorityCeiling)
	}
	if f.Identity && f.Authority != "" {
		return fmt.Errorf("field %s: an identity and an authority are different legs of the model, "+
			"and a part of the request is one or the other, not both", f.Path)
	}
	if len(f.BoundedBy) > 0 && f.Authority != AuthorityRequested {
		return fmt.Errorf("field %s: bounded_by names the ceilings of a requested authority, and this is not declared as one", f.Path)
	}
	for _, ceiling := range f.BoundedBy {
		if !strings.HasPrefix(ceiling, "input.") && !strings.HasPrefix(ceiling, "data.") {
			return fmt.Errorf("field %s: bounded_by %q is neither a part of the request nor a document", f.Path, ceiling)
		}
	}
	return nil
}

// validateCanonicalization checks what a field says happens to its value after
// the decision: each entry is one this reads, the caller sets the part, since a
// value somebody else sets is not one the caller can craft, and the path names
// one part whole, since a request is built with a value written there.
func (f *Field) validateCanonicalization() error {
	if len(f.CanonicalizedAfterDecision) == 0 {
		return nil
	}
	for _, canonicalization := range f.CanonicalizedAfterDecision {
		switch canonicalization {
		case CanonicalDotSegments, CanonicalPercentEncoding:
		default:
			return fmt.Errorf("field %s: canonicalized_after_decision %q is neither %s nor %s",
				f.Path, canonicalization, CanonicalDotSegments, CanonicalPercentEncoding)
		}
	}
	if f.SetBy != SetByCaller {
		return fmt.Errorf("field %s: canonicalized_after_decision is about a value the caller writes, "+
			"and this part is set by %s", f.Path, f.SetBy)
	}
	if !fieldPath.MatchString(strings.TrimPrefix(f.Path, "input.")) {
		return fmt.Errorf("field %s: canonicalized_after_decision is declared on one part of the request "+
			"named whole, as input.request.path", f.Path)
	}
	return nil
}

// validateIdentity checks the identity side of a field: it is an identity only
// where an issuer or the enforcement point sets it, it is pinned or assumable
// and not both, and the two belong to an identity.
func (f *Field) validateIdentity() error {
	if f.Identity && f.SetBy == SetByCaller {
		return fmt.Errorf("field %s: the caller sets it, so an identity there is forged in the request, "+
			"which is a name a decision grants on and not an identity to assume", f.Path)
	}
	if !f.Identity && (f.Pinned || len(f.AssumableBy) > 0) {
		return fmt.Errorf("field %s: pinned and assumable_by describe an identity, and this is not declared as one", f.Path)
	}
	if f.Pinned && len(f.AssumableBy) > 0 {
		return fmt.Errorf("field %s: an identity is pinned or assumable by somebody, not both", f.Path)
	}
	for _, assumption := range f.AssumableBy {
		if assumption.Principal == "" {
			return fmt.Errorf("field %s: an assumable_by entry names no principal", f.Path)
		}
	}
	return nil
}

// FieldFor returns the declaration that answers for a part of the request, the
// first one that covers it.
//
// A declaration covers the part it names and whatever is inside it. Whoever
// puts input.user in the request puts input.user.role there with it, so an
// entry for the first answers for the second, unless an earlier entry names the
// second on its own.
func (p *EnforcementPoint) FieldFor(path string) (Field, bool) {
	if p == nil {
		return Field{}, false
	}
	parsed, err := writemodel.ParsePath(path)
	if err != nil {
		return Field{}, false
	}
	for _, field := range p.Fields {
		if field.path.Matches(cutTo(parsed, field.path)) {
			return field, true
		}
	}
	return Field{}, false
}

// cutTo returns a part of the request cut to the depth a declared path names:
// input.user.role against input.user is input.user, the part an entry has to
// match to answer for what is inside it.
func cutTo(part, declared writemodel.Path) writemodel.Path {
	if len(part.Segments) <= len(declared.Segments) {
		return part
	}
	return writemodel.Path{Segments: part.Segments[:len(declared.Segments)]}
}

// FieldsFor returns the declarations that answer for a part of the request
// which stands for more than one path, and whether they answer for all of it.
//
// input.flags[_] is every key of the flags, and a declaration may speak for
// some of them: input.flags.mfa set by the enforcement point, ahead of
// input.* set by the caller. FieldFor answers with the first declaration that
// covers the path as written, the caller here, which is true of every flag but
// one. This returns each declaration that covers some of what the path stands
// for, in the order they are declared, down to the first that covers it whole.
// Nothing after that one is reached by any of those paths.
//
// For a path with no dynamic segment it is the declaration FieldFor returns.
func (p *EnforcementPoint) FieldsFor(path string) ([]Field, bool) {
	if p == nil {
		return nil, false
	}
	parsed, err := writemodel.ParsePath(path)
	if err != nil {
		return nil, false
	}
	var fields []Field
	for _, field := range p.Fields {
		part := cutTo(parsed, field.path)
		if field.path.Matches(part) {
			return append(fields, field), true
		}
		if field.path.Overlaps(part) {
			fields = append(fields, field)
		}
	}
	return fields, false
}

// Entrypoints turns the decisions into the ones a bundle holds, given how the
// bundle answers which of its rules have a name, and splits them by side. Each
// comes back spelled the way the engine takes an entrypoint, with the field the
// product reads and the answers it acts on when the declaration names them.
func (p *EnforcementPoint) Entrypoints(rulesNamed func(string) []string) (grants, denies []string) {
	for _, decision := range p.Decisions {
		for _, rule := range rulesNamed(decision.Rule) {
			if decision.Side == SideDenies {
				denies = append(denies, decision.entrypoints(rule)...)
				continue
			}
			grants = append(grants, decision.entrypoints(rule)...)
		}
	}
	return grants, denies
}
