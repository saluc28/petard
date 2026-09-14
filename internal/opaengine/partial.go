package opaengine

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/util"
)

// This file asks a decision what is left of it once the data is concrete and
// part of the request is not. It is where the analysis stops being about the
// shape of the policy and starts being about who can do what, today, against
// these documents.

// defaultMaxResiduals bounds how many residual conditions are reported for one
// question.
//
// Partial evaluation expands concrete data into a disjunction, so the count
// grows with the cardinality of the data and not with the size of the policy:
// a decision that reads a collection of ten thousand documents can leave ten
// thousand conditions behind. The value is a declared default and not a derived
// one, like the bounds of the interprocedural walk;
// TestResidualsFollowTheCardinalityOfTheData measures where it starts to cut.
const defaultMaxResiduals = 256

var (
	// ErrNoData is returned when none of the given paths holds a document.
	//
	// It is an error rather than an empty store because the two are not
	// distinguishable afterwards: a decision evaluated against no data comes
	// back as "nothing can make this true", which is exactly what a correct
	// run against real data looks like when the answer is genuinely no.
	ErrNoData = errors.New("opaengine: no data document found")

	// ErrPartial is returned when partial evaluation itself fails. The wrapped
	// error names the decision that was asked about.
	ErrPartial = errors.New("opaengine: partial evaluation failed")
)

// Data are the concrete documents the decisions are evaluated against: the
// users, the roles, the ownerships, the equivalent of the dump a graph of
// Active Directory is built from.
type Data struct {
	store storage.Store

	// Files are the documents that were loaded, with forward slashes on every
	// platform.
	Files []string
}

// Document extensions, the ones OPA reads as data.
var documentExts = []string{".json", ".yaml", ".yml"}

// LoadData reads the JSON and YAML documents under paths into a store. A path
// may be a file or a directory, and directories are walked recursively.
//
// The mount point of a document is the directory it sits in, never its file
// name: a users.json holding {"users": {...}} directly inside the directory
// given here lands on data.users, and one inside a tenants/ subdirectory lands
// on data.tenants.users. That is the rule opa eval follows for -d, verified in
// the OPA sources at v1.19.0 (v1/loader/loader.go:651 and 838), and it is
// replicated rather than reused for one reason:
//
// the loader of OPA splits a path on its first colon, to support the
// prefix:path syntax of the command line (SplitPrefix, v1/loader/loader.go:589).
// On Windows that reads C:\data as the prefix "C" over the path "\data", which
// does not exist, so every absolute path fails with an error that names a
// directory nobody asked for. Passing the paths through an fs.FS instead trades
// the problem for another one, since the walk then stats with backslashes that
// io/fs rejects. Inheriting a defect that depends on the platform, in the step
// that decides which data the whole analysis runs against, is worse than
// carrying these few lines.
//
// Rego files are skipped. The modules come in through Load, which chooses
// between the v1 and the v0 syntax and records which one worked; letting them
// in here too would parse the same policy a second time without that choice.
func LoadData(paths []string) (*Data, error) {
	reader := &dataReader{documents: map[string]any{}}
	for _, path := range paths {
		if err := reader.read(path, nil); err != nil {
			return nil, err
		}
	}
	if len(reader.documents) == 0 {
		return nil, fmt.Errorf("%w under %s", ErrNoData, strings.Join(paths, ", "))
	}

	slices.Sort(reader.files)
	return &Data{store: inmem.NewFromObject(reader.documents), Files: reader.files}, nil
}

// dataReader collects the documents of a load, and the files they came from.
type dataReader struct {
	documents map[string]any
	files     []string
}

// read reads one path under the segments reached so far.
func (r *dataReader) read(path string, at []string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("opaengine: reading %s: %w", path, err)
	}
	if !info.IsDir() {
		return r.document(path, at)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("opaengine: reading %s: %w", path, err)
	}
	for _, entry := range entries {
		child := filepath.Join(path, entry.Name())
		if entry.IsDir() {
			// A subdirectory is a segment of the path its documents land on.
			// The directory given as an argument is not, which is why the
			// segments are only added on the way down.
			if err := r.read(child, append(slices.Clone(at), entry.Name())); err != nil {
				return err
			}
			continue
		}
		if !slices.Contains(documentExts, filepath.Ext(entry.Name())) {
			continue
		}
		if err := r.document(child, at); err != nil {
			return err
		}
	}
	return nil
}

// document reads one file and merges it in.
func (r *dataReader) document(path string, at []string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("opaengine: reading %s: %w", path, err)
	}

	// util.Unmarshal reads JSON and YAML alike, and reads numbers the way the
	// evaluator will: a document loaded with the standard library would compare
	// differently against the same literal in a policy.
	var document any
	if err := util.Unmarshal(content, &document); err != nil {
		return fmt.Errorf("opaengine: parsing %s: %w", path, err)
	}

	object, isObject := document.(map[string]any)
	if !isObject {
		return fmt.Errorf("opaengine: %s holds a %T, and a data document has to be an object", path, document)
	}
	if !mergeInto(r.documents, at, object) {
		return fmt.Errorf("opaengine: %s overwrites a document already loaded under data.%s", path, strings.Join(at, "."))
	}

	r.files = append(r.files, filepath.ToSlash(path))
	return nil
}

// mergeInto merges a document under the given segments, creating them as it
// goes, and reports whether it fits.
//
// Two documents merge when they only meet on objects. Where they meet on a
// value, one would silently replace the other, and which one won would depend
// on the order the files were read in.
func mergeInto(documents map[string]any, at []string, document map[string]any) bool {
	for _, segment := range at {
		next, taken := documents[segment]
		if !taken {
			created := map[string]any{}
			documents[segment] = created
			documents = created
			continue
		}
		object, isObject := next.(map[string]any)
		if !isObject {
			return false
		}
		documents = object
	}

	return mergeDocuments(documents, document)
}

// mergeDocuments folds src into dst, recursing where both hold an object.
func mergeDocuments(dst, src map[string]any) bool {
	for key, value := range src {
		existing, taken := dst[key]
		if !taken {
			dst[key] = value
			continue
		}

		existingObject, existingIsObject := existing.(map[string]any)
		valueObject, valueIsObject := value.(map[string]any)
		if !existingIsObject || !valueIsObject {
			return false
		}
		if !mergeDocuments(existingObject, valueObject) {
			return false
		}
	}
	return true
}

// Presence is what a path finds once the data is concrete: the documents where
// the whole path resolves, and the documents where it stops short.
//
// The keys name the documents, taken from the dynamic segments of the path and
// joined by a dot where the path crosses more than one collection. A path
// written out in full has no dynamic segment and therefore no key: it names one
// document, and the only question about it is whether that document is there.
type Presence struct {
	// Path is the normalized path this answers about.
	Path string

	// Present and Absent are the keys the path resolves for and the keys it
	// does not, sorted.
	Present []string
	Absent  []string
}

// Keys is how many documents the path was tried against.
func (p Presence) Keys() int {
	return len(p.Present) + len(p.Absent)
}

// Presence reports which documents of the collections a path crosses actually
// hold it.
//
// It answers the question no reading of the policy can: a rule that reads
// data.tenants[t].policy.require_mfa applies to the tenants that have the
// field, and is undefined, therefore silent, for the ones that do not. The
// policy is the same for both, and only the data tells them apart.
//
// Absence is the store's own, so a document holding null, or false, is present.
// The difference is the whole point: a value that says no is a check answering,
// and a missing one is a check that never ran.
func (d *Data) Presence(ctx context.Context, path string) (Presence, error) {
	walk, err := d.walk(ctx, path)
	if err != nil {
		return Presence{}, err
	}
	slices.Sort(walk.found.Present)
	slices.Sort(walk.found.Absent)
	return walk.found, nil
}

// walk follows a normalized path over the data, collecting the documents it
// reaches and the documents it does not.
func (d *Data) walk(ctx context.Context, path string) (*presenceWalk, error) {
	ref, err := ast.ParseRef(path)
	if err != nil {
		return nil, fmt.Errorf("opaengine: reading the path %s: %w", path, err)
	}
	if !isDataRooted(ref) {
		return nil, fmt.Errorf("opaengine: %s names no document under data", path)
	}

	txn, err := d.store.NewTransaction(ctx)
	if err != nil {
		return nil, fmt.Errorf("opaengine: opening a read of the data: %w", err)
	}
	defer d.store.Abort(ctx, txn)

	walk := &presenceWalk{ctx: ctx, store: d.store, txn: txn, found: Presence{Path: path}}
	if err := walk.descend(nil, ref[1:], nil); err != nil {
		return nil, err
	}
	return walk, nil
}

// Without returns the same documents with one path taken out wherever it
// resolves, and leaves the data it was called on untouched.
//
// It is how a question about a relation gets asked without reimplementing the
// relation: evaluate a decision against the data as it stands, evaluate it
// again against data where the relation is cut, and the difference is what the
// relation was granting. The trap of section 5 of the fixture is avoided the
// same way partial evaluation avoids it, by never having an opinion of our own
// about what reaching means.
//
// A path whose last segment is an element of an array is left in place. Taking
// an element out would renumber the ones after it, and the second evaluation
// would then differ for a reason nobody asked about.
func (d *Data) Without(ctx context.Context, paths ...string) (*Data, error) {
	root, err := storage.ReadOne(ctx, d.store, storage.Path{})
	if err != nil {
		return nil, fmt.Errorf("opaengine: reading the data: %w", err)
	}
	documents, isObject := clone(root).(map[string]any)
	if !isObject {
		return nil, fmt.Errorf("opaengine: the data holds a %T at its root", root)
	}

	for _, path := range paths {
		walk, err := d.walk(ctx, path)
		if err != nil {
			return nil, err
		}
		for _, at := range walk.resolved {
			remove(documents, at)
		}
	}
	return &Data{store: inmem.NewFromObject(documents), Files: slices.Clone(d.Files)}, nil
}

// With returns the same documents with one path set to a value, creating the
// segments on the way if they are not there, and leaves the data it was called
// on untouched.
//
// It is the other side of Without: where a question about a relation cuts a
// path away, a question about a write puts a value where the write would leave
// one, and asks the decision what it grants then. The path has to be concrete,
// a document rather than a collection, since a write lands on one record.
func (d *Data) With(ctx context.Context, path string, value any) (*Data, error) {
	ref, err := ast.ParseRef(path)
	if err != nil {
		return nil, fmt.Errorf("opaengine: reading the path %s: %w", path, err)
	}
	at, err := concretePath(ref)
	if err != nil {
		return nil, err
	}

	root, err := storage.ReadOne(ctx, d.store, storage.Path{})
	if err != nil {
		return nil, fmt.Errorf("opaengine: reading the data: %w", err)
	}
	documents, isObject := clone(root).(map[string]any)
	if !isObject {
		return nil, fmt.Errorf("opaengine: the data holds a %T at its root", root)
	}

	set(documents, at, value)
	return &Data{store: inmem.NewFromObject(documents), Files: slices.Clone(d.Files)}, nil
}

// Value returns the document a concrete path names, and whether it is there.
// A path that is not concrete, or names nothing, is not a value: the first is
// an error, the second is the false the caller asked about.
func (d *Data) Value(ctx context.Context, path string) (any, bool, error) {
	ref, err := ast.ParseRef(path)
	if err != nil {
		return nil, false, fmt.Errorf("opaengine: reading the path %s: %w", path, err)
	}
	at, err := concretePath(ref)
	if err != nil {
		return nil, false, err
	}

	txn, err := d.store.NewTransaction(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("opaengine: opening a read of the data: %w", err)
	}
	defer d.store.Abort(ctx, txn)

	value, err := d.store.Read(ctx, txn, at)
	if storage.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("opaengine: reading data.%s: %w", strings.Join(at, "."), err)
	}
	return value, true, nil
}

// concretePath turns a data rooted reference with no dynamic segment into the
// store path of the one document it names.
func concretePath(ref ast.Ref) (storage.Path, error) {
	if !isDataRooted(ref) {
		return nil, fmt.Errorf("opaengine: %s names no document under data", ref)
	}
	at := make(storage.Path, 0, len(ref)-1)
	for _, term := range ref[1:] {
		segment, named := namedSegment(term)
		if !named {
			return nil, fmt.Errorf("opaengine: %s is a collection, not one document", ref)
		}
		at = append(at, segment)
	}
	return at, nil
}

// set writes a value into a tree, creating the objects the path passes through.
func set(documents map[string]any, at storage.Path, value any) {
	if len(at) == 0 {
		return
	}
	holder := documents
	for _, segment := range at[:len(at)-1] {
		next, isObject := holder[segment].(map[string]any)
		if !isObject {
			next = map[string]any{}
			holder[segment] = next
		}
		holder = next
	}
	holder[at[len(at)-1]] = value
}

// clone deep copies a document.
//
// The store of OPA round trips what it is given through JSON, which would copy
// it too, but only because a check inside decides that an object needs it.
// Resting on that would mean that the day the check changes, two stores share
// their maps and taking a path out of one silently takes it out of the other.
func clone(value any) any {
	switch document := value.(type) {
	case map[string]any:
		copied := make(map[string]any, len(document))
		for key, child := range document {
			copied[key] = clone(child)
		}
		return copied
	case []any:
		copied := make([]any, len(document))
		for i, child := range document {
			copied[i] = clone(child)
		}
		return copied
	default:
		// Everything else a document holds is a value: a string, a bool, a
		// json.Number, or nothing at all.
		return value
	}
}

// remove takes one document out of a tree, when the path leads to a field of an
// object.
func remove(documents map[string]any, at storage.Path) {
	if len(at) == 0 {
		return
	}

	holder := any(documents)
	for _, segment := range at[:len(at)-1] {
		holder = child(holder, segment)
	}
	if object, isObject := holder.(map[string]any); isObject {
		delete(object, at[len(at)-1])
	}
}

// child returns what a document holds under one segment, following objects and
// arrays alike.
func child(holder any, segment string) any {
	switch document := holder.(type) {
	case map[string]any:
		return document[segment]
	case []any:
		if i, err := strconv.Atoi(segment); err == nil && i >= 0 && i < len(document) {
			return document[i]
		}
	}
	return nil
}

// presenceWalk follows one path down the concrete data, branching wherever the
// path ranges over a collection instead of naming a document.
type presenceWalk struct {
	ctx   context.Context
	store storage.Store
	txn   storage.Transaction
	found Presence

	// resolved are the store paths the documents actually sit at, which is what
	// a caller needs to reach one rather than to count it.
	resolved []storage.Path
}

// descend follows the segments a path names, and hands over to spread at the
// first one it does not.
func (w *presenceWalk) descend(at storage.Path, rest ast.Ref, keys []string) error {
	for i, term := range rest {
		segment, named := namedSegment(term)
		if !named {
			return w.spread(at, rest[i+1:], keys)
		}
		at = append(at, segment)
	}
	return w.arrive(at, keys)
}

// spread branches over the documents of a collection, which is where the keys
// of the answer come from.
func (w *presenceWalk) spread(at storage.Path, rest ast.Ref, keys []string) error {
	collection, found, err := w.read(at)
	if err != nil {
		return err
	}
	if !found {
		// The collection is not there, so nothing under it is either, and there
		// are no keys to name the branches with.
		w.absent(keys)
		return nil
	}

	branch := func(segment string) error {
		return w.descend(append(slices.Clone(at), segment), rest, append(slices.Clone(keys), segment))
	}
	switch value := collection.(type) {
	case map[string]any:
		for _, key := range slices.Sorted(maps.Keys(value)) {
			if err := branch(key); err != nil {
				return err
			}
		}
	case []any:
		for i := range value {
			if err := branch(strconv.Itoa(i)); err != nil {
				return err
			}
		}
	default:
		// A scalar stands where the path expects something to index. Nothing
		// under it exists, and saying so is truer than saying nothing.
		w.absent(keys)
	}
	return nil
}

// arrive records whether the document at the end of the path is there.
func (w *presenceWalk) arrive(at storage.Path, keys []string) error {
	_, found, err := w.read(at)
	if err != nil {
		return err
	}
	if found {
		w.found.Present = append(w.found.Present, keyOf(keys))
		w.resolved = append(w.resolved, slices.Clone(at))
		return nil
	}
	w.absent(keys)
	return nil
}

// absent records one document the path does not reach.
func (w *presenceWalk) absent(keys []string) {
	w.found.Absent = append(w.found.Absent, keyOf(keys))
}

// read fetches one document, telling absence from failure: a path that is not
// there is an answer, and anything else is worth stopping for.
func (w *presenceWalk) read(at storage.Path) (any, bool, error) {
	value, err := w.store.Read(w.ctx, w.txn, at)
	if storage.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("opaengine: reading data.%s: %w", strings.Join(at, "."), err)
	}
	return value, true, nil
}

// namedSegment returns the key a segment names, when it names one rather than
// ranging over the collection.
func namedSegment(term *ast.Term) (string, bool) {
	switch value := term.Value.(type) {
	case ast.String:
		return string(value), true
	case ast.Number:
		return value.String(), true
	default:
		return "", false
	}
}

// keyOf names one branch of the walk. A path with no dynamic segment names a
// single document and has no key, and the empty string is what says so.
func keyOf(keys []string) string {
	return strings.Join(keys, ".")
}

// Request is one question to ask of a decision: which decision, what about the
// request is not known, and what is.
type Request struct {
	// Decision is the rule to ask about, as a path: data.quill.authz.allow.
	Decision string

	// Unknowns are the parts of the request left open, as paths into input.
	// Empty means the whole request, which is the question the tool asks by
	// default: what can anybody get out of this decision.
	//
	// Naming a narrower unknown is what turns the same machinery into a
	// question about one principal. With input.doc unknown and the rest given,
	// the conditions that come back are the documents that principal can read.
	Unknowns []string

	// Input is the part of the request that is known.
	Input map[string]any
}

// Condition is one way a decision can hold once the data is concrete.
type Condition struct {
	// Query is the residual condition, written as Rego so that it can be read,
	// checked against the policy, and pasted into a query:
	// "d-t11-1" = input.doc.
	Query string

	// Value is what the decision evaluates to when the condition holds. It is
	// almost always true, and it is carried because a decision does not have
	// to be a boolean: a policy that answers with a reason or a set of
	// permissions leaves conditions that differ in what they grant.
	Value string
}

// ResidualSet is what is left of one decision when the data is concrete and
// part of the request is not.
type ResidualSet struct {
	Decision string

	// Unknowns are the parts of the request the question left open, as they
	// were asked, so that a result carries the question it answers.
	Unknowns []string

	// Conditions are the ways the decision can still hold, each of them a
	// condition on the unknown part of the request.
	Conditions []Condition

	// Default is the value the decision takes when no condition holds, when
	// the policy declares one. An absent default and a default of false are
	// not the same thing: the first leaves the decision undefined, and what
	// that means is up to the PEP.
	Default string

	// Always is true when the decision holds whatever the unknown part of the
	// request turns out to be. Nothing is left to check, which is a different
	// answer from a long list of conditions and not a shorter one.
	Always bool

	// Truncated is true when the bound cut the conditions short.
	Truncated bool

	// Warnings are the limits the evaluation ran into.
	Warnings []string
}

// Never reports whether nothing at all can make the decision hold.
//
// A truncated result is never this, however empty the conditions look: a bound
// that cut the list is not a proof that the list was empty.
func (rs *ResidualSet) Never() bool {
	return !rs.Always && !rs.Truncated && len(rs.Conditions) == 0
}

// Residuals evaluates a decision against the concrete data, leaving part of the
// request unknown, and reports the conditions under which it can still hold.
//
// This is where reading the policy turns into measuring it against the data,
// and the reason it exists rather than a graph walk of our own: the conditions come out of OPA evaluating the
// policy, so they carry the semantics of whatever the policy actually uses. The
// fixture makes that concrete with graph.reachable, which includes a node only
// if the node is a key of the graph object. Computing reachability ourselves,
// with gonum or anything else, would answer the mathematical question and
// report eighteen documents where the policy grants none.
//
// The compiler is the one the bundle was loaded with, so nothing is compiled
// twice and the evaluation runs against the same AST the rest of the analysis
// read.
//
// Nondeterministic builtins are left unevaluated, which is the default of OPA
// and is deliberately not changed here. rego.NondeterministicBuiltins(true)
// exists to pull external data in during partial evaluation, and turning it on
// would mean that analyzing somebody's policy sends HTTP requests to the hosts
// that policy names. A tool that reads other people's code does not call the
// addresses it finds in it. The calls stay in the residual conditions instead,
// which is also where they belong: a decision that still depends on a call is a
// decision nobody can settle from the data alone.
func Residuals(ctx context.Context, bundle *Bundle, data *Data, ask Request, limits Limits) (*ResidualSet, error) {
	queries, err := partial(ctx, bundle, data, ask)
	if err != nil {
		return nil, err
	}

	unknowns := ask.Unknowns
	if len(unknowns) == 0 {
		unknowns = []string{ast.InputRootDocument.String()}
	}
	result := &ResidualSet{Decision: ask.Decision, Unknowns: slices.Clone(unknowns)}
	result.Conditions, result.Default, result.Always = conditionsOf(queries)
	result.bound(limits.maxResiduals())
	return result, nil
}

// partial runs partial evaluation and returns what OPA left of the decision.
// It is the one place the rego options are built, so that a second question
// asked of the same decision cannot phrase the evaluation differently from
// Residuals and get an answer that does not line up with it.
func partial(ctx context.Context, bundle *Bundle, data *Data, ask Request) (*rego.PartialQueries, error) {
	if data == nil {
		return nil, ErrNoData
	}

	unknowns := ask.Unknowns
	if len(unknowns) == 0 {
		unknowns = []string{ast.InputRootDocument.String()}
	}

	options := []func(*rego.Rego){
		rego.Query(ask.Decision),
		rego.Compiler(bundle.Compiler),
		rego.Store(data.store),
		rego.Unknowns(unknowns),
	}
	if ask.Input != nil {
		options = append(options, rego.Input(ask.Input))
	}

	queries, err := rego.New(options...).Partial(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrPartial, ask.Decision, err)
	}
	return queries, nil
}

// GrantingValue is a constant a residual condition compares an unknown document
// against, taken from the structure of the condition rather than from its
// meaning.
type GrantingValue struct {
	// Value is the constant as a Go value, ready to write back into the data:
	// the string "editor", or a json.Number.
	Value any

	// Text is the constant as it reads, for a report and a finding: editor.
	Text string

	// Membership is true when the document is a collection the value is an
	// element of ("editor" in roles), and false when the document is compared
	// to the value directly (tier == "gold"). It is the difference between
	// writing [value] and writing value, and it comes from which builtin the
	// condition used, not from any reading of what it means.
	Membership bool
}

// ValuesComparedWith partially evaluates a decision with one document left
// unknown and collects the constants the residual conditions compare that
// document against.
//
// It is the third signal of PTD-OPA-006: the values that, written into the
// document, would make the decision grant. They are read off OPA's answer, so a
// decision that grants on "editor" through a rule nobody would spot by eye still
// yields "editor" here. The collection is structural, an operand of a builtin
// call standing next to the document, and it interprets nothing about what the
// condition means: a comparison against a value computed from other data leaves
// nothing to collect, and that is a declared false negative rather than a guess.
func ValuesComparedWith(ctx context.Context, bundle *Bundle, data *Data, ask Request, document string) ([]GrantingValue, error) {
	docRef, err := ast.ParseRef(document)
	if err != nil {
		return nil, fmt.Errorf("opaengine: reading the path %s: %w", document, err)
	}
	if !slices.Contains(ask.Unknowns, document) {
		ask.Unknowns = append(slices.Clone(ask.Unknowns), document)
	}

	queries, err := partial(ctx, bundle, data, ask)
	if err != nil {
		return nil, err
	}

	var values []GrantingValue
	seen := map[string]bool{}
	for _, body := range residualBodies(queries) {
		collectConstants(body, docRef, &values, seen)
	}
	return values, nil
}

// residualBodies returns the rule bodies partial evaluation left, expanding a
// support module one level the way conditionsOf does: a decision with a default
// comes back as a query naming a generated rule, and the disjunction is in that
// rule's bodies rather than in the query.
func residualBodies(queries *rego.PartialQueries) []ast.Body {
	var bodies []ast.Body
	for _, query := range queries.Queries {
		if len(query) == 0 {
			// The decision holds on the data alone, so there is no condition and
			// nothing compared against the document.
			continue
		}
		if ref, ok := generatedRuleRef(query); ok {
			for _, module := range queries.Support {
				for _, rule := range module.Rules {
					if !rule.Default && rulePath(rule).Equal(ref) {
						bodies = append(bodies, rule.Body)
					}
				}
			}
			continue
		}
		bodies = append(bodies, query)
	}
	return bodies
}

// generatedRuleRef returns the ref a query points at when the query is nothing
// but a reference to a rule partial evaluation generated.
func generatedRuleRef(query ast.Body) (ast.Ref, bool) {
	if len(query) != 1 {
		return nil, false
	}
	term, isTerm := query[0].Terms.(*ast.Term)
	if !isTerm {
		return nil, false
	}
	ref, isRef := term.Value.(ast.Ref)
	return ref, isRef
}

// collectConstants gathers the literal operands of every builtin call in a body
// that also names the document, once each.
func collectConstants(body ast.Body, document ast.Ref, values *[]GrantingValue, seen map[string]bool) {
	for _, expr := range body {
		if !expr.IsCall() {
			continue
		}
		operands := expr.Operands()
		if !operandsName(operands, document) {
			continue
		}
		membership := isMembership(expr.Operator())
		for _, operand := range operands {
			native, ok := constantValue(operand.Value)
			if !ok {
				continue
			}
			key := operand.Value.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			*values = append(*values, GrantingValue{Value: native, Text: constantText(operand.Value), Membership: membership})
		}
	}
}

// operandsName reports whether any operand is the document, or a path into it.
func operandsName(operands []*ast.Term, document ast.Ref) bool {
	for _, operand := range operands {
		if ref, isRef := operand.Value.(ast.Ref); isRef {
			if ref.Equal(document) || strictPrefix(document, ref) {
				return true
			}
		}
	}
	return false
}

// isMembership reports whether a builtin is the membership operator, which is
// what puts the document on the collection side of an "x in coll".
func isMembership(operator ast.Ref) bool {
	switch operator.String() {
	case ast.Member.Name, ast.MemberWithKey.Name:
		return true
	default:
		return false
	}
}

// constantValue returns the Go value of a scalar term, and whether the term was
// one. A reference, a variable or a call is not a constant to collect.
func constantValue(value ast.Value) (any, bool) {
	switch value.(type) {
	case ast.String, ast.Number, ast.Boolean, ast.Null:
		native, err := ast.JSON(value)
		if err != nil {
			return nil, false
		}
		return native, true
	default:
		return nil, false
	}
}

// constantText is how a constant reads in a report: a string without its
// quotes, anything else as it is written.
func constantText(value ast.Value) string {
	if s, isString := value.(ast.String); isString {
		return string(s)
	}
	return value.String()
}

// bound cuts the conditions to what the caller is willing to look at, and says
// so.
//
// The cut is on what gets reported, not on what gets computed: partial
// evaluation has already produced every condition by the time they are counted
// here. It keeps a report readable and a graph finite, and it is not a defence
// against an expensive evaluation.
func (rs *ResidualSet) bound(max int) {
	if len(rs.Conditions) <= max {
		return
	}
	rs.Warnings = append(rs.Warnings, fmt.Sprintf(
		"kept %d of %d residual conditions of %s: raise MaxResiduals to see the rest",
		max, len(rs.Conditions), rs.Decision))
	rs.Conditions = rs.Conditions[:max]
	rs.Truncated = true
}

// conditionsOf turns what partial evaluation returned into conditions a reader
// can check.
//
// A decision with a default value does not come back as a list of residual
// queries: it comes back as one query naming a rule that partial evaluation
// generated, plus a support module holding that rule. Verified on the fixture,
// where every decision has a default and every residual therefore lives in a
// support module. The design called support modules a case to handle even
// though they are empty on the simple example; on a policy written the way
// people write policies they are where the answer is.
func conditionsOf(queries *rego.PartialQueries) ([]Condition, string, bool) {
	var (
		conditions []Condition
		fallback   string
		always     bool
	)

	for _, query := range queries.Queries {
		if len(query) == 0 {
			// Nothing left to check: the decision holds on the data alone.
			always = true
			continue
		}
		if expanded, def, ok := expandSupport(query, queries.Support); ok {
			conditions = append(conditions, expanded...)
			if def != "" {
				fallback = def
			}
			continue
		}
		conditions = append(conditions, Condition{Query: query.String(), Value: "true"})
	}
	return conditions, fallback, always
}

// expandSupport reads the conditions out of a support module.
//
// A query that is nothing but a reference to a generated rule is not a
// condition, it is a pointer to where the conditions are. The bodies of that
// rule are the disjunction, and the default among them is what the decision
// falls back to.
//
// One level is expanded, deliberately. If a body still mentions another
// generated rule, that reference stays in the text of the condition, which is
// the truth: the condition holds when that rule does. Expanding further would
// mean combining bodies that are joined by conjunction and disjunction at once,
// and getting that wrong silently is worse than a reader following one more
// reference.
func expandSupport(query ast.Body, support []*ast.Module) ([]Condition, string, bool) {
	ref, ok := generatedRuleRef(query)
	if !ok {
		return nil, "", false
	}

	var (
		conditions []Condition
		fallback   string
		found      bool
	)
	for _, module := range support {
		for _, rule := range module.Rules {
			if !rulePath(rule).Equal(ref) {
				continue
			}
			found = true
			if rule.Default {
				fallback = valueOf(rule)
				continue
			}
			conditions = append(conditions, Condition{Query: rule.Body.String(), Value: valueOf(rule)})
		}
	}
	return conditions, fallback, found
}

// valueOf is what a rule produces when its body holds. A rule with no value is
// a predicate: it says yes, it does not hand back a document.
func valueOf(rule *ast.Rule) string {
	if rule.Head == nil || rule.Head.Value == nil {
		return "true"
	}
	return rule.Head.Value.String()
}
