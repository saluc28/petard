package zanzibar

// Aspects are cross-cutting properties of a raise that hold alongside its
// category, read off the model and the write model after the closure has found
// the raise. They name a risk the structural category does not, for a reader who
// asks what a raise means in an agent or non-human-identity setting, and they
// change nothing about detection: the closure finds the raise either way.

// defeatsExpiry reports whether the decisive write of a raise sets a
// relationship the schema lets carry an expiration, where the write model leaves
// that expiration for the coalition to set or to omit. The relationship then
// grants without the time bound the schema admits: the coalition writes it with
// no expiration, or renews it with one far enough out, so a grant meant to lapse
// does not. An expiration the application supplies, not the writer, is not
// defeated this way and is not marked.
func defeatsExpiry(model *Model, step WriteStep) bool {
	if step.Rule == nil {
		// A creation, or one of the tuples a creation writes, carries no write
		// rule, so there is no expiration filler to read.
		return false
	}
	switch step.Rule.Expiration {
	case FillerApplication:
		// The application sets the expiration with the check, so the coalition
		// cannot choose or omit it.
		return false
	case FillerWriter, FillerNone, "":
		// The writer sets it, or no write carries one; either way the coalition
		// controls whether the tuple bears an expiration. Empty is the writer
		// default.
	default:
		return false
	}
	t := model.Type(step.Relationship.Resource.Type)
	if t == nil {
		return false
	}
	r := t.Relation(step.Relationship.Relation)
	if r == nil {
		return false
	}
	return relationExpires(r, step.Relationship.Subject)
}

// relationExpires reports whether a relationship of this relation, holding this
// subject, can carry an expiration: the allowed subject kind the subject matches
// declares one. A relation that admits an expiration only for a subject kind
// other than the one written does not, so a write of that other kind is not
// marked.
func relationExpires(r *Relation, subj Subject) bool {
	for _, a := range r.Allowed {
		if !a.Expiration {
			continue
		}
		if a.Wildcard {
			if subj.Object.ID == WildcardID && subj.Object.Type == a.Type {
				return true
			}
			continue
		}
		if a.Type == subj.Object.Type && a.Relation == subj.Relation {
			return true
		}
	}
	return false
}
