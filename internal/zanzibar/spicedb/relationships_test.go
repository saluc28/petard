package spicedb

import (
	"errors"
	"testing"
	"time"

	"github.com/saluc28/petard/internal/zanzibar"
)

// Every form a relationship takes in a validation file, with blank lines and
// comments skipped and positions counted from the line the block starts on.
func TestParseRelationships(t *testing.T) {
	text := `// owners
document:readme#owner@user:olivia

  document:readme#viewer@group:eng#member
folder:public#viewer@user:*
document:readme#editor@user:eve[ip_allowlist:{"cidr":"10.0.0.0/8"}][expiration:2030-01-01T00:00:00Z]`

	rels, err := ParseRelationships("file.yaml", 10, text)
	if err != nil {
		t.Fatalf("ParseRelationships() error = %v", err)
	}
	if len(rels) != 4 {
		t.Fatalf("relationships = %d, want 4", len(rels))
	}

	if got := rels[0]; got.String() != "document:readme#owner@user:olivia" || got.Line != 11 || got.Column != 1 {
		t.Errorf("first = %s at %s, want document:readme#owner@user:olivia at line 11 column 1", got, got.Position)
	}
	if got := rels[1]; got.Subject.Relation != "member" || got.Line != 13 || got.Column != 3 {
		t.Errorf("second = %s at %s, want a userset at line 13 column 3", got, got.Position)
	}
	if got := rels[2].Subject; got.ID != zanzibar.WildcardID || got.Relation != "" {
		t.Errorf("third subject = %s, want user:*", got)
	}

	eve := rels[3]
	if eve.Caveat == nil || eve.Caveat.Name != "ip_allowlist" || eve.Caveat.Context["cidr"] != "10.0.0.0/8" {
		t.Errorf("fourth caveat = %+v, want ip_allowlist with its cidr", eve.Caveat)
	}
	if want := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC); eve.Expires == nil || !eve.Expires.Equal(want) {
		t.Errorf("fourth expires = %v, want %v", eve.Expires, want)
	}
}

func TestParseRelationshipsRefusesAMalformedLine(t *testing.T) {
	_, err := ParseRelationships("file.yaml", 1, "document:readme#owner")
	if !errors.Is(err, ErrRelationship) {
		t.Fatalf("ParseRelationships() error = %v, want ErrRelationship", err)
	}
}
