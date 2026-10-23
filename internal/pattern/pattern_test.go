package pattern

import (
	"io/fs"
	"testing"

	"github.com/saluc28/petard/internal/taxonomy"
	registry "github.com/saluc28/petard/taxonomy-registry"
)

// The panel notes are a lightweight parse of the registry, and internal/taxonomy
// is the authoritative loader. They read the same files, so they have to agree
// on every id, name, title and closes, or a pattern would be named one way in
// the panel and another in the report.
func TestNotesMatchTheRegistry(t *testing.T) {
	notes, err := Notes()
	if err != nil {
		t.Fatalf("Notes() error = %v", err)
	}

	for _, engine := range []struct {
		dir string
		fs  fs.FS
	}{
		{registry.OPADir, registry.OPA},
		{registry.ZanzibarDir, registry.Zanzibar},
	} {
		patterns, err := taxonomy.LoadRegistry(engine.fs)
		if err != nil {
			t.Fatalf("LoadRegistry(%s) error = %v", engine.dir, err)
		}

		var mine []Note
		for _, note := range notes {
			if note.Engine == engine.dir {
				mine = append(mine, note)
			}
		}
		if len(mine) != len(patterns) {
			t.Fatalf("%s: %d notes, the registry has %d patterns", engine.dir, len(mine), len(patterns))
		}
		for i, want := range patterns {
			if got := mine[i]; got.ID != want.ID || got.Name != want.Name || got.Title != want.Title || got.Closes != want.Closes {
				t.Errorf("%s note %d = {%s %s %q %q}, the registry says {%s %s %q %q}",
					engine.dir, i, got.ID, got.Name, got.Title, got.Closes, want.ID, want.Name, want.Title, want.Closes)
			}
		}
	}
}
