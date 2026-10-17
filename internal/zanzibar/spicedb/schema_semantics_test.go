package spicedb

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/saluc28/petard/internal/zanzibar"
)

// The engine has to give every answer the validation files of testdata
// assert. zed validate holds the same files against SpiceDB in TestOracle.
func TestAssertions(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "*.yaml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no testdata: %v", err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			f := findOne(t, path)
			checker := zanzibar.NewChecker(f.Schema.Model, f.Relationships, f.Schema, time.Now())
			if len(f.Assertions) == 0 {
				t.Fatal("the file asserts nothing")
			}
			for _, a := range f.Assertions {
				got, err := checker.Check(a.Resource, a.Name, a.Subject, a.Context)
				if err != nil {
					t.Errorf("%s: %s: %v", a.Position, a, err)
					continue
				}
				if got.Level != a.Level {
					t.Errorf("%s: %s = %s, want %s", a.Position, a, got.Level, a.Level)
				}
			}
		})
	}
}
