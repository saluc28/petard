package spicesetup

import (
	"path/filepath"
	"testing"
)

// rel names a path under the repository root, three levels up from this package.
func rel(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", ".."}, parts...)...)
}

// Load reads the schema and its write model from the same directory, and leaves
// the directory for the policy loader while taking the schema and validation
// files out.
func TestLoadDiscoversTheWriteModelBesideTheSchema(t *testing.T) {
	dir := rel("fixtures", "vulnerable-spicedb")

	found, err := Load([]string{dir}, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(found.Files) == 0 {
		t.Fatal("found no SpiceDB files under the fixture")
	}
	if len(found.WriteModels) != 1 {
		t.Fatalf("write models = %d, want 1 beside the schema", len(found.WriteModels))
	}
	for d, wm := range found.WriteModels {
		if wm == nil {
			t.Errorf("write model for %s is nil", d)
		}
	}
	if found.PolicyWriteModel != "" {
		t.Errorf("policy write model = %q, want empty with no flag", found.PolicyWriteModel)
	}
	if len(found.PolicyPaths) != 1 || filepath.Clean(found.PolicyPaths[0]) != filepath.Clean(dir) {
		t.Errorf("policy paths = %v, want just the directory for the policy loader", found.PolicyPaths)
	}
}

// The write-model flag feeds both engines, told apart by the kind the file
// declares: a relationship-writes model is the Zanzibar engine's and is kept
// from the policy loader, a write-paths model is the policy engine's.
func TestLoadRoutesTheWriteModelFlagByKind(t *testing.T) {
	spiceDir := rel("fixtures", "vulnerable-spicedb")
	rebacModel := filepath.Join(spiceDir, "writes.yaml")
	policyModel := rel("fixtures", "vulnerable-bundle", "write-model.yaml")

	tests := []struct {
		name            string
		flag            string
		wantPolicyModel string
	}{
		{"no flag", "", ""},
		{"a relationship-writes model is the zanzibar engine's", rebacModel, ""},
		{"a write-paths model is the policy engine's", policyModel, policyModel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, err := Load([]string{spiceDir}, tt.flag)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if found.PolicyWriteModel != tt.wantPolicyModel {
				t.Errorf("policy write model = %q, want %q", found.PolicyWriteModel, tt.wantPolicyModel)
			}
		})
	}
}
