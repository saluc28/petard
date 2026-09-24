// Package pepregistry carries the declarations of enforcement points into the
// binary, the way the taxonomy registry carries the patterns: somebody who
// downloads a release can name a product with -pep without a checkout.
//
// The files are the registry as it stands in the repository, unmodified. What
// the analysis makes of them is in internal/pep.
package pepregistry

import "embed"

// Dir is where the registry sits in the repository, which is how a report
// names a declaration somebody can open.
const Dir = "pep-registry"

//go:embed *.yaml
var files embed.FS

// Files is every declaration, one YAML file each, named after its id.
var Files = files
