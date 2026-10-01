package opaengine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/v1/bundle"
)

// A bundle that opa build writes, or a bundle server serves, is a gzipped tar
// of the policies and their data side by side. Reading one in place lets a run
// be pointed at what is deployed rather than at a checkout of it.

// tarballExts are the names a bundle archive goes by: bundle.tar.gz is what
// opa build writes unless told otherwise (cmd/build.go:283 at v1.20.2), and
// .tgz is the same thing shorter.
var tarballExts = []string{".tar.gz", ".tgz"}

// isTarball reports whether a path names a bundle archive.
func isTarball(path string) bool {
	for _, ext := range tarballExts {
		if strings.HasSuffix(strings.ToLower(path), ext) {
			return true
		}
	}
	return false
}

// archived is one file of a bundle archive.
type archived struct {
	// name is the archive followed by the path inside it, with forward
	// slashes: bundle.tar.gz/authz/policy.rego. It is how a report names the
	// file, and the only way to tell two archives apart.
	name string

	// inside is the path inside the archive, without the leading slash opa
	// build writes: authz/policy.rego.
	inside string

	content []byte
}

// readTarball reads every file of a bundle archive, through the loader OPA
// reads bundles with and under the size limit it applies to each file
// (bundle.DefaultSizeLimitBytes, v1/bundle/bundle.go:53 at v1.20.2), so that a
// file too large for OPA is too large here as well.
func readTarball(path string) ([]archived, error) {
	compressed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opaengine: reading %s: %w", path, err)
	}

	loader := bundle.NewTarballLoaderWithBaseURL(bytes.NewReader(compressed), "").
		WithSizeLimitBytes(bundle.DefaultSizeLimitBytes)
	var files []archived
	for {
		descriptor, err := loader.NextFile()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, fmt.Errorf("opaengine: reading %s: %w", path, err)
		}

		content, err := contentOf(descriptor)
		if err != nil {
			return nil, fmt.Errorf("opaengine: reading %s in %s: %w", descriptor.Path(), path, err)
		}
		inside := strings.TrimPrefix(filepath.ToSlash(descriptor.Path()), "/")
		files = append(files, archived{
			name:    filepath.ToSlash(path) + "/" + inside,
			inside:  inside,
			content: content,
		})
	}
}

// contentOf reads one file of an archive and closes it.
func contentOf(descriptor *bundle.Descriptor) ([]byte, error) {
	var content bytes.Buffer
	_, err := descriptor.Read(&content, bundle.DefaultSizeLimitBytes)
	if errors.Is(err, io.EOF) {
		// Read copies up to the limit, and a file shorter than the limit ends
		// in EOF, which is every file that was read whole.
		err = nil
	}
	return content.Bytes(), errors.Join(err, descriptor.Close())
}
