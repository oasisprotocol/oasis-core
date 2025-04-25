package bundle

import (
	"path/filepath"
)

// ExplodedPath returns the path under the data directory that contains all of the exploded bundles.
func ExplodedPath(dataDir string) string {
	return filepath.Join(dataDir, "runtimes", "bundles")
}

// TmpBundlePath returns the path under the data directory that contains all of the temporary
// bundles.
func TmpBundlePath(dataDir string) string {
	return filepath.Join(dataDir, "runtimes", "tmp", "bundles")
}
