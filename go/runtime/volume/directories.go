package volume

import (
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/runtime/config"
)

// VolumesDir is the name of the directory located inside the node's runtimes directory which
// contains the persistent volumes.
const VolumesDir = "volumes"

// GetVolumesDir derives the path to the volumes directory.
func GetVolumesDir(dataDir string) string {
	return filepath.Join(dataDir, config.RuntimesDir, VolumesDir)
}
