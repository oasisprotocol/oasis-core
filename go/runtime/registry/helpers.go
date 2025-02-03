package registry

import (
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/common"
)

const (
	// RuntimesDir is the name of the directory located inside the node's data
	// directory which contains the per-runtime state.
	RuntimesDir = "runtimes"
)

func GetRuntimeStateDir(dataDir string, runtimeID common.Namespace) string {
	return filepath.Join(dataDir, RuntimesDir, runtimeID.String())
}

// EnsureRuntimeStateDir ensures a specific per-runtime directory exists and
// returns its full path.
func EnsureRuntimeStateDir(dataDir string, runtimeID common.Namespace) (string, error) {
	path := GetRuntimeStateDir(dataDir, runtimeID)
	if err := common.Mkdir(path); err != nil {
		return "", err
	}

	return path, nil
}
