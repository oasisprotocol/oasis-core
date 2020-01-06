package registry

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/oasislabs/oasis-core/go/common"
)

const (
	// RuntimesDir is the name of the directory located inside the node's data
	// directory which contains the per-runtime state.
	RuntimesDir = "runtimes"
)

// EnsureRuntimeStateDir ensures a specific per-runtime directory exists and
// returns its full path.
func EnsureRuntimeStateDir(dataDir string, runtimeID common.Namespace) (string, error) {
	path := filepath.Join(dataDir, RuntimesDir, runtimeID.String())
	if err := common.Mkdir(path); err != nil {
		return "", err
	}

	return path, nil
}

// ParseRuntimeMap parses strings in the format of <runtime-id>[:<value>] and
// returns them as a map of runtime IDs to value.
func ParseRuntimeMap(rawItems []string) (map[common.Namespace]string, error) {
	result := make(map[common.Namespace]string, len(rawItems))
	for _, rawItem := range rawItems {
		atoms := strings.SplitN(rawItem, ":", 2)

		var id common.Namespace
		if err := id.UnmarshalHex(atoms[0]); err != nil {
			return nil, fmt.Errorf("malformed runtime map item: %s", rawItem)
		}

		if len(atoms) == 1 {
			result[id] = ""
		} else {
			result[id] = atoms[1]
		}
	}
	return result, nil
}
