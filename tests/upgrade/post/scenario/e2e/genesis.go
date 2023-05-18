package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
)

// FixExportedGenesisFile fixes the first exported genesis file and returns a path to the fixed file.
func FixExportedGenesisFile(childEnv *env.Env, sc *e2e.Scenario) (string, error) {
	sc.Logger.Info("searching for exported genesis file")

	exportedGenFilePath, err := findExportedGenesisFile(sc.Net.Nodes())
	if err != nil {
		return "", err
	}

	sc.Logger.Info("fixing exported genesis file", "path", exportedGenFilePath)

	fixedGenFilePath := filepath.Join(childEnv.Dir(), "genesis-fixed.json")
	if err := sc.RunFixGenesisCmd(childEnv, exportedGenFilePath, fixedGenFilePath); err != nil {
		return "", fmt.Errorf("failed to fix exported genesis file: %+w", err)
	}

	return fixedGenFilePath, nil
}

// findExportedGenesisFile returns the path of the first exported genesis file that is found.
func findExportedGenesisFile(nodes []*oasis.Node) (string, error) {
	var exportedGenFilePath string
	for _, node := range nodes {
		dir := filepath.Join(node.DataDir(), "exports")
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasPrefix(d.Name(), "genesis-test:") {
				exportedGenFilePath = path
			}
			return nil
		})
		if exportedGenFilePath != "" {
			break
		}
	}
	if exportedGenFilePath == "" {
		return "", fmt.Errorf("exported genesis file not found")
	}
	return exportedGenFilePath, nil
}
