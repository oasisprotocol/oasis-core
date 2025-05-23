package log

import (
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/runtime/config"
)

// logsDir is the name of the directory located inside the node's runtimes directory which contains
// the component logs.
const logsDir = "logs"

// GetLogsDir derives the path to the logs directory.
func GetLogsDir(dataDir string) string {
	return filepath.Join(dataDir, config.RuntimesDir, logsDir)
}
