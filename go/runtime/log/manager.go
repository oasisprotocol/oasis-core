package log

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

// logFn is the filename of the log file.
const logFn = "log"

// Manager is a log manager.
type Manager struct {
	mu sync.Mutex

	logsDir string
	logs    map[common.Namespace]map[component.ID]*Log

	logger *logging.Logger
}

// NewManager creates a new log manager.
func NewManager(dataDir string) *Manager {
	logger := logging.GetLogger("runtime/log/manager")

	return &Manager{
		logsDir: GetLogsDir(dataDir),
		logs:    make(map[common.Namespace]map[component.ID]*Log),
		logger:  logger,
	}
}

// Get returns a log handle for the log of the given component.
func (m *Manager) Get(runtimeID common.Namespace, componentID component.ID) (*Log, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if log, ok := m.logs[runtimeID][componentID]; ok {
		return log, nil
	}

	logDir := m.getLogDirectory(runtimeID, componentID)
	if err := common.Mkdir(logDir); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}
	fn := filepath.Join(logDir, logFn)

	log, err := NewLog(fn, config.GlobalConfig.Runtime.Log.MaxLogSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create log handle: %w", err)
	}

	logs, ok := m.logs[runtimeID]
	if !ok {
		logs = make(map[component.ID]*Log)
		m.logs[runtimeID] = logs
	}
	logs[componentID] = log
	return log, nil
}

// Remove closes a log handle and removes any logs of the given component.
func (m *Manager) Remove(runtimeID common.Namespace, componentID component.ID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	log, ok := m.logs[runtimeID][componentID]
	if !ok {
		return
	}

	if err := log.Close(); err != nil {
		m.logger.Error("failed to close log handle",
			"err", err,
		)
	}

	logDir := m.getLogDirectory(runtimeID, componentID)
	if err := os.RemoveAll(logDir); err != nil {
		m.logger.Error("failed to remove log directory",
			"err", err,
			"runtime_id", runtimeID,
			"component_id", componentID,
		)
	}

	delete(m.logs[runtimeID], componentID)
	if len(m.logs[runtimeID]) == 0 {
		delete(m.logs, runtimeID)
	}
}

func (m *Manager) getLogDirectory(runtimeID common.Namespace, componentID component.ID) string {
	rawRuntimeID, _ := runtimeID.MarshalText()
	rawComponentID, _ := componentID.MarshalText()
	logDir := filepath.Join(m.logsDir, string(rawRuntimeID), string(rawComponentID))
	return logDir
}
