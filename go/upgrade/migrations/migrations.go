// Package migrations implements upgrade migration handlers.
package migrations

import (
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	upgradeApi "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

const (
	// ModuleName is the migration module name.
	ModuleName = "upgrade-migrations"
)

var (
	registeredHandlers sync.Map

	// ErrMissingMigrationHandler is error returned when a migration handler is not registered.
	ErrMissingMigrationHandler = fmt.Errorf("missing migration handler")
)

// Handler is the interface used by migration handlers.
type Handler interface {
	// StartupUpgrade is called by the upgrade manager to perform
	// the node startup portion of the upgrade.
	StartupUpgrade(*Context) error

	// ConsensusUpgrade is called by the upgrade manager to perform
	// the consensus portion of the upgrade. The interface argument is
	// a private structure passed to Backend.ConsensusUpgrade by the
	// consensus backend.
	//
	// This method will be called twice, once in BeginBlock and once in
	// EndBlock.
	ConsensusUpgrade(*Context, interface{}) error
}

// Context defines the common context used by migration handlers.
type Context struct {
	// Upgrade is the currently pending upgrade structure.
	Upgrade *upgradeApi.PendingUpgrade

	// DataDir is the node's data directory.
	DataDir string

	Logger *logging.Logger
}

// Register registers a new migration handler, by upgrade name.
func Register(name upgradeApi.HandlerName, handler Handler) {
	if err := name.ValidateBasic(); err != nil {
		panic(fmt.Errorf("migration handler name error: %w", err))
	}
	if _, isRegistered := registeredHandlers.Load(name); isRegistered {
		panic(fmt.Errorf("migration handler already registered: %s", name))
	}
	registeredHandlers.Store(name, handler)
}

// NewContext returns a new upgrade migration context.
func NewContext(upgrade *upgradeApi.PendingUpgrade, dataDir string) *Context {
	return &Context{
		Upgrade: upgrade,
		DataDir: dataDir,
		Logger:  logging.GetLogger(ModuleName),
	}
}

// GetHandler returns the handler associated with the upgrade described in the context.
func GetHandler(name upgradeApi.HandlerName) (Handler, error) {
	h, exists := registeredHandlers.Load(name)
	if !exists {
		return nil, ErrMissingMigrationHandler
	}

	return h.(Handler), nil
}
