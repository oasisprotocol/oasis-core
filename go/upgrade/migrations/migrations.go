// Package migrations implements upgrade migration handlers.
package migrations

import (
	"github.com/oasislabs/oasis-core/go/common/logging"
	upgradeApi "github.com/oasislabs/oasis-core/go/upgrade/api"
)

const (
	// ModuleName is the migration module name.
	ModuleName = "upgrade-migrations"
)

var (
	registeredHandlers = map[string]Handler{
		DummyUpgradeName: &dummyMigrationHandler{},
	}
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
func Register(name string, handler Handler) {
	registeredHandlers[name] = handler
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
// If the handler does not exist, this is considered a severe programmer error and will result in a panic.
func GetHandler(ctx *Context) Handler {
	handler, ok := registeredHandlers[ctx.Upgrade.Descriptor.Name]
	if !ok {
		// If we got here, that means the upgrade descriptor checked out, including the upgrader hash.
		// Nothing left to do but bite the dust.
		panic("unknown upgrade name, no way forward")
	}

	return handler
}
