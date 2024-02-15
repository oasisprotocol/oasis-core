package db

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	backendBadger "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/badger"
	backendPathBadger "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/pathbadger"
)

// Backends contains the factories for all the backend implementations.
var Backends = []api.Factory{
	backendBadger.Factory,
	backendPathBadger.Factory,
}

// GetBackendByName returns the backend implementation factory with the given name.
func GetBackendByName(name string) (api.Factory, error) {
	for _, factory := range Backends {
		if name == factory.Name() {
			return factory, nil
		}
	}
	return nil, fmt.Errorf("unsupported node database backend: %s", name)
}

// New creates a given named database backend.
func New(name string, cfg *api.Config) (api.NodeDB, error) {
	factory, err := GetBackendByName(name)
	if err != nil {
		return nil, err
	}
	return factory.New(cfg)
}
