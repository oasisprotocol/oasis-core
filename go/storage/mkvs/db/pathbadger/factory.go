package pathbadger

import "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"

// Factory is the node database factory for the PathBadger backend.
var Factory = &factory{}

type factory struct{}

// New implements api.Factory.
func (f *factory) New(cfg *api.Config) (api.NodeDB, error) {
	return New(cfg)
}

// Name implements api.Factory.
func (f *factory) Name() string {
	return "pathbadger"
}
