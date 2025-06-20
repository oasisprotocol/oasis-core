package stateless

import (
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
)

type nonePruner struct{}

// RegisterHandler implements consensusAPI.StatePruner.
func (p *nonePruner) RegisterHandler(consensusAPI.StatePruneHandler) {
}
