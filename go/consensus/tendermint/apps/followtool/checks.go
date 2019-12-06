package followtool

import (
	"fmt"

	"github.com/tendermint/iavl"

	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

func checkEpochTime(*iavl.MutableTree) error {
	// nothing to check yet
	return nil
}

func checkRegistry(state *iavl.MutableTree) error {
	st := registryState.NewMutableState(state)

	// Check entities.
	entities, err := st.SignedEntities()
	if err != nil {
		return fmt.Errorf("SignedEntities: %w", err)
	}
	seenEntities, err := registry.SanityCheckEntities(entities)
	if err != nil {
		return fmt.Errorf("SanityCheckEntities: %w", err)
	}

	// Check runtimes.
	runtimes, err := st.SignedRuntimes()
	if err != nil {
		return fmt.Errorf("SignedRuntimes: %w", err)
	}
	seenRuntimes, err := registry.SanityCheckRuntimes(runtimes)
	if err != nil {
		return fmt.Errorf("SanityCheckRuntimes: %w", err)
	}

	// Check nodes.
	nodes, err := st.SignedNodes()
	if err != nil {
		return fmt.Errorf("SignedNodes: %w", err)
	}
	err = registry.SanityCheckNodes(nodes, seenEntities, seenRuntimes)
	if err != nil {
		return fmt.Errorf("SanityCheckNodes: %w", err)
	}

	return nil
}

func checkRootHash(*iavl.MutableTree) error {
	// nothing to check yet
	return nil
}

func checkStaking(*iavl.MutableTree) error {
	// nothing to check yet
	return nil
}

func checkKeyManager(*iavl.MutableTree) error {
	// nothing to check yet
	return nil
}

func checkScheduler(*iavl.MutableTree) error {
	// nothing to check yet
	return nil
}

func checkBeacon(*iavl.MutableTree) error {
	// nothing to check yet
	return nil
}

func checkConsensus(*iavl.MutableTree) error {
	// nothing to check yet
	return nil
}

func checkHalt(*iavl.MutableTree) error {
	// nothing to check yet
	return nil
}
