package ias

import (
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	cmnIAS "github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

type enclaveStore struct {
	sync.RWMutex

	enclaves map[common.Namespace][]sgx.EnclaveIdentity
}

func (st *enclaveStore) verifyEvidence(evidence *ias.Evidence) error {
	st.RLock()
	defer st.RUnlock()

	enclaveIDs, ok := st.enclaves[evidence.RuntimeID]
	if !ok {
		return fmt.Errorf("ias: unknown runtime: %v", evidence.RuntimeID)
	}

	var quote cmnIAS.Quote
	if err := quote.UnmarshalBinary(evidence.Quote); err != nil {
		return fmt.Errorf("ias: evidence contains an invalid quote: %w", err)
	}

	id := sgx.EnclaveIdentity{
		MrEnclave: quote.Report.MRENCLAVE,
		MrSigner:  quote.Report.MRSIGNER,
	}

	for _, v := range enclaveIDs {
		if v == id {
			return nil
		}
	}

	return fmt.Errorf("ias: enclave identity not in runtime descriptor: %v", id)
}

func (st *enclaveStore) addRuntime(runtime *registry.Runtime) (int, error) {
	st.Lock()
	defer st.Unlock()

	if runtime.TEEHardware != node.TEEHardwareIntelSGX {
		return len(st.enclaves), nil
	}

	// Regenerate the enclave ID list by iterating over all of the deployments.
	var enclaveIDs []sgx.EnclaveIdentity
	for _, deployment := range runtime.Deployments {
		var cs node.SGXConstraints
		if err := cbor.Unmarshal(deployment.TEE, &cs); err != nil {
			return len(st.enclaves), err
		}

		enclaveIDs = append(enclaveIDs, cs.Enclaves...)
	}

	st.enclaves[runtime.ID] = enclaveIDs

	return len(st.enclaves), nil
}

func newEnclaveStore() *enclaveStore {
	return &enclaveStore{
		enclaves: make(map[common.Namespace][]sgx.EnclaveIdentity),
	}
}
