package ias

import (
	"sync"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	cmnIAS "github.com/oasislabs/oasis-core/go/common/sgx/ias"
	ias "github.com/oasislabs/oasis-core/go/ias/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
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
		return errors.New("ias: unknown runtime")
	}

	var quote cmnIAS.Quote
	if err := quote.UnmarshalBinary(evidence.Quote); err != nil {
		return errors.Wrap(err, "ias: evidence contains an invalid quote")
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

	return errors.New("ias: enclave identity not in runtime descriptor")
}

func (st *enclaveStore) addRuntime(runtime *registry.Runtime) (int, error) {
	st.Lock()
	defer st.Unlock()

	if runtime.TEEHardware != node.TEEHardwareIntelSGX {
		return len(st.enclaves), nil
	}

	var vi registry.VersionInfoIntelSGX
	if err := cbor.Unmarshal(runtime.Version.TEE, &vi); err != nil {
		return len(st.enclaves), err
	}

	st.enclaves[runtime.ID] = vi.Enclaves

	return len(st.enclaves), nil
}

func newEnclaveStore() *enclaveStore {
	return &enclaveStore{
		enclaves: make(map[common.Namespace][]sgx.EnclaveIdentity),
	}
}
