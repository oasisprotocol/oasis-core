package ias

import (
	"bytes"
	"sync"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/sgx"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

type enclaveStore struct {
	sync.RWMutex

	enclaves map[signature.MapKey][]sgx.EnclaveIdentity
}

func (st *enclaveStore) verifyEvidence(evidence *ias.Evidence) error {
	st.RLock()
	defer st.RUnlock()

	enclaveIDs, ok := st.enclaves[evidence.ID.ToMapKey()]
	if !ok {
		return errors.New("ias: unknown runtime")
	}

	quote, err := ias.DecodeQuote(evidence.Quote)
	if err != nil {
		return errors.Wrap(err, "ias: evidence contains an invalid quote")
	}

	var id sgx.EnclaveIdentity
	id.FromComponents(quote.Report.MRSIGNER, quote.Report.MRENCLAVE)

	for _, v := range enclaveIDs {
		if bytes.Equal(v[:], id[:]) {
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

	st.enclaves[runtime.ID.ToMapKey()] = vi.Enclaves

	return len(st.enclaves), nil
}

func newEnclaveStore() *enclaveStore {
	return &enclaveStore{
		enclaves: make(map[signature.MapKey][]sgx.EnclaveIdentity),
	}
}
