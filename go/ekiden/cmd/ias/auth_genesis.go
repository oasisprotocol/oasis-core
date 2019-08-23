package ias

import (
	"bytes"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/sgx"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
	"github.com/oasislabs/ekiden/go/genesis"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

type genesisAuthenticator struct {
	logger   *logging.Logger
	enclaves map[signature.MapKey][]sgx.EnclaveIdentity
}

func (auth *genesisAuthenticator) VerifyEvidence(signer signature.PublicKey, evidence *ias.Evidence) error {
	// Since this only uses the genesis document, it is not able to
	// validate that the signer is a node scheduled for the appropriate
	// runtime.

	enclaveIDs, ok := auth.enclaves[evidence.ID.ToMapKey()]
	if !ok {
		auth.logger.Error("not a genesis runtime",
			"id", evidence.ID,
		)
		return errors.New("ias: not a runtime specified in genesis")
	}

	quote, err := ias.DecodeQuote(evidence.Quote)
	if err != nil {
		auth.logger.Error("evidence contains an invalid quote",
			"err", err,
		)
		return errors.Wrap(err, "ias: evidence contains an invalid quote")
	}

	var id sgx.EnclaveIdentity
	id.FromComponents(quote.Report.MRSIGNER, quote.Report.MRENCLAVE)

	for _, v := range enclaveIDs {
		if bytes.Equal(v[:], id[:]) {
			auth.logger.Debug("found enclave identity in genesis runtime descriptor",
				"id", evidence.ID,
				"enclave_identity", id,
			)
			return nil
		}
	}

	auth.logger.Error("enclave identity not in genesis runtime descriptor",
		"id", evidence.ID,
		"enclave_identity", id,
	)
	return errors.New("ias: enclave identity not in genesis runtime descriptor")
}

func newGenesisAuthenticator() (ias.GRPCAuthenticator, error) {
	genesisProvider, err := genesis.New()
	if err != nil {
		return nil, err
	}

	doc, err := genesisProvider.GetGenesisDocument()
	if err != nil {
		return nil, err
	}

	auth := &genesisAuthenticator{
		logger:   logging.GetLogger("cmd/ias/proxy/auth/genesis"),
		enclaves: make(map[signature.MapKey][]sgx.EnclaveIdentity),
	}
	for _, v := range doc.Registry.Runtimes {
		var rt registry.Runtime
		if err = v.Open(registry.RegisterGenesisRuntimeSignatureContext, &rt); err != nil {
			return nil, err
		}

		if rt.TEEHardware != node.TEEHardwareIntelSGX {
			continue
		}
		if len(rt.Version.TEE) == 0 {
			continue
		}

		var vi registry.VersionInfoIntelSGX
		if err = cbor.Unmarshal(rt.Version.TEE, &vi); err != nil {
			return nil, err
		}

		auth.enclaves[rt.ID.ToMapKey()] = vi.Enclaves
	}

	return auth, nil
}
