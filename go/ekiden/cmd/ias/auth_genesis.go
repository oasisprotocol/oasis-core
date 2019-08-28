package ias

import (
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
	"github.com/oasislabs/ekiden/go/genesis"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

type genesisAuthenticator struct {
	logger *logging.Logger

	enclaves *enclaveStore
}

func (auth *genesisAuthenticator) VerifyEvidence(signer signature.PublicKey, evidence *ias.Evidence) error {
	// Since this only uses the genesis document, it is not able to
	// validate that the signer is a node scheduled for the appropriate
	// runtime.

	err := auth.enclaves.verifyEvidence(evidence)
	if err != nil {
		auth.logger.Error("rejecting proxy request, invalid runtime",
			"err", err,
			"id", evidence.ID,
		)
		return err
	}

	auth.logger.Debug("allowing proxy request, found enclave identity",
		"id", evidence.ID,
	)
	return nil
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
		enclaves: newEnclaveStore(),
	}
	for _, v := range doc.Registry.Runtimes {
		var rt registry.Runtime
		if err = v.Open(registry.RegisterGenesisRuntimeSignatureContext, &rt); err != nil {
			return nil, err
		}

		if _, err = auth.enclaves.addRuntime(&rt); err != nil {
			return nil, err
		}
	}

	return auth, nil
}
