package ias

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/file"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	iasProxy "github.com/oasisprotocol/oasis-core/go/ias/proxy"
)

type genesisAuthenticator struct {
	logger *logging.Logger

	enclaves *enclaveStore
}

func (auth *genesisAuthenticator) VerifyEvidence(ctx context.Context, evidence *ias.Evidence) error {
	// Since this only uses the genesis document, it is not able to
	// validate that the signer is a node scheduled for the appropriate
	// runtime.

	err := auth.enclaves.verifyEvidence(evidence)
	if err != nil {
		auth.logger.Error("rejecting proxy request, invalid runtime",
			"err", err,
			"runtime_id", evidence.RuntimeID,
		)
		return err
	}

	auth.logger.Debug("allowing proxy request, found enclave identity",
		"runtime_id", evidence.RuntimeID,
	)
	return nil
}

func newGenesisAuthenticator() (iasProxy.Authenticator, error) {
	genesisProvider, err := genesis.DefaultFileProvider()
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
	for _, rt := range doc.Registry.Runtimes {
		if _, err = auth.enclaves.addRuntime(rt); err != nil {
			return nil, err
		}
	}

	return auth, nil
}
