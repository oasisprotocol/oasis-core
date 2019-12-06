package e2e

import (
	"fmt"

	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// IdentityCLI is the identity CLI scenario.
	IdentityCLI scenario.Scenario = &identityCLIImpl{
		logger: logging.GetLogger("scenario/e2e/identity-cli"),
	}
)

type identityCLIImpl struct {
	nodeBinary string
	dataDir    string

	logger *logging.Logger
}

func (i *identityCLIImpl) Name() string {
	return "identity-cli"
}

func (i *identityCLIImpl) Init(childEnv *env.Env, net *oasis.Network) error {
	i.nodeBinary = viper.GetString(cfgNodeBinary)

	dataDir, err := childEnv.NewSubDir("test-identity")
	if err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: init failed to create subdir: %w", err)
	}
	i.dataDir = dataDir.String()

	return nil
}

func (i *identityCLIImpl) Fixture() (*oasis.NetworkFixture, error) {
	return nil, nil
}

func (i *identityCLIImpl) Run(childEnv *env.Env) error {
	args := []string{
		"identity", "init",
		"--" + common.CfgDataDir, i.dataDir,
	}
	if err := runSubCommand(childEnv, "identity-init", i.nodeBinary, args); err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: failed provision node identity: %w", err)
	}

	// Load created identity.
	factory := fileSigner.NewFactory(i.dataDir, signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
	if _, err := identity.Load(i.dataDir, factory); err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: failed to load node initialized identity: %w", err)
	}

	return nil
}
