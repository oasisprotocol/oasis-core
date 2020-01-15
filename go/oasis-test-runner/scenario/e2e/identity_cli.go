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
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis/cli"
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

func (ident *identityCLIImpl) Name() string {
	return "identity-cli"
}

func (ident *identityCLIImpl) Init(childEnv *env.Env, net *oasis.Network) error {
	ident.nodeBinary = viper.GetString(cfgNodeBinary)

	dataDir, err := childEnv.NewSubDir("test-identity")
	if err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: init failed to create subdir: %w", err)
	}
	ident.dataDir = dataDir.String()

	return nil
}

func (ident *identityCLIImpl) Fixture() (*oasis.NetworkFixture, error) {
	return nil, nil
}

func (ident *identityCLIImpl) Run(childEnv *env.Env) error {
	args := []string{
		"identity", "init",
		"--" + common.CfgDataDir, ident.dataDir,
	}
	if err := cli.RunSubCommand(childEnv, ident.logger, "identity-init", ident.nodeBinary, args); err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: failed provision node identity: %w", err)
	}

	// Load created identity.
	factory := fileSigner.NewFactory(ident.dataDir, signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
	if _, err := identity.Load(ident.dataDir, factory); err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: failed to load node initialized identity: %w", err)
	}

	return nil
}
