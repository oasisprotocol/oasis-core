package e2e

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// IdentityCLI is the identity CLI scenario.
	IdentityCLI scenario.Scenario = &identityCLIImpl{
		e2eImpl: *newE2eImpl("identity-cli"),
	}
)

type identityCLIImpl struct {
	e2eImpl

	dataDir string
}

func (ident *identityCLIImpl) Clone() scenario.Scenario {
	return &identityCLIImpl{
		e2eImpl: ident.e2eImpl.Clone(),
		dataDir: ident.dataDir,
	}
}

func (ident *identityCLIImpl) PreInit(childEnv *env.Env) error {
	return nil
}

func (ident *identityCLIImpl) Init(childEnv *env.Env, net *oasis.Network) error {
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
	// Provision node's identity.
	args := []string{
		"identity", "init",
		"--" + common.CfgDataDir, ident.dataDir,
	}
	nodeBinary, _ := ident.flags.GetString(cfgNodeBinary)
	if err := cli.RunSubCommand(childEnv, ident.logger, "identity-init", nodeBinary, args); err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: failed provision node's identity: %w", err)
	}

	if err := ident.loadIdentity(); err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: %w", err)
	}

	if err := ident.tendermintShowAddress(childEnv, "node"); err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: %w", err)
	}
	if err := ident.tendermintShowAddress(childEnv, "consensus"); err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: %w", err)
	}

	return nil
}

func (ident *identityCLIImpl) loadIdentity() error {
	ident.logger.Info("loading generated entity")

	factory, err := fileSigner.NewFactory(ident.dataDir, signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
	if err != nil {
		return fmt.Errorf("failed to create identity file signer: %w", err)
	}
	if _, err = identity.Load(ident.dataDir, factory); err != nil {
		return fmt.Errorf("failed to load node's identity: %w", err)
	}
	return nil
}

func (ident *identityCLIImpl) tendermintShowAddress(childEnv *env.Env, addrName string) error {
	subCmd := fmt.Sprintf("show-%s-address", addrName)
	ident.logger.Info(fmt.Sprintf("running tendermint %s", subCmd))

	args := []string{
		"identity", "tendermint", subCmd,
		"--" + common.CfgDataDir, ident.dataDir,
	}
	nodeBinary, _ := ident.flags.GetString(cfgNodeBinary)
	if out, err := cli.RunSubCommandWithOutput(childEnv, ident.logger, subCmd, nodeBinary, args); err != nil {
		return fmt.Errorf("failed to get %s's tendermint address: error: %w output: %s", addrName, err, out.String())
	}
	return nil
}
