package e2e

import (
	"fmt"

	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// IdentityCLI is the identity CLI scenario.
var IdentityCLI scenario.Scenario = &identityCLIImpl{
	E2E: *NewE2E("identity-cli"),
}

type identityCLIImpl struct {
	E2E

	dataDir string
}

func (sc *identityCLIImpl) Clone() scenario.Scenario {
	return &identityCLIImpl{
		E2E:     sc.E2E.Clone(),
		dataDir: sc.dataDir,
	}
}

func (sc *identityCLIImpl) PreInit(childEnv *env.Env) error {
	return nil
}

func (sc *identityCLIImpl) Init(childEnv *env.Env, net *oasis.Network) error {
	dataDir, err := childEnv.NewSubDir("test-identity")
	if err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: init failed to create subdir: %w", err)
	}
	sc.dataDir = dataDir.String()

	return nil
}

func (sc *identityCLIImpl) Fixture() (*oasis.NetworkFixture, error) {
	return nil, nil
}

func (sc *identityCLIImpl) Run(childEnv *env.Env) error {
	// Provision node's identity.
	args := []string{
		"identity", "init",
		"--" + common.CfgDataDir, sc.dataDir,
	}
	nodeBinary, _ := sc.Flags.GetString(cfgNodeBinary)
	if err := cli.RunSubCommand(childEnv, sc.Logger, "identity-init", nodeBinary, args); err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: failed provision node's identity: %w", err)
	}

	if err := sc.loadIdentity(); err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: %w", err)
	}
	if err := sc.showTLSPubkey(childEnv, false); err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: %w", err)
	}
	if err := sc.showTLSPubkey(childEnv, true); err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: %w", err)
	}
	if err := sc.tendermintShowAddress(childEnv, "node"); err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: %w", err)
	}
	if err := sc.tendermintShowAddress(childEnv, "consensus"); err != nil {
		return fmt.Errorf("scenario/e2e/identity_cli: %w", err)
	}

	return nil
}

func (sc *identityCLIImpl) loadIdentity() error {
	sc.Logger.Info("loading generated entity")

	factory, err := fileSigner.NewFactory(sc.dataDir, identity.RequiredSignerRoles...)
	if err != nil {
		return fmt.Errorf("failed to create identity file signer: %w", err)
	}
	if _, err = identity.Load(sc.dataDir, factory); err != nil {
		return fmt.Errorf("failed to load node's identity: %w", err)
	}
	return nil
}

func (sc *identityCLIImpl) showTLSPubkey(childEnv *env.Env, sentry bool) error {
	var subCmd string
	switch sentry {
	case true:
		subCmd = "show-sentry-client-pubkey"
	case false:
		subCmd = "show-tls-pubkey"
	}
	sc.Logger.Info(fmt.Sprintf("running %s", subCmd))

	args := []string{
		"identity", subCmd,
		"--" + common.CfgDataDir, sc.dataDir,
	}
	nodeBinary, _ := sc.Flags.GetString(cfgNodeBinary)
	if out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, subCmd, nodeBinary, args); err != nil {
		return fmt.Errorf("failed to run %s: error: %w output: %s", subCmd, err, out.String())
	}
	return nil
}

func (sc *identityCLIImpl) tendermintShowAddress(childEnv *env.Env, addrName string) error {
	subCmd := fmt.Sprintf("show-%s-address", addrName)
	sc.Logger.Info(fmt.Sprintf("running tendermint %s", subCmd))

	args := []string{
		"identity", "tendermint", subCmd,
		"--" + common.CfgDataDir, sc.dataDir,
	}
	nodeBinary, _ := sc.Flags.GetString(cfgNodeBinary)
	if out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, subCmd, nodeBinary, args); err != nil {
		return fmt.Errorf("failed to get %s's tendermint address: error: %w output: %s", addrName, err, out.String())
	}
	return nil
}
