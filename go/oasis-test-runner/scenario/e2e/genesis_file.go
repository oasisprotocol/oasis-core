package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	genesisFile "github.com/oasisprotocol/oasis-core/go/genesis/file"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// GenesisFile is the scenario for testing the correctness of marshalled genesis
// documents.
var GenesisFile scenario.Scenario = &genesisFileImpl{
	E2E: *NewE2E("genesis-file"),
}

type genesisFileImpl struct {
	E2E
}

func (s *genesisFileImpl) Clone() scenario.Scenario {
	return &genesisFileImpl{
		E2E: s.E2E.Clone(),
	}
}

func (s *genesisFileImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := s.E2E.Fixture()
	if err != nil {
		return nil, err
	}

	// A single validator is enough for this scenario.
	//
	// WARNING: Once the insecure backend goes away, it will no longer
	// be possible to run this configuration as the PVSS backend
	// currently requires multiple validators.
	f.Validators = []oasis.ValidatorFixture{
		{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true, SupplementarySanityInterval: 1}},
	}
	f.Network.SetInsecureBeacon()

	return f, nil
}

func (s *genesisFileImpl) Run(childEnv *env.Env) error {
	// Manually provision genesis file.
	s.Logger.Info("manually provisioning genesis file before starting the network")
	if err := s.Net.MakeGenesis(); err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to create genesis file: %w", err)
	}
	// Set this genesis file in network's configuration.
	cfg := s.Net.Config()
	cfg.GenesisFile = s.Net.GenesisPath()

	if err := s.runGenesisCheckCmd(childEnv, s.Net.GenesisPath()); err != nil {
		return fmt.Errorf("e2e/genesis-file: running genesis check failed: %w", err)
	}
	s.Logger.Info("manually provisioned genesis file passed genesis check command")

	if err := s.Net.Start(); err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to start network: %w", err)
	}

	s.Logger.Info("waiting for network to come up")
	if err := s.Net.Controller().WaitNodesRegistered(context.Background(), 1); err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to wait for registered nodes: %w", err)
	}

	// Dump network state to a genesis file.
	s.Logger.Info("dumping network state to genesis file")
	dumpPath := filepath.Join(childEnv.Dir(), "genesis_dump.json")
	args := []string{
		"genesis", "dump",
		"--height", "0",
		"--genesis.file", dumpPath,
		"--address", "unix:" + s.Net.Validators()[0].SocketPath(),
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, s.Logger, "genesis-file", s.Net.Config().NodeBinary, args)
	if err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to dump state: error: %w output: %s", err, out.String())
	}

	if err = s.runGenesisCheckCmd(childEnv, dumpPath); err != nil {
		return fmt.Errorf("e2e/genesis-file: running genesis check failed: %w", err)
	}
	s.Logger.Info("genesis file from dumped network state passed genesis check command")

	uncanonicalPath := filepath.Join(childEnv.Dir(), "genesis_uncanonical.json")
	if err = s.createUncanonicalGenesisFile(childEnv, uncanonicalPath); err != nil {
		return fmt.Errorf("e2e/genesis-file: creating uncanonical genesis file failed: %w", err)
	}
	err = s.runGenesisCheckCmd(childEnv, uncanonicalPath)
	expectedError := "genesis file is not in canonical form, see the diff on stderr"
	switch {
	case err == nil:
		return fmt.Errorf("e2e/genesis-file: running genesis check for an uncanonical genesis file should fail")
	case !strings.Contains(err.Error(), expectedError):
		return fmt.Errorf(
			"e2e/genesis-file: running genesis check for an uncanonical genesis file "+
				"should fail with an error containing: '%s' (actual error: %s)",
			expectedError, err,
		)
	default:
		s.Logger.Info("uncanonical genesis file didn't pass genesis check command")
	}

	return nil
}

func (s *genesisFileImpl) runGenesisCheckCmd(childEnv *env.Env, genesisFilePath string) error {
	args := []string{
		"genesis", "check",
		"--genesis.file", genesisFilePath,
		"--debug.dont_blame_oasis",
		"--debug.allow_test_keys",
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, s.Logger, "genesis-file", s.Net.Config().NodeBinary, args)
	if err != nil {
		return fmt.Errorf("genesis check failed: error: %w output: %s", err, out.String())
	}
	return nil
}

func (s *genesisFileImpl) createUncanonicalGenesisFile(childEnv *env.Env, uncanonicalGenesisFilePath string) error {
	provider, err := genesisFile.NewFileProvider(s.Net.GenesisPath())
	if err != nil {
		return fmt.Errorf("failed to open genesis file: %w", err)
	}
	doc, err := provider.GetGenesisDocument()
	if err != nil {
		return fmt.Errorf("failed to get genesis document: %w", err)
	}

	// Create a marshalled genesis document in an uncanonical form (e.g with 4 space indents).
	rawUncanonical, err := json.MarshalIndent(doc, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal genesis document: %w", err)
	}
	if err := ioutil.WriteFile(uncanonicalGenesisFilePath, rawUncanonical, 0o600); err != nil {
		return fmt.Errorf("failed to write mashalled genesis document to file: %w", err)
	}

	return nil
}
