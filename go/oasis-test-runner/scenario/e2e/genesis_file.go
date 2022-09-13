package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	genesisFile "github.com/oasisprotocol/oasis-core/go/genesis/file"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

const (
	// Parameters from https://docs.oasis.io/node/mainnet.
	latestMainnetGenesisURL          = "https://github.com/oasisprotocol/mainnet-artifacts/releases/download/2022-04-11/genesis.json"
	latestMainnetGenesisDocumentHash = "b11b369e0da5bb230b220127f5e7b242d385ef8c6f54906243f30af63c815535"

	latestMainnetNeedsUpgrade = false
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
	// be possible to run this configuration as the VRF backend
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

	if _, err := s.runGenesisCheckCmd(childEnv, s.Net.GenesisPath()); err != nil {
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

	if _, err = s.runGenesisCheckCmd(childEnv, dumpPath); err != nil {
		return fmt.Errorf("e2e/genesis-file: running genesis check failed: %w", err)
	}
	s.Logger.Info("genesis file from dumped network state passed genesis check command")

	// Check if the latest Mainnet genesis file passes genesis check.
	latestMainnetGenesis := filepath.Join(childEnv.Dir(), "genesis_mainnet.json")
	if err = s.downloadLatestMainnetGenesisFile(childEnv, latestMainnetGenesis); err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to download latest Mainnet genesis "+
			"file at '%s': %w", latestMainnetGenesisURL, err)
	}

	// Convert latest Mainnet genesis file to canonical form and ensure its Genesis document's
	// hash matches the authoritative one.
	var latestMainnetGenesisFixed string
	if latestMainnetNeedsUpgrade {
		// When upgrade is needed, run fix-genesis.
		latestMainnetGenesisFixed = filepath.Join(childEnv.Dir(), "genesis_mainnet_fixed.json")
		if err = s.runFixGenesisCmd(childEnv, latestMainnetGenesis, latestMainnetGenesisFixed); err != nil {
			return fmt.Errorf("e2e/genesis-file: failed run fix-genesis on latest Mainnet genesis "+
				"file at '%s': %w", latestMainnetGenesisURL, err)
		}
	} else {
		latestMainnetGenesisFixed = latestMainnetGenesis
	}
	checkOut, err := s.runGenesisCheckCmd(childEnv, latestMainnetGenesisFixed)
	switch {
	case err != nil:
		return fmt.Errorf("e2e/genesis-file: running genesis check for the latest Mainnet"+
			" genesis file at '%s' failed: %w",
			latestMainnetGenesisURL, err,
		)
	case !latestMainnetNeedsUpgrade && !strings.Contains(checkOut, latestMainnetGenesisDocumentHash):
		return fmt.Errorf(
			"e2e/genesis-file: running genesis check for the latest Mainnet genesis "+
				"file should return the correct "+
				"genesis document's hash: '%s' (actual output: %s)",
			latestMainnetGenesisDocumentHash, checkOut,
		)
	default:
		s.Logger.Info("latest Mainnet genesis file is OK")
	}

	// Make sure a genesis file in an uncanonical form doesn't pass genesis check command and
	// returns an appropriate error.
	uncanonicalGenesis := filepath.Join(childEnv.Dir(), "genesis_uncanonical.json")
	if err = s.createUncanonicalGenesisFile(childEnv, uncanonicalGenesis); err != nil {
		return fmt.Errorf("e2e/genesis-file: creating uncanonical genesis file failed: %w", err)
	}
	_, err = s.runGenesisCheckCmd(childEnv, uncanonicalGenesis)
	expectedError := "genesis file is not in canonical form, see the diff on stderr"
	switch {
	case err == nil:
		return fmt.Errorf("e2e/genesis-file: running genesis check for an uncanonical "+
			"genesis file should fail with '%s'",
			expectedError,
		)
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

func (s *genesisFileImpl) runGenesisCheckCmd(childEnv *env.Env, genesisFilePath string) (string, error) {
	args := []string{
		"genesis", "check",
		"--genesis.file", genesisFilePath,
		"--debug.dont_blame_oasis",
		"--debug.allow_test_keys",
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, s.Logger, "genesis-file", s.Net.Config().NodeBinary, args)
	if err != nil {
		return "", fmt.Errorf("genesis check failed: error: %w output: %s", err, out.String())
	}
	return out.String(), nil
}

func (s *genesisFileImpl) runFixGenesisCmd(childEnv *env.Env, genesisFilePath, fixedGenesisFilePath string) error {
	args := []string{
		"debug", "fix-genesis",
		"--genesis.file", genesisFilePath,
		"--genesis.new_file", fixedGenesisFilePath,
		"--debug.dont_blame_oasis",
		"--debug.allow_test_keys",
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, s.Logger, "genesis-file", s.Net.Config().NodeBinary, args)
	if err != nil {
		return fmt.Errorf("debug fix-genesis failed: error: %w output: %s", err, out.String())
	}
	return nil
}

func (s *genesisFileImpl) downloadLatestMainnetGenesisFile(childEnv *env.Env, latestMainnetGenesisFilePath string) error {
	// Get the data.
	resp, err := http.Get(latestMainnetGenesisURL)
	if err != nil {
		return fmt.Errorf("failed to download genesis file: %w", err)
	}
	defer resp.Body.Close()

	// Create the file.
	out, err := os.Create(latestMainnetGenesisFilePath)
	if err != nil {
		return fmt.Errorf("failed to create genesis file: %w", err)
	}
	defer out.Close()

	// Write the body to the file.
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to copy genesis file: %w", err)
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
