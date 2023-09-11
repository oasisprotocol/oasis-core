package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	// Mainnet genesis dump at height: 11645601.
	genesisURL    = "https://oasis-artifacts.s3.us-east-2.amazonaws.com/genesis_mainnet_dump_11645601.json"
	genesisSHA256 = "16386902d822227d0ba1e011ab84a754a48c61457e06240986f9c00e84895459" // #nosec G101

	genesisNeedsUpgrade = true
	// Only relevant if genesis file doesn't need upgrade.
	genesisDocumentHash = "b11b369e0da5bb230b220127f5e7b242d385ef8c6f54906243f30af63c815535" // #nosec G101
)

// GenesisFile is the scenario for testing the correctness of marshalled genesis
// documents.
var GenesisFile scenario.Scenario = &genesisFileImpl{
	Scenario: *NewScenario("genesis-file"),
}

type genesisFileImpl struct {
	Scenario
}

func (s *genesisFileImpl) Clone() scenario.Scenario {
	return &genesisFileImpl{
		Scenario: s.Scenario.Clone(),
	}
}

func (s *genesisFileImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := s.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// A single validator is enough for this scenario.
	//
	// WARNING: Once the insecure backend goes away, it will no longer
	// be possible to run this configuration as the VRF backend
	// currently requires multiple validators.
	f.Validators = []oasis.ValidatorFixture{
		{Entity: 1, Consensus: oasis.ConsensusFixture{SupplementarySanityInterval: 1}},
	}
	f.Network.SetInsecureBeacon()

	return f, nil
}

func (s *genesisFileImpl) Run(ctx context.Context, childEnv *env.Env) error {
	cli := cli.New(childEnv, s.Net, s.Logger)

	// Manually provision genesis file.
	s.Logger.Info("manually provisioning genesis file before starting the network")
	if err := s.Net.MakeGenesis(); err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to create genesis file: %w", err)
	}
	// Set this genesis file in network's configuration.
	cfg := s.Net.Config()
	cfg.GenesisFile = s.Net.GenesisPath()

	if _, err := cli.Genesis.Check(s.Net.GenesisPath()); err != nil {
		return fmt.Errorf("e2e/genesis-file: running genesis check failed: %w", err)
	}
	s.Logger.Info("manually provisioned genesis file passed genesis check command")

	if err := s.Net.Start(); err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to start network: %w", err)
	}

	s.Logger.Info("waiting for network to come up")
	if err := s.Net.Controller().WaitNodesRegistered(ctx, 1); err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to wait for registered nodes: %w", err)
	}

	// Dump network state to a genesis file.
	s.Logger.Info("dumping network state to genesis file")
	dumpPath := filepath.Join(childEnv.Dir(), "genesis_dump.json")
	if err := cli.Genesis.Dump(dumpPath); err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to dump state: %w", err)
	}

	if _, err := cli.Genesis.Check(dumpPath); err != nil {
		return fmt.Errorf("e2e/genesis-file: running genesis check failed: %w", err)
	}
	s.Logger.Info("genesis file from dumped network state passed genesis check command")

	// Check if the latest Mainnet genesis file passes genesis check.
	latestMainnetGenesis := filepath.Join(childEnv.Dir(), "genesis_mainnet.json")
	if err := s.downloadGenesisFile(childEnv, latestMainnetGenesis); err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to download latest Mainnet genesis "+
			"file at '%s': %w", genesisURL, err)
	}

	// Convert latest Mainnet genesis file to canonical form and ensure its Genesis document's
	// hash matches the authoritative one.
	var latestMainnetGenesisFixed string
	if genesisNeedsUpgrade {
		// When upgrade is needed, run fix-genesis.
		latestMainnetGenesisFixed = filepath.Join(childEnv.Dir(), "genesis_mainnet_fixed.json")
		if err := cli.Genesis.Migrate(latestMainnetGenesis, latestMainnetGenesisFixed); err != nil {
			return fmt.Errorf("e2e/genesis-file: failed run fix-genesis on latest Mainnet genesis "+
				"file at '%s': %w", genesisURL, err)
		}
	} else {
		latestMainnetGenesisFixed = latestMainnetGenesis
	}
	checkOut, err := cli.Genesis.Check(latestMainnetGenesisFixed)
	switch {
	case err != nil:
		return fmt.Errorf("e2e/genesis-file: running genesis check for the latest Mainnet"+
			" genesis file at '%s' failed: %w",
			genesisURL, err,
		)
	case !genesisNeedsUpgrade && !strings.Contains(checkOut, genesisDocumentHash):
		return fmt.Errorf(
			"e2e/genesis-file: running genesis check for the latest Mainnet genesis "+
				"file should return the correct "+
				"genesis document's hash: '%s' (actual output: %s)",
			genesisDocumentHash, checkOut,
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
	_, err = cli.Genesis.Check(uncanonicalGenesis)
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

func (s *genesisFileImpl) downloadGenesisFile(_ *env.Env, path string) error {
	// Get the data.
	resp, err := http.Get(genesisURL)
	if err != nil {
		return fmt.Errorf("failed to download genesis file: %w", err)
	}
	defer resp.Body.Close()

	// Create the file.
	outf, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create genesis file: %w", err)
	}
	defer outf.Close()

	// Also compute the hash.
	outh := sha256.New()
	out := io.MultiWriter(outf, outh)

	// Write the body to the file.
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to copy genesis file: %w", err)
	}

	// Ensure the file hash matches.
	h := outh.Sum(nil)
	expected, err := hex.DecodeString(genesisSHA256)
	if err != nil {
		return fmt.Errorf("invalid expected hash '%s': %w", expected, err)
	}
	if !bytes.Equal(h, expected) {
		return fmt.Errorf("invalid genesis file hash: got: '%x', expected: '%x'", h, expected)
	}
	return nil
}

func (s *genesisFileImpl) createUncanonicalGenesisFile(_ *env.Env, uncanonicalGenesisFilePath string) error {
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
	if err := os.WriteFile(uncanonicalGenesisFilePath, rawUncanonical, 0o600); err != nil {
		return fmt.Errorf("failed to write mashalled genesis document to file: %w", err)
	}

	return nil
}
