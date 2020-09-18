package e2e

import (
	"bytes"
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
	f.Validators = []oasis.ValidatorFixture{
		{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
	}

	return f, nil
}

func (s *genesisFileImpl) Run(childEnv *env.Env) error {
	var err error
	var out bytes.Buffer

	// Manually provision genesis file.
	s.Logger.Info("manually provisioning genesis file before starting the network")
	if err = s.Net.MakeGenesis(); err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to create genesis file")
	}
	// Set this genesis file in network's configuration.
	cfg := s.Net.Config()
	cfg.GenesisFile = s.Net.GenesisPath()

	// Checking if genesis check command works.
	args := []string{
		"genesis", "check",
		"--genesis.file", s.Net.GenesisPath(),
		"--debug.dont_blame_oasis",
		"--debug.allow_test_keys",
	}
	out, err = cli.RunSubCommandWithOutput(childEnv, s.Logger, "genesis-file", s.Net.Config().NodeBinary, args)
	if err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to run genesis check: error: %w output: %s", err, out.String())
	}
	s.Logger.Info("manually provisioned genesis file passed genesis check command")

	if err = checkGenesisFileCanonical(s.Net.GenesisPath()); err != nil {
		return fmt.Errorf("e2e/genesis-file: %w", err)
	}
	s.Logger.Info("manually provisioned genesis file equals canonical form")

	if err = s.Net.Start(); err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to start network: %w", err)
	}

	s.Logger.Info("waiting for network to come up")
	if err = s.Net.Controller().WaitNodesRegistered(context.Background(), 1); err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to wait for registered nodes: %w", err)
	}

	// Dump network state to a genesis file.
	s.Logger.Info("dumping network state to genesis file")
	dumpPath := filepath.Join(childEnv.Dir(), "genesis_dump.json")
	args = []string{
		"genesis", "dump",
		"--height", "0",
		"--genesis.file", dumpPath,
		"--address", "unix:" + s.Net.Validators()[0].SocketPath(),
	}
	out, err = cli.RunSubCommandWithOutput(childEnv, s.Logger, "genesis-file", s.Net.Config().NodeBinary, args)
	if err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to dump state: error: %w output: %s", err, out.String())
	}
	if err = checkGenesisFileCanonical(dumpPath); err != nil {
		return fmt.Errorf("e2e/genesis-file: %w", err)
	}
	s.Logger.Info("genesis file from dumped network state equals canonical form")

	// Checking if genesis convert command returns canonical form.
	convertPath := filepath.Join(childEnv.Dir(), "genesis_convert.json")
	args = []string{
		"genesis", "convert",
		"--genesis.file", dumpPath,
		"--genesis.canonical_file", convertPath,
		"--debug.dont_blame_oasis",
		"--debug.allow_test_keys",
	}
	out, err = cli.RunSubCommandWithOutput(childEnv, s.Logger, "genesis-file", s.Net.Config().NodeBinary, args)
	if err != nil {
		return fmt.Errorf("e2e/genesis-file: failed to run genesis convert: error: %w output: %s", err, out.String())
	}
	if err = checkGenesisFileCanonical(convertPath); err != nil {
		return fmt.Errorf("e2e/genesis-file: %w", err)
	}
	s.Logger.Info("genesis file generated via convert command equals canonical form")

	return nil
}

// checkGenesisFileCanonical checks if the given genesis file equals the
// canonical form.
func checkGenesisFileCanonical(filePath string) error {
	// Load genesis document from the genesis file.
	provider, err := genesisFile.NewFileProvider(filePath)
	if err != nil {
		return fmt.Errorf("failed to open genesis file: %w", err)
	}
	doc, err := provider.GetGenesisDocument()
	if err != nil {
		return fmt.Errorf("failed to get genesis document: %w", err)
	}
	// Perform sanity checks on the loaded genesis document.
	err = doc.SanityCheck()
	if err != nil {
		return fmt.Errorf("genesis document sanity check failed: %w", err)
	}

	// Load raw genesis file.
	rawFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read genesis file: %w", err)
	}
	// Create a marshalled genesis document in the canonical form with 2 space indents.
	rawCanonical, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal genesis document: %w", err)
	}
	// Genesis file should equal the canonical form.
	if !bytes.Equal(rawFile, rawCanonical) {
		fileLines := strings.Split(string(rawFile), "\n")
		canonicalLines := strings.Split(string(rawCanonical), "\n")
		return fmt.Errorf(
			"genesis document is not marshalled to the canonical form:\n"+
				"\nActual marshalled genesis document (trimmed):\n%s\n"+
				"\nExpected marshalled genesis document (trimmed):\n%s\n",
			strings.Join(fileLines[:10], "\n"), strings.Join(canonicalLines[:10], "\n"),
		)
	}
	return nil
}
