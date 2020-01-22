package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"reflect"

	genesis "github.com/oasislabs/oasis-core/go/genesis/file"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// HaltRestore is the halt and restore scenario.
	HaltRestore scenario.Scenario = newHaltRestoreImpl()

	dumpGlob = "genesis-*.json"
)

const haltEpoch = 3

type haltRestoreImpl struct {
	basicImpl
}

func newHaltRestoreImpl() scenario.Scenario {
	return &haltRestoreImpl{
		basicImpl: *newBasicImpl(
			"halt-restore",
			"test-long-term-client",
			[]string{"--mode", "part1"},
		),
	}
}

func (sc *haltRestoreImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}
	f.Network.HaltEpoch = haltEpoch
	for _, val := range f.Validators {
		val.Restartable = true
	}
	return f, nil
}

func (sc *haltRestoreImpl) getExportedGenesisFiles() ([]string, error) {
	// Gather all nodes.
	var nodes []interface {
		ExportsPath() string
	}
	for _, v := range sc.net.Validators() {
		nodes = append(nodes, v)
	}
	for _, n := range sc.net.ComputeWorkers() {
		nodes = append(nodes, n)
	}
	for _, n := range sc.net.StorageWorkers() {
		nodes = append(nodes, n)
	}
	for _, n := range sc.net.Keymanagers() {
		nodes = append(nodes, n)
	}

	// Gather all genesis files.
	var files []string
	for _, node := range nodes {
		dumpGlobPath := filepath.Join(node.ExportsPath(), dumpGlob)
		globMatch, err := filepath.Glob(dumpGlobPath)
		if err != nil {
			return nil, fmt.Errorf("glob failed: %s: %w", dumpGlobPath, err)
		}
		if len(globMatch) == 0 {
			return nil, fmt.Errorf("genesis file not found in: %s", dumpGlobPath)
		}
		if len(globMatch) > 1 {
			return nil, fmt.Errorf("more than one genesis file found in: %s", dumpGlobPath)
		}
		files = append(files, globMatch[0])
	}

	// Assert all exported files match.
	var firstHash hash.Hash
	for _, file := range files {
		// Compute hash.
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %s: %w", file, err)
		}
		defer f.Close()
		hnew := sha256.New()
		if _, err := io.Copy(hnew, f); err != nil {
			return nil, fmt.Errorf("sha256 failed on: %s: %w", file, err)
		}
		if firstHash == nil {
			firstHash = hnew
		}

		// Compare hash with first hash.
		if !bytes.Equal(firstHash.Sum(nil), hnew.Sum(nil)) {
			return nil, fmt.Errorf("exported genesis files do not match %s, %s", files[0], file)
		}
	}

	return files, nil
}

func (sc *haltRestoreImpl) Run(childEnv *env.Env) error {
	clientErrCh, cmd, err := sc.basicImpl.start(childEnv)
	if err != nil {
		return err
	}

	// Wait for the client to exit.
	select {
	case err = <-sc.basicImpl.net.Errors():
		_ = cmd.Process.Kill()
	case err = <-clientErrCh:
	}
	if err != nil {
		return err
	}

	// Wait for the epoch after the halt epoch.
	ctx := context.Background()
	sc.logger.Info("waiting for halt epoch")
	// Wait for halt epoch.
	err = sc.net.Controller().Consensus.WaitEpoch(ctx, haltEpoch)
	if err != nil {
		return fmt.Errorf("scenario/e2e/halt_restore: failed waiting for halt epoch: %w", err)
	}

	// Wait for validators to exit so that genesis docs are dumped.
	var exitChs []reflect.SelectCase
	for _, val := range sc.net.Validators() {
		exitChs = append(exitChs, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(val.Exit()),
		})
	}
	// Exit status doesn't matter, we only need one of the validators to stop existing.
	_, _, _ = reflect.Select(exitChs)

	sc.logger.Info("gathering exported genesis files")
	files, err := sc.getExportedGenesisFiles()
	if err != nil {
		return fmt.Errorf("scenario/e2e/halt_restore: failure getting exported genesis files: %w", err)
	}

	// Stop the network.
	sc.logger.Info("stopping the network")
	sc.basicImpl.net.Stop()
	if err = sc.basicImpl.cleanTendermintStorage(childEnv); err != nil {
		return fmt.Errorf("scenario/e2e/halt_restore: failed to clean tendemint storage: %w", err)
	}

	// Start the network and the client again and check that everything
	// works with restored state.
	sc.logger.Info("starting the network again")

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	// Update halt epoch in the exported genesis so the network doesn't
	// instantly halt.
	genesisFileProvider, err := genesis.NewFileProvider(files[0])
	if err != nil {
		sc.logger.Error("scenario/e2e/halt_restore: failed getting genesis file provider",
			"err", err,
			"genesis_file", files[0],
		)
		return err
	}
	genesisDoc, err := genesisFileProvider.GetGenesisDocument()
	if err != nil {
		sc.logger.Error("scenario/e2e/halt_restore: failed getting genesis document from file provider",
			"err", err,
		)
		return err
	}
	genesisDoc.HaltEpoch = genesisDoc.EpochTime.Base + haltEpoch
	if err = genesisDoc.WriteFileJSON(files[0]); err != nil {
		sc.logger.Error("scenario/e2e/halt_restore: failed to update genesis",
			"err", err,
		)
		return err
	}

	// Use the updated genesis file.
	fixture.Network.GenesisFile = files[0]
	// Make sure to not overwrite the entity.
	fixture.Entities[1].Restore = true

	if sc.basicImpl.net, err = fixture.Create(childEnv); err != nil {
		return err
	}

	sc.basicImpl.clientArgs = []string{"--mode", "part2"}
	return sc.basicImpl.Run(childEnv)
}
