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
	"strconv"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// TrustRoot is a consensus trust root.
type TrustRoot struct {
	Height       string
	Hash         string
	ChainContext string
}

// WaitBlocks waits for the specified number of blocks.
func (sc *Scenario) WaitBlocks(ctx context.Context, n int) (*consensus.Block, error) {
	sc.Logger.Info("waiting for blocks", "n", n)

	blockCh, blockSub, err := sc.Net.Controller().Consensus.WatchBlocks(ctx)
	if err != nil {
		return nil, err
	}
	defer blockSub.Close()

	var blk *consensus.Block
	for i := 0; i < n; i++ {
		select {
		case blk = <-blockCh:
			sc.Logger.Info("new block",
				"height", blk.Height,
			)
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for blocks")
		}
	}

	return blk, nil
}

// WaitEpochs waits for the specified number of epochs.
func (sc *Scenario) WaitEpochs(ctx context.Context, n beacon.EpochTime) error {
	sc.Logger.Info("waiting few epochs", "n", n)

	epoch, err := sc.Net.ClientController().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return err
	}
	if err := sc.Net.ClientController().Beacon.WaitEpoch(ctx, epoch+n); err != nil {
		return err
	}
	return nil
}

// ChainContext returns the consensus chain context.
func (sc *Scenario) ChainContext(ctx context.Context) (string, error) {
	sc.Logger.Info("fetching consensus chain context")

	cc, err := sc.Net.Controller().Consensus.GetChainContext(ctx)
	if err != nil {
		return "", err
	}
	return cc, nil
}

// TrustRoot returns a suitable trust root after running the network for a few blocks.
func (sc *Scenario) TrustRoot(ctx context.Context) (*TrustRoot, error) {
	sc.Logger.Info("preparing trust root")

	block, err := sc.WaitBlocks(ctx, 5)
	if err != nil {
		return nil, err
	}

	chainContext, err := sc.ChainContext(ctx)
	if err != nil {
		return nil, err
	}

	return &TrustRoot{
		Height:       strconv.FormatInt(block.Height, 10),
		Hash:         block.Hash.Hex(),
		ChainContext: chainContext,
	}, nil
}

// TestEntityNonce returns the nonce of the test entity.
func (sc *Scenario) TestEntityNonce(ctx context.Context) (uint64, error) {
	ent, _, err := entity.TestEntity()
	if err != nil {
		return 0, err
	}
	return sc.EntityNonce(ctx, ent)
}

// EntityNonce returns the nonce of the specified entity.
func (sc *Scenario) EntityNonce(ctx context.Context, ent *entity.Entity) (uint64, error) {
	addr := staking.NewAddress(ent.ID)
	return sc.Net.ClientController().Consensus.GetSignerNonce(ctx, &consensus.GetSignerNonceRequest{
		Height:         consensus.HeightLatest,
		AccountAddress: addr,
	})
}

// EntityNonceByID returns the nonce of the specified entity.
func (sc *Scenario) EntityNonceByID(ctx context.Context, id signature.PublicKey) (uint64, error) {
	ent, err := sc.Net.ClientController().Registry.GetEntity(ctx, &registry.IDQuery{
		Height: consensus.HeightLatest,
		ID:     id,
	})
	if err != nil {
		return 0, err
	}
	return sc.EntityNonce(ctx, ent)
}

// ExportedGenesisFiles gathers exported genesis files and ensures all exported genesis files match.
func (sc *Scenario) ExportedGenesisFiles(skipCompute bool) ([]string, error) {
	dumpGlob := "genesis-*.json"

	// Gather all nodes.
	var nodes []interface {
		ExportsPath() string
	}
	for _, v := range sc.Net.Validators() {
		nodes = append(nodes, v)
	}
	if !skipCompute {
		for _, n := range sc.Net.ComputeWorkers() {
			nodes = append(nodes, n)
		}
	}
	for _, n := range sc.Net.Keymanagers() {
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

// RegisterEntity registers the specified entity.
func (sc *Scenario) RegisterEntity(ctx context.Context, childEnv *env.Env, cli *cli.Helpers, ent *oasis.Entity, nonce uint64) error {
	txPath := uniqueFilepath(filepath.Join(childEnv.Dir(), "register_entity.json"))
	if err := cli.Registry.GenerateRegisterEntityTx(ent.Dir(), nonce, txPath); err != nil {
		return fmt.Errorf("failed to generate register entity tx: %w", err)
	}
	if err := cli.Consensus.SubmitTx(txPath); err != nil {
		return fmt.Errorf("failed to submit register entity tx: %w", err)
	}

	return nil
}

// uniqueFilepath joins any number of path elements into a single path, checks if a file exists
// at that path, and if it does, appends a unique suffix to the filename to ensure the returned
// path is not already in use.
func uniqueFilepath(elem ...string) string {
	path := filepath.Join(elem...)
	if !fileExists(path) {
		return path
	}

	dir, filename := filepath.Split(path)
	extension := filepath.Ext(filename)
	prefix := filename[:len(filename)-len(extension)]

	for suffix := 1; ; suffix++ {
		newFilename := fmt.Sprintf("%s_%d%s", prefix, suffix, extension)
		newPath := filepath.Join(dir, newFilename)
		if !fileExists(newPath) {
			return newPath
		}
	}
}

// fileExists returns true iff the named file exists.
func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}
