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
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
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
	return sc.Net.ClientController().Beacon.WaitEpoch(ctx, epoch+n)
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

	block, err := sc.WaitBlocks(ctx, 3)
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
func (sc *Scenario) RegisterEntity(childEnv *env.Env, cli *cli.Helpers, ent *oasis.Entity, nonce uint64) error {
	txPath := uniqueFilepath(filepath.Join(childEnv.Dir(), "register_entity.json"))
	if err := cli.Registry.GenerateRegisterEntityTx(ent.Dir(), nonce, txPath); err != nil {
		return fmt.Errorf("failed to generate register entity tx: %w", err)
	}
	if err := cli.Consensus.SubmitTx(txPath); err != nil {
		return fmt.Errorf("failed to submit register entity tx: %w", err)
	}

	return nil
}

// RegisterRuntime registers the specified runtime.
func (sc *Scenario) RegisterRuntime(childEnv *env.Env, cli *cli.Helpers, rt registry.Runtime, nonce uint64) error {
	txPath := uniqueFilepath(childEnv.Dir(), fmt.Sprintf("register_runtime_%s.json", rt.ID))
	if err := cli.Registry.GenerateRegisterRuntimeTx(childEnv.Dir(), rt, nonce, txPath); err != nil {
		return fmt.Errorf("failed to generate register runtime tx: %w", err)
	}

	if err := cli.Consensus.SubmitTx(txPath); err != nil {
		return fmt.Errorf("failed to register runtime: %w", err)
	}

	return nil
}

// EnsureProposalFinalized submits a proposal, votes for it and ensures the
// proposal is finalized.
func (sc *Scenario) EnsureProposalFinalized(ctx context.Context, content *governance.ProposalContent, entity *oasis.Entity, entityNonce uint64, currentEpoch beacon.EpochTime) (*governance.Proposal, uint64, beacon.EpochTime, error) {
	// Submit proposal.
	tx := governance.NewSubmitProposalTx(entityNonce, &transaction.Fee{Gas: 2000}, content)
	entityNonce++
	sigTx, err := transaction.Sign(entity.Signer(), tx)
	if err != nil {
		return nil, entityNonce, currentEpoch, fmt.Errorf("failed signing submit proposal transaction: %w", err)
	}
	sc.Logger.Info("submitting proposal", "content", content)
	err = sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx)
	if err != nil {
		return nil, entityNonce, currentEpoch, fmt.Errorf("failed submitting proposal transaction: %w", err)
	}

	// Ensure proposal created.
	aps, err := sc.Net.Controller().Governance.ActiveProposals(ctx, consensus.HeightLatest)
	if err != nil {
		return nil, entityNonce, currentEpoch, fmt.Errorf("failed querying active proposals: %w", err)
	}
	var proposal *governance.Proposal
	for _, p := range aps {
		if p.Content.Equals(content) {
			proposal = p
			break
		}
	}
	if proposal == nil {
		return nil, entityNonce, currentEpoch, fmt.Errorf("submitted proposal %v not found", content)
	}

	// Vote for the proposal.
	vote := governance.ProposalVote{
		ID:   proposal.ID,
		Vote: governance.VoteYes,
	}
	tx = governance.NewCastVoteTx(entityNonce, &transaction.Fee{Gas: 2000}, &vote)
	entityNonce++
	sigTx, err = transaction.Sign(entity.Signer(), tx)
	if err != nil {
		return nil, entityNonce, currentEpoch, fmt.Errorf("failed signing cast vote transaction: %w", err)
	}
	sc.Logger.Info("submitting vote for proposal", "proposal", proposal, "vote", vote)
	err = sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx)
	if err != nil {
		return nil, entityNonce, currentEpoch, fmt.Errorf("failed submitting cast vote transaction: %w", err)
	}

	// Ensure vote was cast.
	votes, err := sc.Net.Controller().Governance.Votes(ctx,
		&governance.ProposalQuery{
			Height:     consensus.HeightLatest,
			ProposalID: aps[0].ID,
		},
	)
	if err != nil {
		return nil, entityNonce, currentEpoch, fmt.Errorf("failed queying votes: %w", err)
	}
	if l := len(votes); l != 1 {
		return nil, entityNonce, currentEpoch, fmt.Errorf("expected one vote, got: %v", l)
	}
	if vote := votes[0].Vote; vote != governance.VoteYes {
		return nil, entityNonce, currentEpoch, fmt.Errorf("expected vote Yes, got: %s", string(vote))
	}

	// Transition to the epoch when proposal finalizes.
	for ep := currentEpoch + 1; ep < aps[0].ClosesAt+1; ep++ {
		sc.Logger.Info("transitioning to epoch", "epoch", ep)
		currentEpoch++
		if err = sc.Net.Controller().SetEpoch(ctx, currentEpoch); err != nil {
			// Errors can happen because an upgrade happens exactly during
			// an epoch transition.  So make sure to ignore them.
			sc.Logger.Warn("failed to set epoch",
				"epoch", currentEpoch,
				"err", err,
			)
		}
	}

	p, err := sc.Net.Controller().Governance.Proposal(ctx,
		&governance.ProposalQuery{
			Height:     consensus.HeightLatest,
			ProposalID: proposal.ID,
		},
	)
	if err != nil {
		return nil, entityNonce, currentEpoch, fmt.Errorf("failed to query proposal: %w", err)
	}
	sc.Logger.Info("got proposal",
		"state", p.State.String(),
		"results", p.Results,
		"len", len(p.Results),
		"invalid", p.InvalidVotes,
	)
	// Ensure proposal finalized.
	if p.State == governance.StateActive || p.State == governance.StateFailed {
		return nil, entityNonce, currentEpoch, fmt.Errorf("expected finalized proposal, proposal state: %v", p.State)
	}

	return p, entityNonce, currentEpoch, nil
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
