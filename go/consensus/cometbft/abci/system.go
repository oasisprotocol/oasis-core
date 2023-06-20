package abci

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/cometbft/cometbft/abci/types"
	cmtmerkle "github.com/cometbft/cometbft/crypto/merkle"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	cmtcrypto "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/crypto"
)

// prepareSystemTxs prepares a list of system transactions to be included in a proposed block in
// case where the node is currently the block proposer.
func (mux *abciMux) prepareSystemTxs() ([][]byte, []*types.ResponseDeliverTx, error) {
	var (
		systemTxs       [][]byte
		systemTxResults []*types.ResponseDeliverTx
	)

	// Append block metadata as a system transaction.
	stateRoot, err := mux.state.workingStateRoot()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute working state root: %w", err)
	}
	eventsRoot, err := mux.computeProvableEventsRoot()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute provable events root: %w", err)
	}

	blockMeta := consensus.NewBlockMetadataTx(&consensus.BlockMetadata{
		StateRoot:  stateRoot,
		EventsRoot: eventsRoot,
	})
	sigBlockMeta, err := transaction.Sign(mux.state.identity.ConsensusSigner, blockMeta)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign block metadata transaction: %w", err)
	}
	sigBlockMetaRaw := cbor.Marshal(sigBlockMeta)
	if l := len(sigBlockMetaRaw); l > consensus.BlockMetadataMaxSize {
		mux.logger.Error("serialized block metadata larger than maximum allowed size",
			"meta_size", l,
			"max_meta_size", consensus.BlockMetadataMaxSize,
		)
		return nil, nil, fmt.Errorf("serialized block metadata would be oversized")
	}
	systemTxs = append(systemTxs, sigBlockMetaRaw)
	systemTxResults = append(systemTxResults, &types.ResponseDeliverTx{
		Code: types.CodeTypeOK,
		Data: cbor.Marshal(nil),
	})

	return systemTxs, systemTxResults, nil
}

// processSystemTx processes a system transaction in DeliverTx context.
func (mux *abciMux) processSystemTx(ctx *api.Context, tx *transaction.Transaction) error {
	if ctx.Mode() != api.ContextDeliverTx {
		return fmt.Errorf("system methods are not allowed to be called")
	}

	// NOTE: The panics below will either trigger a bad proposal being rejected (on nodes in the
	//       validator set) or a failure in block processing (on other nodes).

	// Since system transactions can only be injected by the proposer, make sure they are not
	// themselves included in the proposal phase.
	if len(mux.state.proposal.hash) == 0 {
		panic(fmt.Errorf("system transaction included during proposal phase"))
	}

	// Nonce must be zero and fee must be nil.
	if tx.Nonce != 0 || tx.Fee != nil {
		panic(fmt.Errorf("malformed system transaction in block"))
	}
	// Transaction must be signed by the proposer.
	txSigner := ctx.TxSigner()
	txSignerAddress := []byte(cmtcrypto.PublicKeyToCometBFT(&txSigner).Address())
	if proposerAddress := ctx.BlockContext().ProposerAddress; !bytes.Equal(txSignerAddress, proposerAddress) {
		panic(fmt.Errorf("system transaction not signed by block proposer (expected: %x got: %x)", proposerAddress, txSignerAddress))
	}

	// Accumulate system transactions for later verification.
	ctx.BlockContext().SystemTransactions = append(ctx.BlockContext().SystemTransactions, tx)

	return nil
}

// validateSystemTxs performs system transaction validation at the end of a block.
func (mux *abciMux) validateSystemTxs() error {
	// Don't perform any validation when we are still building the proposal.
	if len(mux.state.proposal.hash) == 0 {
		return nil
	}

	var hasBlockMetadata bool
	for _, tx := range mux.state.blockCtx.SystemTransactions {
		switch tx.Method {
		case consensus.MethodMeta:
			// Block metadata, verify state root.
			if hasBlockMetadata {
				return fmt.Errorf("duplicate block metadata in block")
			}
			hasBlockMetadata = true

			var meta consensus.BlockMetadata
			if err := cbor.Unmarshal(tx.Body, &meta); err != nil {
				return fmt.Errorf("malformed block metadata: %w", err)
			}
			if err := meta.ValidateBasic(); err != nil {
				return fmt.Errorf("malformed block metadata: %w", err)
			}

			// Verify state root.
			stateRoot, err := mux.state.workingStateRoot()
			if err != nil {
				return fmt.Errorf("failed to compute working state root: %w", err)
			}
			if !stateRoot.Equal(&meta.StateRoot) {
				return fmt.Errorf("invalid state root in block metadata (expected: %s got: %s)", stateRoot, meta.StateRoot)
			}

			// Verify provable events root.
			eventsRoot, err := mux.computeProvableEventsRoot()
			if err != nil {
				return fmt.Errorf("failed to compute provable events root: %w", err)
			}
			if !bytes.Equal(eventsRoot, meta.EventsRoot) {
				return fmt.Errorf("invalid events root in block metadata (expected: %x got: %x)", eventsRoot, meta.EventsRoot)
			}

			mux.logger.Debug("validated block metadata",
				"state_root", meta.StateRoot,
				"events_root", hex.EncodeToString(eventsRoot),
			)
		default:
			return fmt.Errorf("unknown system method: %s", tx.Method)
		}
	}

	if !hasBlockMetadata {
		return fmt.Errorf("missing required block metadata")
	}
	return nil
}

func (mux *abciMux) computeProvableEventsRoot() ([]byte, error) {
	provable := mux.state.blockCtx.ProvableEvents
	provableEvents := make([][]byte, len(provable))
	for i, pe := range provable {
		provableEvents[i] = cbor.Marshal(pe.ProvableRepresentation())
	}
	return cmtmerkle.HashFromByteSlices(provableEvents), nil
}
