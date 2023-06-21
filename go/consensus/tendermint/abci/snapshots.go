package abci

import (
	"bytes"

	"github.com/cometbft/cometbft/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	storageApi "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

func (mux *abciMux) ListSnapshots(req types.RequestListSnapshots) types.ResponseListSnapshots {
	// Get a list of all current checkpoints.
	cps, err := mux.state.storage.Checkpointer().GetCheckpoints(mux.state.ctx, &checkpoint.GetCheckpointsRequest{
		Version: 1,
	})
	if err != nil {
		mux.logger.Error("failed to get checkpoints",
			"err", err,
		)
		return types.ResponseListSnapshots{}
	}

	var rsp types.ResponseListSnapshots
	for _, cp := range cps {
		cpHash := cp.EncodedHash()

		rsp.Snapshots = append(rsp.Snapshots, &types.Snapshot{
			Height:   cp.Root.Version,
			Format:   uint32(cp.Version),
			Chunks:   uint32(len(cp.Chunks)),
			Hash:     cpHash[:],
			Metadata: cbor.Marshal(cp),
		})
	}

	return rsp
}

func (mux *abciMux) OfferSnapshot(req types.RequestOfferSnapshot) types.ResponseOfferSnapshot {
	if req.Snapshot == nil {
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_REJECT}
	}
	if req.Snapshot.Format != 1 {
		mux.logger.Warn("received snapshot with unsupported version",
			"version", req.Snapshot.Format,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_REJECT_FORMAT}
	}

	// Decode checkpoint metadata hash and sanity check against the request.
	var metadataHash hash.Hash
	metadataHash.FromBytes(req.Snapshot.Metadata)
	var h hash.Hash
	if err := h.UnmarshalBinary(req.Snapshot.Hash); err != nil {
		mux.logger.Warn("received snapshot with malformed hash",
			"err", err,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_REJECT}
	}
	if !metadataHash.Equal(&h) {
		mux.logger.Warn("received snapshot with mismatching hash",
			"expected_hash", h,
			"hash", metadataHash,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_REJECT}
	}

	// Decode checkpoint metadata.
	var cp checkpoint.Metadata
	if err := cbor.Unmarshal(req.Snapshot.Metadata, &cp); err != nil {
		mux.logger.Warn("received snapshot with malformed metadata",
			"err", err,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_REJECT}
	}

	// Number of chunks must match.
	if int(req.Snapshot.Chunks) != len(cp.Chunks) {
		mux.logger.Warn("received snapshot with mismatching number of chunks",
			"expected_chunks", len(cp.Chunks),
			"chunks", req.Snapshot.Chunks,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_REJECT}
	}
	// Root hash must match.
	var appHash hash.Hash
	if err := appHash.UnmarshalBinary(req.AppHash); err != nil {
		// NOTE: This should never happen as it indicates a problem with Tendermint.
		mux.logger.Error("received request with malformed hash",
			"err", err,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_ABORT}
	}
	if !cp.Root.Hash.Equal(&appHash) {
		mux.logger.Warn("received snapshot with mismatching root hash",
			"expected_root", appHash,
			"root", cp.Root.Hash,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_REJECT}
	}

	// Snapshot seems correct (e.g., it is for the correct root), start the restoration process.
	if err := mux.state.storage.NodeDB().StartMultipartInsert(cp.Root.Version); err != nil {
		mux.logger.Error("failed to start multipart restoration",
			"err", err,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_ABORT}
	}
	if err := mux.state.storage.Checkpointer().StartRestore(mux.state.ctx, &cp); err != nil {
		mux.logger.Error("failed to start restore",
			"err", err,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_ABORT}
	}

	mux.logger.Info("started state restore process",
		"root", cp.Root,
	)

	return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_ACCEPT}
}

func (mux *abciMux) LoadSnapshotChunk(req types.RequestLoadSnapshotChunk) types.ResponseLoadSnapshotChunk {
	// Fetch the metadata for the specified checkpoint.
	cps, err := mux.state.storage.Checkpointer().GetCheckpoints(mux.state.ctx, &checkpoint.GetCheckpointsRequest{
		Version:     uint16(req.Format),
		RootVersion: &req.Height,
	})
	if err != nil {
		mux.logger.Error("failed to get checkpoints",
			"err", err,
		)
		return types.ResponseLoadSnapshotChunk{}
	}
	if len(cps) != 1 {
		mux.logger.Error("failed to get checkpoints",
			"cps", len(cps),
		)
		return types.ResponseLoadSnapshotChunk{}
	}

	// Fetch the chunk itself.
	chunk, err := cps[0].GetChunkMetadata(uint64(req.Chunk))
	if err != nil {
		mux.logger.Error("failed to get chunk metadata",
			"err", err,
		)
		return types.ResponseLoadSnapshotChunk{}
	}
	var buf bytes.Buffer
	if err := mux.state.storage.Checkpointer().GetCheckpointChunk(mux.state.ctx, chunk, &buf); err != nil {
		mux.logger.Error("failed to get chunk",
			"err", err,
		)
		return types.ResponseLoadSnapshotChunk{}
	}

	return types.ResponseLoadSnapshotChunk{Chunk: buf.Bytes()}
}

func (mux *abciMux) ApplySnapshotChunk(req types.RequestApplySnapshotChunk) types.ResponseApplySnapshotChunk {
	cp := mux.state.storage.Checkpointer().GetCurrentCheckpoint()

	mux.logger.Debug("attempting to restore a chunk",
		"root", cp.Root,
		"index", req.Index,
	)

	buf := bytes.NewBuffer(req.Chunk)
	done, err := mux.state.storage.Checkpointer().RestoreChunk(mux.state.ctx, uint64(req.Index), buf)
	switch {
	case err == nil:
	case errors.Is(err, checkpoint.ErrNoRestoreInProgress):
		// This should never happen.
		mux.logger.Error("ApplySnapshotChunk called without OfferSnapshot, aborting state sync")
		if err = mux.state.storage.Checkpointer().AbortRestore(mux.state.ctx); err != nil {
			mux.logger.Error("failed to abort checkpoint restore: %w",
				"err", err,
			)
		}
		if err = mux.state.storage.NodeDB().AbortMultipartInsert(); err != nil {
			mux.logger.Error("failed to abort multipart restore: %w",
				"err", err,
			)
		}
		return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_ABORT}
	case errors.Is(err, checkpoint.ErrChunkAlreadyRestored):
		return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_ACCEPT}
	case errors.Is(err, checkpoint.ErrChunkCorrupted):
		// Corrupted chunk, refetch.
		mux.logger.Warn("received corrupted chunk",
			"sender", req.Sender,
			"index", req.Index,
			"err", err,
		)

		return types.ResponseApplySnapshotChunk{
			RefetchChunks: []uint32{req.Index},
			// TODO: Consider banning the sender.
			Result: types.ResponseApplySnapshotChunk_RETRY,
		}
	case errors.Is(err, checkpoint.ErrChunkProofVerificationFailed):
		// Chunk was as specified in the manifest but did not match the reported root. In this case
		// we need to abort processing the given snapshot.
		mux.logger.Warn("chunk contains invalid proof, snapshot is bad",
			"err", err,
		)

		return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_REJECT_SNAPSHOT}
	default:
		// Unspecified error during restoration.
		mux.logger.Error("error during chunk restoration, aborting state sync",
			"err", err,
		)
		if err = mux.state.storage.Checkpointer().AbortRestore(mux.state.ctx); err != nil {
			mux.logger.Error("failed to abort checkpoint restore: %w",
				"err", err,
			)
		}
		if err = mux.state.storage.NodeDB().AbortMultipartInsert(); err != nil {
			mux.logger.Error("failed to abort multipart restore: %w",
				"err", err,
			)
		}

		return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_ABORT}
	}

	// Check if we are done with the restoration. In this case, finalize the root.
	if done {
		err = mux.state.storage.NodeDB().Finalize(mux.state.ctx, []storageApi.Root{cp.Root})
		if err != nil {
			mux.logger.Error("failed to finalize restored root",
				"err", err,
			)
			if err = mux.state.storage.NodeDB().AbortMultipartInsert(); err != nil {
				mux.logger.Error("failed to abort multipart restore: %w",
					"err", err,
				)
			}
			return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_ABORT}
		}

		if err = mux.state.doApplyStateSync(cp.Root); err != nil {
			mux.logger.Error("failed to apply state sync root",
				"err", err,
			)
			return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_ABORT}
		}

		mux.logger.Info("successfully synced state",
			"root", cp.Root,
			logging.LogEvent, LogEventABCIStateSyncComplete,
		)

		// Notify applications that state has been synced.
		mux.state.resetProposal()
		defer mux.state.closeProposal()

		ctx := mux.state.NewContext(api.ContextEndBlock, mux.currentTime)
		defer ctx.Close()

		if _, err = mux.md.Publish(ctx, api.MessageStateSyncCompleted, nil); err != nil {
			mux.logger.Error("failed to dispatch state sync completed message",
				"err", err,
			)
			return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_ABORT}
		}
	}

	return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_ACCEPT}
}
