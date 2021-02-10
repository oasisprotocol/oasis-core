// Package storage implements the storage debug sub-commands.
package storage

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdControl "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/control"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	storageAPI "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/worker/storage"
	storageWorkerAPI "github.com/oasisprotocol/oasis-core/go/worker/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/committee"
)

const (
	// MaxSyncCheckRetries is the maximum number of waiting loops for the storage worker to get synced.
	MaxSyncCheckRetries = 180
)

var (
	finalizeRound uint64

	storageCmd = &cobra.Command{
		Use:   "storage",
		Short: "node storage interface utilities",
	}

	storageCheckRootsCmd = &cobra.Command{
		Use:   "check-roots runtime-id (hex)",
		Short: "check that the given storage node has all the roots up to the current block",
		Args: func(cmd *cobra.Command, args []string) error {
			nrFn := cobra.ExactArgs(1)
			if err := nrFn(cmd, args); err != nil {
				return err
			}
			for _, arg := range args {
				if err := ValidateRuntimeIDStr(arg); err != nil {
					return fmt.Errorf("malformed runtime id '%v': %w", arg, err)
				}
			}

			return nil
		},
		Run: doCheckRoots,
	}

	storageForceFinalizeCmd = &cobra.Command{
		Use:   "force-finalize runtime-id (hex)...",
		Short: "force the node to trigger round finalization and wait for it to complete",
		Args: func(cmd *cobra.Command, args []string) error {
			nrFn := cobra.MinimumNArgs(1)
			if err := nrFn(cmd, args); err != nil {
				return err
			}
			for _, arg := range args {
				if err := ValidateRuntimeIDStr(arg); err != nil {
					return fmt.Errorf("malformed runtime id '%v': %w", arg, err)
				}
			}

			return nil
		},
		Run: doForceFinalize,
	}

	logger = logging.GetLogger("cmd/storage")
)

// ValidateRuntimeIDStr validates that the given string is a valid runtime id.
func ValidateRuntimeIDStr(idStr string) error {
	var ns common.Namespace
	return ns.UnmarshalHex(idStr)
}

func checkDiff(ctx context.Context, storageClient storageAPI.Backend, root string, oldRoot, newRoot node.Root) {
	it, err := storageClient.GetDiff(ctx, &storageAPI.GetDiffRequest{StartRoot: oldRoot, EndRoot: newRoot})
	if err != nil {
		logger.Error("error getting write log from the syncing node",
			"err", err,
			"root_type", root,
			"old_root", oldRoot,
			"new_root", newRoot,
		)
		os.Exit(1)
	}
	for {
		more, err := it.Next()
		if err != nil {
			logger.Error("can't get next item from write log iterator",
				"err", err,
				"root_type", root,
				"old_root", oldRoot,
				"new_root", newRoot,
			)
			os.Exit(1)
		}
		if !more {
			break
		}

		val, err := it.Value()
		if err != nil {
			logger.Error("can't get value out of write log iterator",
				"err", err,
				"root_type", root,
				"old_root", oldRoot,
				"new_root", newRoot,
			)
			os.Exit(1)
		}
		logger.Debug("write log entry", "key", val.Key, "value", val.Value)
	}
	logger.Debug("write log read successfully",
		"root_type", root,
		"old_root", oldRoot,
		"new_root", newRoot,
	)
}

func doCheckRoots(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	conn, _ := cmdControl.DoConnect(cmd)
	client := runtimeClient.NewRuntimeClient(conn)
	storageWorkerClient := storageWorkerAPI.NewStorageWorkerClient(conn)
	storageClient := storageAPI.NewStorageClient(conn)
	defer conn.Close()

	var id common.Namespace
	if err := id.UnmarshalHex(args[0]); err != nil {
		logger.Error("failed to decode runtime id",
			"err", err,
		)
		os.Exit(1)
	}

	latestBlock, err := client.GetBlock(ctx, &runtimeClient.GetBlockRequest{RuntimeID: id, Round: runtimeClient.RoundLatest})
	if err != nil {
		logger.Error("failed to get latest block from roothash",
			"err", err,
		)
		os.Exit(1)
	}

	// Wait for the worker to sync until this last round.
	var resp *storageWorkerAPI.GetLastSyncedRoundResponse
	retryCount := 0
	for {
		lastSyncedReq := &storageWorkerAPI.GetLastSyncedRoundRequest{
			RuntimeID: id,
		}
		resp, err = storageWorkerClient.GetLastSyncedRound(ctx, lastSyncedReq)
		if err != nil {
			logger.Error("failed to get last synced round from storage worker",
				"err", err,
			)
			os.Exit(1)
		}

		if resp.Round >= latestBlock.Header.Round {
			break
		}
		logger.Debug("storage worker not synced yet, waiting",
			"last_synced", resp.Round,
			"expected", latestBlock.Header.Round,
		)
		time.Sleep(5 * time.Second)

		retryCount++
		if retryCount > MaxSyncCheckRetries {
			logger.Error("exceeded maximum wait retries, aborting")
			os.Exit(1)
		}
	}
	logger.Debug("storage worker is synced at least to the round we want",
		"last_synced", resp.Round,
		"expected", latestBlock.Header.Round,
	)

	// Go through every block up to latestBlock and try getting write logs for each of them.
	oldStateRoot := node.Root{
		Namespace: id,
		Type:      node.RootTypeState,
	}
	oldStateRoot.Hash.Empty()
	emptyRoot := node.Root{
		Namespace: id,
		Type:      node.RootTypeIO,
	}
	emptyRoot.Hash.Empty()
	for i := uint64(0); i <= latestBlock.Header.Round; i++ {
		var blk *block.Block
		blk, err = client.GetBlock(ctx, &runtimeClient.GetBlockRequest{RuntimeID: id, Round: i})
		if err != nil {
			logger.Error("failed to get block from roothash",
				"err", err,
				"round", i,
			)
			os.Exit(1)
		}

		stateRoot := node.Root{
			Namespace: id,
			Version:   i,
			Type:      node.RootTypeState,
			Hash:      blk.Header.StateRoot,
		}
		if !oldStateRoot.Hash.Equal(&stateRoot.Hash) {
			checkDiff(ctx, storageClient, "state", oldStateRoot, stateRoot)
		}
		oldStateRoot = stateRoot

		emptyRoot.Version = i
		ioRoot := node.Root{
			Namespace: id,
			Version:   i,
			Type:      node.RootTypeIO,
			Hash:      blk.Header.IORoot,
		}
		if !ioRoot.Hash.IsEmpty() {
			checkDiff(ctx, storageClient, "io", emptyRoot, ioRoot)
		}
	}
}

func doForceFinalize(cmd *cobra.Command, args []string) {
	if finalizeRound == 0 {
		panic("can't finalize round 0")
	}

	ctx := context.Background()

	conn, _ := cmdControl.DoConnect(cmd)
	storageWorkerClient := storageWorkerAPI.NewStorageWorkerClient(conn)
	defer conn.Close()

	failed := false
	for _, arg := range args {
		var id common.Namespace
		if err := id.UnmarshalHex(arg); err != nil {
			logger.Error("failed to decode runtime id",
				"err", err,
			)
			failed = true
			continue
		}

		err := storageWorkerClient.ForceFinalize(ctx, &storageWorkerAPI.ForceFinalizeRequest{
			RuntimeID: id,
			Round:     finalizeRound,
		})
		if err != nil {
			logger.Error("failed to force round to finalize",
				"err", err,
				"round", finalizeRound,
			)
			failed = true
			continue
		}
	}
	if failed {
		os.Exit(1)
	}
}

// Register registers the storage sub-command and all of its children.
func Register(parentCmd *cobra.Command) {
	storageCheckRootsCmd.PersistentFlags().AddFlagSet(cmdGrpc.ClientFlags)
	storageCheckRootsCmd.PersistentFlags().AddFlagSet(cmdFlags.DebugDontBlameOasisFlag)

	storageForceFinalizeCmd.Flags().Uint64Var(&finalizeRound, "round", committee.RoundLatest, "the round to force finalize; default latest")
	storageForceFinalizeCmd.PersistentFlags().AddFlagSet(cmdGrpc.ClientFlags)
	storageForceFinalizeCmd.PersistentFlags().AddFlagSet(cmdFlags.DebugDontBlameOasisFlag)

	storageExportCmd.Flags().AddFlagSet(storage.Flags)
	storageExportCmd.Flags().AddFlagSet(cmdFlags.GenesisFileFlags)
	storageExportCmd.Flags().AddFlagSet(cmdFlags.DebugDontBlameOasisFlag)
	storageExportCmd.Flags().AddFlagSet(storageExportFlags)

	storageBenchmarkCmd.Flags().AddFlagSet(storageBenchmarkFlags)

	storageCmd.AddCommand(storageCheckRootsCmd)
	storageCmd.AddCommand(storageForceFinalizeCmd)
	storageCmd.AddCommand(storageExportCmd)
	storageCmd.AddCommand(storageBenchmarkCmd)
	parentCmd.AddCommand(storageCmd)
}
