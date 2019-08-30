// Package storage implements the storage debug sub-commands.
package storage

import (
	"context"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	cmdDebugClient "github.com/oasislabs/ekiden/go/ekiden/cmd/debug/client"
	cmdRoothashDebug "github.com/oasislabs/ekiden/go/ekiden/cmd/debug/roothash"
	clientGrpc "github.com/oasislabs/ekiden/go/grpc/client"
	storageGrpc "github.com/oasislabs/ekiden/go/grpc/storage"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	storageApi "github.com/oasislabs/ekiden/go/storage/api"
	storageClient "github.com/oasislabs/ekiden/go/storage/client"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

const (
	// MaxSyncCheckRetries is the maximum number of waiting loops for the storage worker to get synced.
	MaxSyncCheckRetries = 180
)

var (
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
				if err := cmdRoothashDebug.ValidateRuntimeIDStr(arg); err != nil {
					return fmt.Errorf("malformed runtime id '%v': %v", arg, err)
				}
			}

			return nil
		},
		Run: doCheckRoots,
	}

	logger = logging.GetLogger("cmd/storage")
)

func checkDiff(ctx context.Context, storageClient storageApi.Backend, root string, oldRoot node.Root, newRoot node.Root) {
	it, err := storageClient.GetDiff(ctx, oldRoot, newRoot)
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

	conn, client := cmdDebugClient.DoConnect(cmd)
	storageWorkerClient := storageGrpc.NewStorageWorkerClient(conn)
	defer conn.Close()

	storageClient, err := storageClient.New(ctx, nil, nil, nil)
	if err != nil {
		logger.Error("error while connecting to storage client",
			"err", err,
		)
		os.Exit(1)
	}

	var id signature.PublicKey
	if err = id.UnmarshalHex(args[0]); err != nil {
		logger.Error("failed to decode runtime id",
			"err", err,
		)
		os.Exit(1)
	}

	res, err := client.GetBlock(ctx, &clientGrpc.GetBlockRequest{RuntimeId: id, Round: math.MaxUint64})
	if err != nil {
		logger.Error("failed to get latest block from roothash",
			"err", err,
		)
		os.Exit(1)
	}

	var latestBlock block.Block
	if err = latestBlock.UnmarshalCBOR(res.Block); err != nil {
		logger.Error("failed to parse block",
			"err", err,
			"runtime_id", id,
		)
		os.Exit(1)
	}

	// Wait for the worker to sync until this last round.
	var resp *storageGrpc.GetLastSyncedRoundResponse
	retryCount := 0
	for {
		lastSyncedReq := &storageGrpc.GetLastSyncedRoundRequest{
			RuntimeId: id,
		}
		resp, err = storageWorkerClient.GetLastSyncedRound(ctx, lastSyncedReq)
		if err != nil {
			logger.Error("failed to get last synced round from storage worker",
				"err", err,
			)
			os.Exit(1)
		}

		if resp.GetRound() >= latestBlock.Header.Round {
			break
		}
		logger.Debug("storage worker not synced yet, waiting",
			"last_synced", resp.GetRound(),
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
		"last_synced", resp.GetRound(),
		"expected", latestBlock.Header.Round,
	)

	// Go through every block up to latestBlock and try getting write logs for each of them.
	oldStateRoot := node.Root{}
	oldStateRoot.Hash.Empty()
	emptyRoot := node.Root{}
	emptyRoot.Hash.Empty()
	for i := uint64(0); i <= latestBlock.Header.Round; i++ {
		res, err = client.GetBlock(ctx, &clientGrpc.GetBlockRequest{RuntimeId: id, Round: i})
		if err != nil {
			logger.Error("failed to get block from roothash",
				"err", err,
				"round", i,
			)
			os.Exit(1)
		}

		var blk block.Block
		if err = blk.UnmarshalCBOR(res.Block); err != nil {
			logger.Error("failed to parse block",
				"err", err,
				"runtime_id", id,
				"round", i,
			)
			os.Exit(1)
		}

		stateRoot := node.Root{
			Round: i,
			Hash:  blk.Header.StateRoot,
		}
		if !oldStateRoot.Hash.Equal(&stateRoot.Hash) {
			checkDiff(ctx, storageClient, "state", oldStateRoot, stateRoot)
		}
		oldStateRoot = stateRoot

		emptyRoot.Round = i
		ioRoot := node.Root{
			Round: i,
			Hash:  blk.Header.IORoot,
		}
		if !ioRoot.Hash.IsEmpty() {
			checkDiff(ctx, storageClient, "io", emptyRoot, ioRoot)
		}
	}
}

// Register registers the storage sub-command and all of its children.
func Register(parentCmd *cobra.Command) {
	storageCheckRootsCmd.Flags().AddFlagSet(storageClient.Flags)
	storageCheckRootsCmd.PersistentFlags().AddFlagSet(cmdGrpc.ClientFlags)

	storageCmd.AddCommand(storageCheckRootsCmd)
	parentCmd.AddCommand(storageCmd)
}
