// Package roothash implements the roothash debug sub-commands.
package roothash

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/spf13/cobra"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	clientGrpc "github.com/oasislabs/oasis-core/go/grpc/client"
	controlGrpc "github.com/oasislabs/oasis-core/go/grpc/control"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdControl "github.com/oasislabs/oasis-core/go/oasis-node/cmd/control"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
)

var (
	roothashExportFile string

	roothashCmd = &cobra.Command{
		Use:   "roothash",
		Short: "root hash backend utilities",
	}

	roothashExportCmd = &cobra.Command{
		Use:   "export [runtime id (hex)]...",
		Short: "export the current root hash(es)",
		Args: func(cmd *cobra.Command, args []string) error {
			nrFn := cobra.MinimumNArgs(1)
			if err := nrFn(cmd, args); err != nil {
				return err
			}
			for _, arg := range args {
				if err := ValidateRuntimeIDStr(arg); err != nil {
					return fmt.Errorf("malformed runtime id '%v': %v", arg, err)
				}
			}

			return nil
		},
		Run: doExport,
	}

	logger = logging.GetLogger("cmd/roothash")

	cfgRoothashExportFile = "output_file"
)

// ValidateRuntimeIDStr validates that the given string is a valid runtime id.
func ValidateRuntimeIDStr(idStr string) error {
	b, err := hex.DecodeString(idStr)
	if err != nil {
		return err
	}

	var id signature.PublicKey
	if err = id.UnmarshalBinary(b); err != nil {
		return err
	}

	return nil
}

func doExport(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	conn, controlClient := cmdControl.DoConnect(cmd)
	client := clientGrpc.NewRuntimeClient(conn)
	defer conn.Close()

	logger.Debug("waiting for sync status")
	// Use background context to block until the result comes in.
	_, err := controlClient.WaitSync(ctx, &controlGrpc.WaitSyncRequest{})
	if err != nil {
		logger.Error("failed to wait for sync status",
			"err", err,
		)
		os.Exit(1)
	}

	var (
		genesisBlocks []*block.Block
		failed        bool
	)
	for _, idHex := range args {
		var id signature.PublicKey
		if err = id.UnmarshalHex(idHex); err != nil {
			logger.Error("failed to decode runtime id",
				"err", err,
			)
			failed = true
			continue
		}

		logger.Debug("exporting",
			"runtime_id", idHex,
		)

		res, berr := client.GetBlock(ctx, &clientGrpc.GetBlockRequest{RuntimeId: id[:], Round: math.MaxUint64})
		if berr != nil {
			logger.Error("failed to get latest block",
				"err", berr,
				"runtime_id", id,
			)
			failed = true
			continue
		}

		// Update block header so the block will be suitable as the genesis block.
		var latestBlock block.Block
		err = latestBlock.UnmarshalCBOR(res.Block)
		if err != nil {
			logger.Error("failed to parse block",
				"err", err,
				"runtime_id", idHex,
			)
			failed = true
			continue
		}

		genesisBlk := block.NewGenesisBlock(id, latestBlock.Header.Timestamp)
		genesisBlk.Header.Round = latestBlock.Header.Round
		genesisBlk.Header.StateRoot = latestBlock.Header.StateRoot

		genesisBlocks = append(genesisBlocks, genesisBlk)
	}

	w, shouldClose, err := cmdCommon.GetOutputWriter(cmd, cfgRoothashExportFile)
	if err != nil {
		logger.Error("failed to get writer",
			"err", err,
		)
		os.Exit(1)
	}
	if shouldClose {
		defer w.Close()
	}

	b, _ := json.Marshal(genesisBlocks)
	if _, err = w.Write(b); err != nil {
		logger.Error("failed to write genesis blocks",
			"err", err,
		)
		os.Exit(1)
	}

	if failed {
		os.Exit(1)
	}
}

// Register regisers the roothash sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	roothashCmd.PersistentFlags().AddFlagSet(cmdGrpc.ClientFlags)
	roothashExportCmd.Flags().StringVarP(&roothashExportFile, cfgRoothashExportFile, "o", "", "root hash block output file")

	roothashCmd.AddCommand(roothashExportCmd)
	parentCmd.AddCommand(roothashCmd)
}
