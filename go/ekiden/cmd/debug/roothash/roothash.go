// Package roothash implements the roothash debug sub-commands.
package roothash

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	"github.com/oasislabs/ekiden/go/grpc/roothash"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
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
				if err := validateRuntimeIDStr(arg); err != nil {
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

func validateRuntimeIDStr(idStr string) error {
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

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, roothash.RootHashClient) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := roothash.NewRootHashClient(conn)

	return conn, client
}

func doExport(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	var genesisBlocks []*roothash.GenesisBlock
	for _, idHex := range args {
		id, err := hex.DecodeString(idHex)
		if err != nil {
			logger.Error("failed to decode runtime id",
				"err", err,
			)
			continue
		}

		logger.Debug("exporting",
			"runtime_id", idHex,
		)

		req := &roothash.LatestBlockRequest{
			RuntimeId: id,
		}
		blk, err := client.GetLatestBlock(context.Background(), req)
		if err != nil {
			logger.Error("failed to get latest block",
				"err", err,
				"runtime_id", idHex,
			)
			continue
		}

		// Update block header so the block will be suitable as the genesis block.
		var latestBlock block.Block
		err = latestBlock.FromProto(blk.Block)
		if err != nil {
			logger.Error("failed to parse block",
				"err", err,
				"runtime_id", idHex,
			)
			continue
		}

		var ns signature.PublicKey
		if err = ns.UnmarshalBinary(id); err != nil {
			logger.Error("failed to parse runtime id",
				"err", err,
				"runtime_id", idHex,
			)
			continue
		}

		genesisBlk := block.NewGenesisBlock(ns, latestBlock.Header.Timestamp)
		genesisBlk.Header.Round = latestBlock.Header.Round
		genesisBlk.Header.StateRoot = latestBlock.Header.StateRoot

		genBlk := &roothash.GenesisBlock{
			RuntimeId: id,
			Block:     genesisBlk.ToProto(),
		}
		genesisBlocks = append(genesisBlocks, genBlk)
	}

	raw, err := proto.Marshal(&roothash.GenesisBlocks{
		GenesisBlocks: genesisBlocks,
	})
	if err != nil {
		logger.Error("failed to serialize genesis blocks",
			"err", err,
		)
		os.Exit(1)
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

	if _, err = w.Write(raw); err != nil {
		logger.Error("failed to write genesis blocks",
			"err", err,
		)
		os.Exit(1)
	}
}

// Register regisers the roothash sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	cmdGrpc.RegisterClientFlags(roothashCmd, true)
	roothashExportCmd.Flags().StringVarP(&roothashExportFile, cfgRoothashExportFile, "o", "", "root hash block output file")

	roothashCmd.AddCommand(roothashExportCmd)
	parentCmd.AddCommand(roothashCmd)
}
