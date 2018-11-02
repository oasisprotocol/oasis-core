// Package roothash implements the roothash debug sub-commands.
package roothash

import (
	"encoding/hex"
	"fmt"
	"io"
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

		genBlk := &roothash.GenesisBlock{
			RuntimeId: id,
			Block:     blk.Block,
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

	w, shouldClose, err := getOutput(cmd, cfgRoothashExportFile)
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

func getOutput(cmd *cobra.Command, cfg string) (io.WriteCloser, bool, error) {
	f, _ := cmd.Flags().GetString(cfg)
	if f == "" {
		return os.Stdout, false, nil
	}

	w, err := os.Create(f)
	return w, true, err
}

// Register regisers the roothash sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	cmdGrpc.RegisterClientFlags(roothashCmd, true)
	roothashExportCmd.Flags().StringVarP(&roothashExportFile, cfgRoothashExportFile, "o", "", "root hash block output file")

	roothashCmd.AddCommand(roothashExportCmd)
	parentCmd.AddCommand(roothashCmd)
}
