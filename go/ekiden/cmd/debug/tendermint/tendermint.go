// Package tendermint implements the tendermint debug sub-commands.
package tendermint

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/ugorji/go/codec"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/tendermint/inspector"
)

var (
	stateFilename string

	tmCmd = &cobra.Command{
		Use:   "tendermint",
		Short: "tendermint backend utilities",
	}

	tmDumpMuxStateCmd = &cobra.Command{
		Use:   "dump-abci-mux-state",
		Short: "dump ABCI mux state as JSON",
		Run:   doDumpMuxState,
	}
)

func doDumpMuxState(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	logger := logging.GetLogger("cmd/debug/tendermint/dump-abci-mux-state")

	state, err := inspector.OpenMuxState(stateFilename)
	if err != nil {
		logger.Error("failed to open ABCI mux state",
			"err", err,
		)
		return
	}
	defer state.Close()

	output := make(map[string]interface{})
	state.Tree().Iterate(func(key, value []byte) bool {
		// Try to decode as CBOR and if that fails, output as hex.
		var decoded interface{}
		if err := cbor.Unmarshal(value, &decoded); err != nil {
			decoded = hex.EncodeToString(value)
		}

		output[string(key)] = decoded
		return false
	})

	handle := new(codec.JsonHandle)
	handle.Indent = 2
	handle.HTMLCharsAsIs = true
	handle.MapKeyAsString = true

	var b []byte
	enc := codec.NewEncoderBytes(&b, handle)
	defer enc.Release()
	enc.MustEncode(output)
	fmt.Printf("%s\n", b)
}

// Register registers the tendermint sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	registerBootstrap(tmCmd)
	tmDumpMuxStateCmd.Flags().StringVarP(&stateFilename, "state", "s", "abci-mux-state.bolt.db", "ABCI mux state file to dump")

	tmCmd.AddCommand(tmDumpMuxStateCmd)
	parentCmd.AddCommand(tmCmd)
}
