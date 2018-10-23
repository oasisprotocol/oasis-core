package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/ugorji/go/codec"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/logging"
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
		Run:   tmDumpMuxState,
	}

	tmLog = logging.GetLogger("tendermint-cli")
)

func tmDumpMuxState(cmd *cobra.Command, args []string) {
	initCommon()

	state, err := inspector.OpenMuxState(stateFilename)
	if err != nil {
		tmLog.Error("failed to open ABCI mux state",
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
	enc.MustEncode(output)
	fmt.Printf("%s\n", b)
}

func init() {
	tmDumpMuxStateCmd.PersistentFlags().StringVarP(&stateFilename, "state", "s", "abci-mux-state.bolt.db", "ABCI mux state file to dump")

	rootCmd.AddCommand(tmCmd)
	tmCmd.AddCommand(tmDumpMuxStateCmd)
}
