// Package consensus contains common consensus-related flags.
package consensus

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	genesisFile "github.com/oasisprotocol/oasis-core/go/genesis/file"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
)

const (
	// CfgTxNonce configures the nonce.
	CfgTxNonce = "transaction.nonce"

	// CfgTxFeeAmount configures the fee amount in base units.
	CfgTxFeeAmount = "transaction.fee.amount"

	// CfgTxFeeGas configures the maximum gas limit.
	CfgTxFeeGas = "transaction.fee.gas"

	// CfgTxFile configures the filename for the transaction.
	CfgTxFile = "transaction.file"

	// CfgTxUnsigned makes SaveTx save an unsigned transaction.
	CfgTxUnsigned = "transaction.unsigned"
)

var (
	TxFlags     = flag.NewFlagSet("", flag.ContinueOnError)
	TxFileFlags = flag.NewFlagSet("", flag.ContinueOnError)

	logger = logging.GetLogger("cmd/common/consensus")
)

func AssertTxFileOK() {
	f := viper.GetString(CfgTxFile)
	if f == "" {
		logger.Error("failed to determine tx file")
		os.Exit(1)
	}

	// XXX: Other checks to see if we can write to the file?
}

func InitGenesis() *genesisAPI.Document {
	genesis, err := genesisFile.DefaultFileProvider()
	if err != nil {
		logger.Error("failed to load genesis file",
			"err", err,
		)
		os.Exit(1)
	}

	// Retrieve the genesis document and use it to configure the ChainID for
	// signature domain separation. We do this as early as possible.
	genesisDoc, err := genesis.GetGenesisDocument()
	if err != nil {
		logger.Error("failed to retrieve genesis document",
			"err", err,
		)
		os.Exit(1)
	}
	genesisDoc.SetChainContext()

	return genesisDoc
}

func GetTxNonceAndFee() (uint64, *transaction.Fee) {
	var fee transaction.Fee
	nonce := viper.GetUint64(CfgTxNonce)
	if err := fee.Amount.UnmarshalText([]byte(viper.GetString(CfgTxFeeAmount))); err != nil {
		logger.Error("failed to parse fee amount",
			"err", err,
		)
		os.Exit(1)
	}
	fee.Gas = transaction.Gas(viper.GetUint64(CfgTxFeeGas))
	return nonce, &fee
}

func SignAndSaveTx(ctx context.Context, tx *transaction.Transaction) {
	if viper.GetBool(CfgTxUnsigned) {
		rawUnsignedTx := cbor.Marshal(tx)
		if err := ioutil.WriteFile(viper.GetString(CfgTxFile), rawUnsignedTx, 0o600); err != nil {
			logger.Error("failed to save unsigned transaction",
				"err", err,
			)
			os.Exit(1)
		}
		return
	}

	entityDir, err := cmdSigner.CLIDirOrPwd()
	if err != nil {
		logger.Error("failed to retrieve signer dir",
			"err", err,
		)
		os.Exit(1)
	}
	_, signer, err := cmdCommon.LoadEntity(cmdSigner.Backend(), entityDir)
	if err != nil {
		logger.Error("failed to load account entity",
			"err", err,
		)
		os.Exit(1)
	}
	defer signer.Reset()

	fmt.Printf("You are about to sign the following transaction:\n")
	tx.PrettyPrint(ctx, "  ", os.Stdout)

	sigTx, err := transaction.Sign(signer, tx)
	if err != nil {
		logger.Error("failed to sign transaction",
			"err", err,
		)
		os.Exit(1)
	}

	rawTx, err := json.Marshal(sigTx)
	if err != nil {
		logger.Error("failed to marshal transaction",
			"err", err,
		)
		os.Exit(1)
	}
	if err = ioutil.WriteFile(viper.GetString(CfgTxFile), rawTx, 0o600); err != nil {
		logger.Error("failed to save transaction",
			"err", err,
		)
		os.Exit(1)
	}
}

func init() {
	TxFileFlags.String(CfgTxFile, "", "path to the transaction")
	_ = viper.BindPFlags(TxFileFlags)

	TxFlags.Uint64(CfgTxNonce, 0, "nonce of the signing account")
	TxFlags.Uint64(CfgTxFeeAmount, 0, "transaction fee in base units")
	TxFlags.String(CfgTxFeeGas, "0", "maximum transaction gas limit")
	TxFlags.Bool(CfgTxUnsigned, false, "generate an unsigned transaction")
	_ = viper.BindPFlags(TxFlags)
	TxFlags.AddFlagSet(TxFileFlags)
	TxFlags.AddFlagSet(cmdFlags.DebugTestEntityFlags)
	TxFlags.AddFlagSet(cmdSigner.Flags)
	TxFlags.AddFlagSet(cmdSigner.CLIFlags)
	TxFlags.AddFlagSet(cmdFlags.GenesisFileFlags)
}
