// Package consensus contains common consensus-related flags.
package consensus

import (
	"encoding/json"
	"io/ioutil"
	"os"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	genesisFile "github.com/oasislabs/oasis-core/go/genesis/file"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
)

const (
	// CfgTxNonce configures the nonce.
	CfgTxNonce = "transaction.nonce"

	// CfgTxFeeAmount configures the fee amount in tokens.
	CfgTxFeeAmount = "transaction.fee.amount"

	// CfgTxFeeGas configures the maximum gas limit.
	CfgTxFeeGas = "transaction.fee.gas"

	// CfgTxFile configures the filename for the transaction.
	CfgTxFile = "transaction.file"
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

func InitGenesis() {
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

func SignAndSaveTx(tx *transaction.Transaction) {
	_, signer, err := cmdCommon.LoadEntity(cmdFlags.Entity())
	if err != nil {
		logger.Error("failed to load account entity",
			"err", err,
		)
		os.Exit(1)
	}
	defer signer.Reset()

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
	if err = ioutil.WriteFile(viper.GetString(CfgTxFile), rawTx, 0600); err != nil {
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
	TxFlags.Uint64(CfgTxFeeAmount, 0, "transaction fee in tokens")
	TxFlags.String(CfgTxFeeGas, "0", "maximum transaction gas limit")
	_ = viper.BindPFlags(TxFlags)
	TxFlags.AddFlagSet(TxFileFlags)
	TxFlags.AddFlagSet(cmdFlags.DebugTestEntityFlags)
	TxFlags.AddFlagSet(cmdFlags.EntityFlags)
	TxFlags.AddFlagSet(cmdFlags.GenesisFileFlags)
}
