package stake

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	cmdFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	grpcStaking "github.com/oasislabs/ekiden/go/grpc/staking"
	"github.com/oasislabs/ekiden/go/staking/api"
)

const (
	cfgAccountID = "stake.account.id"

	cfgTxNonce  = "stake.transaction.nonce"
	cfgTxAmount = "stake.transaction.amount"
	cfgTxFile   = "stake.transaction.file"

	cfgTransferDestination = "stake.transfer.destination"
)

var (
	accountInfoFlags     = flag.NewFlagSet("", flag.ContinueOnError)
	accountSubmitFlags   = flag.NewFlagSet("", flag.ContinueOnError)
	txFlags              = flag.NewFlagSet("", flag.ContinueOnError)
	txFileFlags          = flag.NewFlagSet("", flag.ContinueOnError)
	accountTransferFlags = flag.NewFlagSet("", flag.ContinueOnError)

	accountCmd = &cobra.Command{
		Use:   "account",
		Short: "account management commands",
	}

	accountInfoCmd = &cobra.Command{
		Use:   "info",
		Short: "query account info",
		Run:   doAccountInfo,
	}

	accountSubmitCmd = &cobra.Command{
		Use:   "submit",
		Short: "Submit a pre-generated transaction",
		Run:   doAccountSubmit,
	}

	accountTransferCmd = &cobra.Command{
		Use:   "gen_transfer",
		Short: "generate a transfer transaction",
		Run:   doAccountTransfer,
	}

	accountBurnCmd = &cobra.Command{
		Use:   "gen_burn",
		Short: "Generate a burn transaction",
		Run:   doAccountBurn,
	}

	accountEscrowCmd = &cobra.Command{
		Use:   "gen_escrow",
		Short: "Generate an escrow (stake) transaction",
		Run:   doAccountEscrow,
	}

	accountReclaimEscrowCmd = &cobra.Command{
		Use:   "gen_reclaim_escrow",
		Short: "Generate a reclaim_escrow (unstake) transaction",
		Run:   doAccountReclaimEscrow,
	}
)

type serializedTx struct {
	Transfer      *api.SignedTransfer      `json:"tranfer"`
	Burn          *api.SignedBurn          `json:"burn"`
	Escrow        *api.SignedEscrow        `json:"escrow"`
	ReclaimEscrow *api.SignedReclaimEscrow `json:"reclaim_escrow"`
}

func (tx *serializedTx) MustSave() {
	rawTx, err := json.Marshal(tx)
	if err != nil {
		logger.Error("failed to marshal transaction",
			"err", err,
		)
		os.Exit(1)
	}
	if err = ioutil.WriteFile(viper.GetString(cfgTxFile), rawTx, 0600); err != nil {
		logger.Error("failed to save transaction",
			"err", err,
		)
		os.Exit(1)
	}
}

func assertTxFileOK() {
	f := viper.GetString(cfgTxFile)
	if f == "" {
		logger.Error("failed to determine tx file")
		os.Exit(1)
	}

	// XXX: Other checks to see if we can write to the file?
}

func doAccountInfo(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	var id signature.PublicKey
	if err := id.UnmarshalHex(viper.GetString(cfgAccountID)); err != nil {
		logger.Error("failed to parse account ID",
			"err", err,
		)
		os.Exit(1)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	ctx := context.Background()
	ai := getAccountInfo(ctx, cmd, id, client)
	b, _ := json.Marshal(ai)
	fmt.Printf("%v\n", string(b))
}

func doAccountSubmit(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	rawTx, err := ioutil.ReadFile(viper.GetString(cfgTxFile))
	if err != nil {
		logger.Error("failed to read raw serialized transaction",
			"err", err,
		)
		os.Exit(1)
	}

	var tx serializedTx
	if err = json.Unmarshal(rawTx, &tx); err != nil {
		logger.Error("failed to parse serialized transaction",
			"err", err,
		)
		os.Exit(1)
	}

	ctx := context.Background()
	doWithRetries(cmd, "submit transaction", func() error {
		if signed := tx.Transfer; signed != nil {
			_, err = client.Transfer(ctx, &grpcStaking.TransferRequest{
				SignedTransfer: cbor.Marshal(signed),
			})
		}
		if signed := tx.Burn; signed != nil {
			_, err = client.Burn(ctx, &grpcStaking.BurnRequest{
				SignedBurn: cbor.Marshal(signed),
			})
		}
		if signed := tx.Escrow; signed != nil {
			_, err = client.AddEscrow(ctx, &grpcStaking.AddEscrowRequest{
				SignedEscrow: cbor.Marshal(signed),
			})
		}
		if signed := tx.ReclaimEscrow; signed != nil {
			_, err = client.ReclaimEscrow(ctx, &grpcStaking.ReclaimEscrowRequest{
				SignedReclaim: cbor.Marshal(signed),
			})
		}
		return err
	})
}

func doAccountTransfer(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	assertTxFileOK()

	var xfer api.Transfer
	if err := xfer.To.UnmarshalHex(viper.GetString(cfgTransferDestination)); err != nil {
		logger.Error("failed to parse transfer destination ID",
			"err", err,
		)
		os.Exit(1)
	}
	if err := xfer.Tokens.UnmarshalText([]byte(viper.GetString(cfgTxAmount))); err != nil {
		logger.Error("failed to parse transfer amount",
			"err", err,
		)
		os.Exit(1)
	}
	xfer.Nonce = viper.GetUint64(cfgTxNonce)

	_, signer, err := cmdCommon.LoadEntity(cmdFlags.Entity())
	if err != nil {
		logger.Error("failed to load account entity",
			"err", err,
		)
		os.Exit(1)
	}
	defer signer.Reset()

	signedXfer, err := api.SignTransfer(signer, &xfer)
	if err != nil {
		logger.Error("failed to sign transfer",
			"err", err,
		)
		os.Exit(1)
	}

	tx := &serializedTx{
		Transfer: signedXfer,
	}
	tx.MustSave()
}

func doAccountBurn(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	assertTxFileOK()

	var burn api.Burn
	if err := burn.Tokens.UnmarshalText([]byte(viper.GetString(cfgTxAmount))); err != nil {
		logger.Error("failed to parse burn amount",
			"err", err,
		)
		os.Exit(1)
	}
	burn.Nonce = viper.GetUint64(cfgTxNonce)

	_, signer, err := cmdCommon.LoadEntity(cmdFlags.Entity())
	if err != nil {
		logger.Error("failed to load account entity",
			"err", err,
		)
		os.Exit(1)
	}
	defer signer.Reset()

	signedBurn, err := api.SignBurn(signer, &burn)
	if err != nil {
		logger.Error("failed to sign burn",
			"err", err,
		)
		os.Exit(1)
	}

	tx := &serializedTx{
		Burn: signedBurn,
	}
	tx.MustSave()
}

func doAccountEscrow(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	assertTxFileOK()

	var escrow api.Escrow
	if err := escrow.Tokens.UnmarshalText([]byte(viper.GetString(cfgTxAmount))); err != nil {
		logger.Error("failed to parse escrow amount",
			"err", err,
		)
		os.Exit(1)
	}
	escrow.Nonce = viper.GetUint64(cfgTxNonce)

	_, signer, err := cmdCommon.LoadEntity(cmdFlags.Entity())
	if err != nil {
		logger.Error("failed to load account entity",
			"err", err,
		)
		os.Exit(1)
	}
	defer signer.Reset()

	signedEscrow, err := api.SignEscrow(signer, &escrow)
	if err != nil {
		logger.Error("failed to sign escrow",
			"err", err,
		)
		os.Exit(1)
	}

	tx := &serializedTx{
		Escrow: signedEscrow,
	}
	tx.MustSave()
}

func doAccountReclaimEscrow(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	assertTxFileOK()

	var reclaim api.ReclaimEscrow
	if err := reclaim.Tokens.UnmarshalText([]byte(viper.GetString(cfgTxAmount))); err != nil {
		logger.Error("failed to parse escrow reclaim amount",
			"err", err,
		)
		os.Exit(1)
	}
	reclaim.Nonce = viper.GetUint64(cfgTxNonce)

	_, signer, err := cmdCommon.LoadEntity(cmdFlags.Entity())
	if err != nil {
		logger.Error("failed to load account entity",
			"err", err,
		)
		os.Exit(1)
	}
	defer signer.Reset()

	signedReclaim, err := api.SignReclaimEscrow(signer, &reclaim)
	if err != nil {
		logger.Error("failed to sign reclaim_escrow",
			"err", err,
		)
		os.Exit(1)
	}

	tx := &serializedTx{
		ReclaimEscrow: signedReclaim,
	}
	tx.MustSave()
}

func registerAccountCmd() {
	for _, v := range []*cobra.Command{
		accountInfoCmd,
		accountSubmitCmd,
		accountTransferCmd,
		accountBurnCmd,
		accountReclaimEscrowCmd,
	} {
		accountCmd.AddCommand(v)
	}

	accountInfoCmd.Flags().AddFlagSet(accountInfoFlags)
	accountSubmitCmd.Flags().AddFlagSet(accountSubmitFlags)
	accountTransferCmd.Flags().AddFlagSet(accountTransferFlags)
	accountBurnCmd.Flags().AddFlagSet(txFlags)
	accountEscrowCmd.Flags().AddFlagSet(txFlags)
	accountReclaimEscrowCmd.Flags().AddFlagSet(txFlags)
}

func init() {
	accountInfoFlags.String(cfgAccountID, "", "ID of the account")
	_ = viper.BindPFlags(accountInfoFlags)
	accountInfoFlags.AddFlagSet(cmdFlags.RetriesFlags)
	accountInfoFlags.AddFlagSet(cmdGrpc.ClientFlags)

	accountSubmitFlags.AddFlagSet(accountInfoFlags)
	accountSubmitFlags.AddFlagSet(cmdFlags.RetriesFlags)
	accountSubmitFlags.AddFlagSet(cmdGrpc.ClientFlags)

	txFileFlags.String(cfgTxFile, "", "path to the transaction")
	_ = viper.BindPFlags(txFileFlags)

	txFlags.Uint64(cfgTxNonce, 0, "nonce of the source account")
	txFlags.String(cfgTxAmount, "0", "amount of tokens for the transaction")
	_ = viper.BindPFlags(txFlags)
	txFlags.AddFlagSet(txFileFlags)
	txFlags.AddFlagSet(cmdFlags.DebugTestEntityFlags)
	txFlags.AddFlagSet(cmdFlags.EntityFlags)

	accountTransferFlags.String(cfgTransferDestination, "", "transfer destination account ID")
	_ = viper.BindPFlags(accountTransferFlags)
	accountTransferFlags.AddFlagSet(txFlags)
}
