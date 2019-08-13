package stake

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/json"
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

	cfgApprovalSpender = "stake.approval.spender"

	cfgWithdrawalFrom = "stake.withdrawal.from"
)

var (
	accountCmd = &cobra.Command{
		Use:   "account",
		Short: "account management commands",
	}

	accountInfoCmd = &cobra.Command{
		Use:   "info",
		Short: "query account info",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerAccountInfoFlags(cmd)
		},
		Run: doAccountInfo,
	}

	accountSubmitCmd = &cobra.Command{
		Use:   "submit",
		Short: "Submit a pre-generated transaction",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerAccountSubmitFlags(cmd)
		},
		Run: doAccountSubmit,
	}

	accountTransferCmd = &cobra.Command{
		Use:   "gen_transfer",
		Short: "generate a transfer transaction",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerAccountTransferFlags(cmd)
		},
		Run: doAccountTransfer,
	}

	accountApproveCmd = &cobra.Command{
		Use:   "gen_approve",
		Short: "generate an approval transaction",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerAccountApproveFlags(cmd)
		},
		Run: doAccountApprove,
	}

	accountWithdrawCmd = &cobra.Command{
		Use:   "gen_withdraw",
		Short: "Generate a withdrawal transaction",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerAccountWithdrawFlags(cmd)
		},
		Run: doAccountWithdraw,
	}

	accountBurnCmd = &cobra.Command{
		Use:   "gen_burn",
		Short: "Generate a burn transaction",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerTxFlags(cmd)
		},
		Run: doAccountBurn,
	}

	accountEscrowCmd = &cobra.Command{
		Use:   "gen_escrow",
		Short: "Generate an escrow (stake) transaction",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerTxFlags(cmd)
		},
		Run: doAccountEscrow,
	}

	accountReclaimEscrowCmd = &cobra.Command{
		Use:   "gen_reclaim_escrow",
		Short: "Generate a reclaim_escrow (unstake) transaction",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerTxFlags(cmd)
		},
		Run: doAccountReclaimEscrow,
	}
)

type serializedTx struct {
	Transfer      *api.SignedTransfer      `codec:"tranfer"`
	Approval      *api.SignedApproval      `codec:"approval"`
	Withdrawal    *api.SignedWithdrawal    `codec:"withdrawal"`
	Burn          *api.SignedBurn          `codec:"burn"`
	Escrow        *api.SignedEscrow        `codec:"escrow"`
	ReclaimEscrow *api.SignedReclaimEscrow `codec:"reclaim_escrow"`
}

func (tx *serializedTx) MustSave() {
	rawTx := json.Marshal(tx)
	if err := ioutil.WriteFile(viper.GetString(cfgTxFile), rawTx, 0600); err != nil {
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
	fmt.Printf("%v\n", string(json.Marshal(ai)))
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
		if signed := tx.Approval; signed != nil {
			_, err = client.Approve(ctx, &grpcStaking.ApproveRequest{
				SignedApproval: cbor.Marshal(signed),
			})
		}
		if signed := tx.Withdrawal; signed != nil {
			_, err = client.Withdraw(ctx, &grpcStaking.WithdrawRequest{
				SignedWithdrawal: cbor.Marshal(signed),
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

func doAccountApprove(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	assertTxFileOK()

	var approval api.Approval
	if err := approval.Spender.UnmarshalHex(viper.GetString(cfgApprovalSpender)); err != nil {
		logger.Error("failed to parse approval spender ID",
			"err", err,
		)
		os.Exit(1)
	}
	if err := approval.Tokens.UnmarshalText([]byte(viper.GetString(cfgTxAmount))); err != nil {
		logger.Error("failed to parse approval amount",
			"err", err,
		)
		os.Exit(1)
	}
	approval.Nonce = viper.GetUint64(cfgTxNonce)

	_, signer, err := cmdCommon.LoadEntity(cmdFlags.Entity())
	if err != nil {
		logger.Error("failed to load account entity",
			"err", err,
		)
		os.Exit(1)
	}
	defer signer.Reset()

	signedApproval, err := api.SignApproval(signer, &approval)
	if err != nil {
		logger.Error("failed to sign approval",
			"err", err,
		)
		os.Exit(1)
	}

	tx := &serializedTx{
		Approval: signedApproval,
	}
	tx.MustSave()
}

func doAccountWithdraw(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	assertTxFileOK()

	var withdrawal api.Withdrawal
	if err := withdrawal.From.UnmarshalHex(viper.GetString(cfgWithdrawalFrom)); err != nil {
		logger.Error("failed to parse withdrawal source ID",
			"err", err,
		)
		os.Exit(1)
	}
	if err := withdrawal.Tokens.UnmarshalText([]byte(viper.GetString(cfgTxAmount))); err != nil {
		logger.Error("failed to parse withdrawal amount",
			"err", err,
		)
		os.Exit(1)
	}
	withdrawal.Nonce = viper.GetUint64(cfgTxNonce)

	_, signer, err := cmdCommon.LoadEntity(cmdFlags.Entity())
	if err != nil {
		logger.Error("failed to load account entity",
			"err", err,
		)
		os.Exit(1)
	}
	defer signer.Reset()

	signedWithdrawal, err := api.SignWithdrawal(signer, &withdrawal)
	if err != nil {
		logger.Error("failed to sign withdrawal",
			"err", err,
		)
		os.Exit(1)
	}

	tx := &serializedTx{
		Withdrawal: signedWithdrawal,
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

func registerAccountInfoFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgAccountID, "", "ID of the account")
	}

	for _, v := range []string{
		cfgAccountID,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}

	cmdFlags.RegisterRetries(cmd)
	cmdGrpc.RegisterClientFlags(cmd, false)
}

func registerAccountSubmitFlags(cmd *cobra.Command) {
	registerTxFileFlag(cmd)

	cmdFlags.RegisterRetries(cmd)
	cmdGrpc.RegisterClientFlags(cmd, false)
}

func registerTxFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Uint64(cfgTxNonce, 0, "nonce of the source account")
		cmd.Flags().String(cfgTxAmount, "0", "amount of tokens for the transaction")
	}

	for _, v := range []string{
		cfgTxNonce,
		cfgTxAmount,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}

	registerTxFileFlag(cmd)
	cmdFlags.RegisterDebugTestEntity(cmd)
	cmdFlags.RegisterEntity(cmd)
}

func registerTxFileFlag(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgTxFile, "", "path to the transaction")
	}

	_ = viper.BindPFlag(cfgTxFile, cmd.Flags().Lookup(cfgTxFile))
}

func registerAccountTransferFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgTransferDestination, "", "transfer destination account ID")
	}

	for _, v := range []string{
		cfgTransferDestination,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}

	registerTxFlags(cmd)
}

func registerAccountApproveFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgApprovalSpender, "", "approval spender account ID")
	}

	for _, v := range []string{
		cfgApprovalSpender,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}

	registerTxFlags(cmd)
}

func registerAccountWithdrawFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgWithdrawalFrom, "", "withdrawal source account ID")
	}

	for _, v := range []string{
		cfgWithdrawalFrom,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}

	registerTxFlags(cmd)
}

func registerAccountCmd() {
	for _, v := range []*cobra.Command{
		accountInfoCmd,
		accountSubmitCmd,
		accountTransferCmd,
		accountApproveCmd,
		accountWithdrawCmd,
		accountBurnCmd,
		accountReclaimEscrowCmd,
	} {
		accountCmd.AddCommand(v)
	}

	registerAccountInfoFlags(accountInfoCmd)
	registerAccountSubmitFlags(accountSubmitCmd)
	registerAccountTransferFlags(accountTransferCmd)
	registerAccountApproveFlags(accountApproveCmd)
	registerAccountWithdrawFlags(accountWithdrawCmd)
	registerTxFlags(accountBurnCmd)
	registerTxFlags(accountEscrowCmd)
	registerTxFlags(accountReclaimEscrowCmd)
}
