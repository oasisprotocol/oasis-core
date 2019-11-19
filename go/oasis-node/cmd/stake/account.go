package stake

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/consensus/gas"
	genesisFile "github.com/oasislabs/oasis-core/go/genesis/file"
	grpcStaking "github.com/oasislabs/oasis-core/go/grpc/staking"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasislabs/oasis-core/go/staking/api"
)

const (
	// CfgAccountID configures the account address.
	CfgAccountID = "stake.account.id"

	// CfgTxNonce configures the nonce.
	CfgTxNonce = "stake.transaction.nonce"

	// CfgTxFeeAmount configures the fee amount in tokens.
	CfgTxFeeAmount = "stake.transaction.fee.amount"

	// CfgTxFeeGas configures the maximum gas limit.
	CfgTxFeeGas = "stake.transaction.fee.gas"

	// CfgTxFile configures the filename for the transaction.
	CfgTxFile = "stake.transaction.file"

	// CfgAmount configures the amount of tokens.
	CfgAmount = "stake.transaction.amount"

	// CfgTransferDestination configures the transfer destination address.
	CfgTransferDestination = "stake.transfer.destination"

	// CfgEscrowAccount configures the escrow address.
	CfgEscrowAccount = "stake.escrow.account"

	// CfgCommissionScheduleRates configures the commission schedule rate steps.
	CfgCommissionScheduleRates = "stake.commission_schedule.rates"

	// CfgCommissionScheduleBounds configures the commission schedule rate bound steps.
	CfgCommissionScheduleBounds = "stake.commission_schedule.bounds"
)

var (
	accountInfoFlags        = flag.NewFlagSet("", flag.ContinueOnError)
	accountSubmitFlags      = flag.NewFlagSet("", flag.ContinueOnError)
	txFlags                 = flag.NewFlagSet("", flag.ContinueOnError)
	amountFlags             = flag.NewFlagSet("", flag.ContinueOnError)
	txFileFlags             = flag.NewFlagSet("", flag.ContinueOnError)
	escrowFlags             = flag.NewFlagSet("", flag.ContinueOnError)
	commissionScheduleFlags = flag.NewFlagSet("", flag.ContinueOnError)
	accountTransferFlags    = flag.NewFlagSet("", flag.ContinueOnError)

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

	accountAmendCommissionScheduleCmd = &cobra.Command{
		Use:   "gen_amend_commission_schedule",
		Short: "Generate an amend_commission_schedule transaction",
		Run:   doAccountAmendCommissionSchedule,
	}
)

type serializedTx struct {
	Transfer                *api.SignedTransfer                `json:"tranfer"`
	Burn                    *api.SignedBurn                    `json:"burn"`
	Escrow                  *api.SignedEscrow                  `json:"escrow"`
	ReclaimEscrow           *api.SignedReclaimEscrow           `json:"reclaim_escrow"`
	AmendCommissionSchedule *api.SignedAmendCommissionSchedule `json:"amend_commission_schedule"`
}

func (tx *serializedTx) MustSave() {
	rawTx, err := json.Marshal(tx)
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

func assertTxFileOK() {
	f := viper.GetString(CfgTxFile)
	if f == "" {
		logger.Error("failed to determine tx file")
		os.Exit(1)
	}

	// XXX: Other checks to see if we can write to the file?
}

func initGenesis() {
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
		logger.Error("failed to load genesis file",
			"err", err,
		)
		os.Exit(1)
	}
	signature.SetChainContext(genesisDoc.ChainID)
}

func doAccountInfo(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	var id signature.PublicKey
	if err := id.UnmarshalHex(viper.GetString(CfgAccountID)); err != nil {
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

	rawTx, err := ioutil.ReadFile(viper.GetString(CfgTxFile))
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
		if signed := tx.AmendCommissionSchedule; signed != nil {
			_, err = client.AmendCommissionSchedule(ctx, &grpcStaking.AmendCommissionScheduleRequest{
				SignedAmendCommissionSchedule: cbor.Marshal(signed),
			})
		}
		return err
	})
}

func doAccountTransfer(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	initGenesis()
	assertTxFileOK()

	var xfer api.Transfer
	if err := xfer.To.UnmarshalHex(viper.GetString(CfgTransferDestination)); err != nil {
		logger.Error("failed to parse transfer destination ID",
			"err", err,
		)
		os.Exit(1)
	}
	if err := xfer.Tokens.UnmarshalText([]byte(viper.GetString(CfgAmount))); err != nil {
		logger.Error("failed to parse transfer amount",
			"err", err,
		)
		os.Exit(1)
	}
	xfer.Nonce = viper.GetUint64(CfgTxNonce)
	if err := xfer.Fee.Amount.UnmarshalText([]byte(viper.GetString(CfgTxFeeAmount))); err != nil {
		logger.Error("failed to parse fee amount",
			"err", err,
		)
		os.Exit(1)
	}
	xfer.Fee.Gas = gas.Gas(viper.GetUint64(CfgTxFeeGas))

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

	initGenesis()
	assertTxFileOK()

	var burn api.Burn
	if err := burn.Tokens.UnmarshalText([]byte(viper.GetString(CfgAmount))); err != nil {
		logger.Error("failed to parse burn amount",
			"err", err,
		)
		os.Exit(1)
	}
	burn.Nonce = viper.GetUint64(CfgTxNonce)
	if err := burn.Fee.Amount.UnmarshalText([]byte(viper.GetString(CfgTxFeeAmount))); err != nil {
		logger.Error("failed to parse fee amount",
			"err", err,
		)
		os.Exit(1)
	}
	burn.Fee.Gas = gas.Gas(viper.GetUint64(CfgTxFeeGas))

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

	initGenesis()
	assertTxFileOK()

	var escrow api.Escrow
	if err := escrow.Account.UnmarshalHex(viper.GetString(CfgEscrowAccount)); err != nil {
		logger.Error("failed to parse escrow account",
			"err", err,
		)
		os.Exit(1)
	}
	if err := escrow.Tokens.UnmarshalText([]byte(viper.GetString(CfgAmount))); err != nil {
		logger.Error("failed to parse escrow amount",
			"err", err,
		)
		os.Exit(1)
	}
	escrow.Nonce = viper.GetUint64(CfgTxNonce)
	if err := escrow.Fee.Amount.UnmarshalText([]byte(viper.GetString(CfgTxFeeAmount))); err != nil {
		logger.Error("failed to parse fee amount",
			"err", err,
		)
		os.Exit(1)
	}
	escrow.Fee.Gas = gas.Gas(viper.GetUint64(CfgTxFeeGas))

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

	initGenesis()
	assertTxFileOK()

	var reclaim api.ReclaimEscrow
	if err := reclaim.Account.UnmarshalHex(viper.GetString(CfgEscrowAccount)); err != nil {
		logger.Error("failed to parse escrow account",
			"err", err,
		)
		os.Exit(1)
	}
	if err := reclaim.Shares.UnmarshalText([]byte(viper.GetString(CfgAmount))); err != nil {
		logger.Error("failed to parse escrow reclaim amount",
			"err", err,
		)
		os.Exit(1)
	}
	reclaim.Nonce = viper.GetUint64(CfgTxNonce)
	if err := reclaim.Fee.Amount.UnmarshalText([]byte(viper.GetString(CfgTxFeeAmount))); err != nil {
		logger.Error("failed to parse fee amount",
			"err", err,
		)
		os.Exit(1)
	}
	reclaim.Fee.Gas = gas.Gas(viper.GetUint64(CfgTxFeeGas))

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

func scanRateStep(dst *api.CommissionRateStep, raw string) error {
	var rateBI big.Int
	n, err := fmt.Sscanf(raw, "%d/%d", &dst.Start, &rateBI)
	if err != nil {
		return err
	}
	if n != 2 {
		return fmt.Errorf("scanned %d tokens (need 2)", n)
	}
	if err = dst.Rate.FromBigInt(&rateBI); err != nil {
		return errors.Wrap(err, "rate")
	}
	return nil
}

func scanBoundStep(dst *api.CommissionRateBoundStep, raw string) error {
	var rateMinBI big.Int
	var rateMaxBI big.Int
	n, err := fmt.Sscanf(raw, "%d/%d/%d", &dst.Start, &rateMinBI, &rateMaxBI)
	if err != nil {
		return err
	}
	if n != 3 {
		return fmt.Errorf("scanned %d tokens (need 3)", n)
	}
	if err = dst.RateMin.FromBigInt(&rateMinBI); err != nil {
		return errors.Wrap(err, "rate min")
	}
	if err = dst.RateMax.FromBigInt(&rateMaxBI); err != nil {
		return errors.Wrap(err, "rate max")
	}
	return nil
}

func doAccountAmendCommissionSchedule(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	initGenesis()
	assertTxFileOK()

	var amendCommissionSchedule api.AmendCommissionSchedule
	rawRates := viper.GetStringSlice(CfgCommissionScheduleRates)
	if rawRates != nil {
		amendCommissionSchedule.Amendment.Rates = make([]api.CommissionRateStep, len(rawRates))
		for i, rawRate := range rawRates {
			if err := scanRateStep(&amendCommissionSchedule.Amendment.Rates[i], rawRate); err != nil {
				logger.Error("failed to parse commission schedule rate step",
					"err", err,
					"index", i,
					"raw_rate", rawRate,
				)
				os.Exit(1)
			}
		}
	}
	rawBounds := viper.GetStringSlice(CfgCommissionScheduleBounds)
	if rawBounds != nil {
		amendCommissionSchedule.Amendment.Bounds = make([]api.CommissionRateBoundStep, len(rawBounds))
		for i, rawBound := range rawBounds {
			if err := scanBoundStep(&amendCommissionSchedule.Amendment.Bounds[i], rawBound); err != nil {
				logger.Error("failed to parse commission schedule bound step",
					"err", err,
					"index", i,
					"raw_bound", rawBound,
				)
				os.Exit(1)
			}
		}
	}
	amendCommissionSchedule.Nonce = viper.GetUint64(CfgTxNonce)
	if err := amendCommissionSchedule.Fee.Amount.UnmarshalText([]byte(viper.GetString(CfgTxFeeAmount))); err != nil {
		logger.Error("failed to parse fee amount",
			"err", err,
		)
		os.Exit(1)
	}
	amendCommissionSchedule.Fee.Gas = gas.Gas(viper.GetUint64(CfgTxFeeGas))

	_, signer, err := cmdCommon.LoadEntity(cmdFlags.Entity())
	if err != nil {
		logger.Error("failed to load account entity",
			"err", err,
		)
		os.Exit(1)
	}
	defer signer.Reset()

	signedAmendCommissionSchedule, err := api.SignAmendCommissionSchedule(signer, &amendCommissionSchedule)
	if err != nil {
		logger.Error("failed to sign amend_commission_schedule",
			"err", err,
		)
		os.Exit(1)
	}

	tx := &serializedTx{
		AmendCommissionSchedule: signedAmendCommissionSchedule,
	}
	tx.MustSave()
}

func registerAccountCmd() {
	for _, v := range []*cobra.Command{
		accountInfoCmd,
		accountSubmitCmd,
		accountTransferCmd,
		accountBurnCmd,
		accountEscrowCmd,
		accountReclaimEscrowCmd,
		accountAmendCommissionScheduleCmd,
	} {
		accountCmd.AddCommand(v)
	}

	accountInfoCmd.Flags().AddFlagSet(accountInfoFlags)
	accountSubmitCmd.Flags().AddFlagSet(accountSubmitFlags)
	accountTransferCmd.Flags().AddFlagSet(accountTransferFlags)
	accountBurnCmd.Flags().AddFlagSet(txFlags)
	accountBurnCmd.Flags().AddFlagSet(amountFlags)
	accountEscrowCmd.Flags().AddFlagSet(escrowFlags)
	accountReclaimEscrowCmd.Flags().AddFlagSet(escrowFlags)
	accountAmendCommissionScheduleCmd.Flags().AddFlagSet(commissionScheduleFlags)
}

func init() {
	accountInfoFlags.String(CfgAccountID, "", "ID of the account")
	_ = viper.BindPFlags(accountInfoFlags)
	accountInfoFlags.AddFlagSet(cmdFlags.RetriesFlags)
	accountInfoFlags.AddFlagSet(cmdGrpc.ClientFlags)

	txFileFlags.String(CfgTxFile, "", "path to the transaction")
	_ = viper.BindPFlags(txFileFlags)

	accountSubmitFlags.AddFlagSet(accountInfoFlags)
	accountSubmitFlags.AddFlagSet(cmdFlags.RetriesFlags)
	accountSubmitFlags.AddFlagSet(cmdGrpc.ClientFlags)
	accountSubmitFlags.AddFlagSet(txFileFlags)

	txFlags.Uint64(CfgTxNonce, 0, "nonce of the source account")
	txFlags.Uint64(CfgTxFeeAmount, 0, "transaction fee in tokens")
	txFlags.String(CfgTxFeeGas, "0", "maximum gas limit")
	_ = viper.BindPFlags(txFlags)
	txFlags.AddFlagSet(txFileFlags)
	txFlags.AddFlagSet(cmdFlags.DebugTestEntityFlags)
	txFlags.AddFlagSet(cmdFlags.EntityFlags)
	txFlags.AddFlagSet(cmdFlags.GenesisFileFlags)

	amountFlags.String(CfgAmount, "0", "amount of tokens for the transaction")
	_ = viper.BindPFlags(amountFlags)

	accountTransferFlags.String(CfgTransferDestination, "", "transfer destination account ID")
	_ = viper.BindPFlags(accountTransferFlags)
	accountTransferFlags.AddFlagSet(txFlags)
	accountTransferFlags.AddFlagSet(amountFlags)

	escrowFlags.String(CfgEscrowAccount, "", "ID of the escrow account")
	_ = viper.BindPFlags(escrowFlags)
	escrowFlags.AddFlagSet(txFlags)
	escrowFlags.AddFlagSet(amountFlags)

	commissionScheduleFlags.StringSlice(CfgCommissionScheduleRates, nil, fmt.Sprintf("commission rate step. Multiple of this flag is allowed. Each step is in the format start_epoch/rate_numerator. The rate is rate_numerator divided by %v", api.CommissionRateDenominator))
	commissionScheduleFlags.StringSlice(CfgCommissionScheduleBounds, nil, fmt.Sprintf("commission rate bound step. Multiple of this flag is allowed. Each step is in the format start_epoch/rate_min_numerator/rate_max_numerator. The minimum rate is rate_min_numerator divided by %v, and the maximum rate is rate_max_numerator divided by %v", api.CommissionRateDenominator, api.CommissionRateDenominator))
	_ = viper.BindPFlags(commissionScheduleFlags)
	commissionScheduleFlags.AddFlagSet(txFlags)
}
