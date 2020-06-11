package stake

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	// CfgAccountAddr configures the account address.
	CfgAccountAddr = "stake.account.address"

	// CfgAmount configures the amount of tokens.
	CfgAmount = "stake.amount"

	// CfgShares configures the amount of shares.
	CfgShares = "stake.shares"

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
	amountFlags             = flag.NewFlagSet("", flag.ContinueOnError)
	sharesFlags             = flag.NewFlagSet("", flag.ContinueOnError)
	commonEscrowFlags       = flag.NewFlagSet("", flag.ContinueOnError)
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

func doAccountInfo(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	var addr staking.Address
	if err := addr.UnmarshalText([]byte(viper.GetString(CfgAccountAddr))); err != nil {
		logger.Error("failed to parse account address",
			"err", err,
		)
		os.Exit(1)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	ctx := context.Background()
	acct := getAccount(ctx, cmd, addr, client)
	acctData, _ := json.Marshal(acct)
	fmt.Printf("%v\n", string(acctData))
}

func doAccountTransfer(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	var xfer staking.Transfer
	if err := xfer.To.UnmarshalText([]byte(viper.GetString(CfgTransferDestination))); err != nil {
		logger.Error("failed to parse transfer destination account address",
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

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := staking.NewTransferTx(nonce, fee, &xfer)

	cmdConsensus.SignAndSaveTx(tx)
}

func doAccountBurn(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	var burn staking.Burn
	if err := burn.Tokens.UnmarshalText([]byte(viper.GetString(CfgAmount))); err != nil {
		logger.Error("failed to parse burn amount",
			"err", err,
		)
		os.Exit(1)
	}

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := staking.NewBurnTx(nonce, fee, &burn)

	cmdConsensus.SignAndSaveTx(tx)
}

func doAccountEscrow(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	var escrow staking.Escrow
	if err := escrow.Account.UnmarshalText([]byte(viper.GetString(CfgEscrowAccount))); err != nil {
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

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := staking.NewAddEscrowTx(nonce, fee, &escrow)

	cmdConsensus.SignAndSaveTx(tx)
}

func doAccountReclaimEscrow(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	var reclaim staking.ReclaimEscrow
	if err := reclaim.Account.UnmarshalText([]byte(viper.GetString(CfgEscrowAccount))); err != nil {
		logger.Error("failed to parse escrow account",
			"err", err,
		)
		os.Exit(1)
	}
	if err := reclaim.Shares.UnmarshalText([]byte(viper.GetString(CfgShares))); err != nil {
		logger.Error("failed to parse escrow reclaim shares",
			"err", err,
		)
		os.Exit(1)
	}

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := staking.NewReclaimEscrowTx(nonce, fee, &reclaim)

	cmdConsensus.SignAndSaveTx(tx)
}

func scanRateStep(dst *staking.CommissionRateStep, raw string) error {
	var rateBI big.Int
	n, err := fmt.Sscanf(raw, "%d/%d", &dst.Start, &rateBI)
	if err != nil {
		return err
	}
	if n != 2 {
		return fmt.Errorf("scanned %d tokens (need 2)", n)
	}
	if err = dst.Rate.FromBigInt(&rateBI); err != nil {
		return fmt.Errorf("rate: %w", err)
	}
	return nil
}

func scanBoundStep(dst *staking.CommissionRateBoundStep, raw string) error {
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
		return fmt.Errorf("rate min: %w", err)
	}
	if err = dst.RateMax.FromBigInt(&rateMaxBI); err != nil {
		return fmt.Errorf("rate max: %w", err)
	}
	return nil
}

func doAccountAmendCommissionSchedule(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	var amendCommissionSchedule staking.AmendCommissionSchedule
	rawRates := viper.GetStringSlice(CfgCommissionScheduleRates)
	if rawRates != nil {
		amendCommissionSchedule.Amendment.Rates = make([]staking.CommissionRateStep, len(rawRates))
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
		amendCommissionSchedule.Amendment.Bounds = make([]staking.CommissionRateBoundStep, len(rawBounds))
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

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := staking.NewAmendCommissionScheduleTx(nonce, fee, &amendCommissionSchedule)

	cmdConsensus.SignAndSaveTx(tx)
}

func registerAccountCmd() {
	for _, v := range []*cobra.Command{
		accountInfoCmd,
		accountTransferCmd,
		accountBurnCmd,
		accountEscrowCmd,
		accountReclaimEscrowCmd,
		accountAmendCommissionScheduleCmd,
	} {
		accountCmd.AddCommand(v)
	}

	accountInfoCmd.Flags().AddFlagSet(accountInfoFlags)
	accountTransferCmd.Flags().AddFlagSet(accountTransferFlags)
	accountBurnCmd.Flags().AddFlagSet(cmdConsensus.TxFlags)
	accountBurnCmd.Flags().AddFlagSet(amountFlags)
	accountEscrowCmd.Flags().AddFlagSet(commonEscrowFlags)
	accountEscrowCmd.Flags().AddFlagSet(amountFlags)
	accountReclaimEscrowCmd.Flags().AddFlagSet(commonEscrowFlags)
	accountReclaimEscrowCmd.Flags().AddFlagSet(sharesFlags)
	accountAmendCommissionScheduleCmd.Flags().AddFlagSet(commissionScheduleFlags)
}

func init() {
	accountInfoFlags.String(CfgAccountAddr, "", "Address of the account")
	_ = viper.BindPFlags(accountInfoFlags)
	accountInfoFlags.AddFlagSet(cmdFlags.RetriesFlags)
	accountInfoFlags.AddFlagSet(cmdGrpc.ClientFlags)

	amountFlags.String(CfgAmount, "0", "amount of tokens for the transaction")
	_ = viper.BindPFlags(amountFlags)

	sharesFlags.String(CfgShares, "0", "amount of shares for the transaction")
	_ = viper.BindPFlags(sharesFlags)

	accountTransferFlags.String(CfgTransferDestination, "", "transfer destination account address")
	_ = viper.BindPFlags(accountTransferFlags)
	accountTransferFlags.AddFlagSet(cmdConsensus.TxFlags)
	accountTransferFlags.AddFlagSet(amountFlags)

	commonEscrowFlags.String(CfgEscrowAccount, "", "address of the escrow account")
	_ = viper.BindPFlags(commonEscrowFlags)
	commonEscrowFlags.AddFlagSet(cmdConsensus.TxFlags)

	commissionScheduleFlags.StringSlice(CfgCommissionScheduleRates, nil, fmt.Sprintf(
		"commission rate step. Multiple of this flag is allowed. "+
			"Each step is in the format start_epoch/rate_numerator. "+
			"The rate is rate_numerator divided by %v", staking.CommissionRateDenominator,
	))
	commissionScheduleFlags.StringSlice(CfgCommissionScheduleBounds, nil, fmt.Sprintf(
		"commission rate bound step. Multiple of this flag is allowed. "+
			"Each step is in the format start_epoch/rate_min_numerator/rate_max_numerator. "+
			"The minimum rate is rate_min_numerator divided by %v, and the maximum rate is "+
			"rate_max_numerator divided by %v", staking.CommissionRateDenominator, staking.CommissionRateDenominator,
	))
	_ = viper.BindPFlags(commissionScheduleFlags)
	commissionScheduleFlags.AddFlagSet(cmdConsensus.TxFlags)
}
