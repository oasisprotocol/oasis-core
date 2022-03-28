package stake

import (
	"context"
	"fmt"
	"math/big"
	"os"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	cmdContext "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/context"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	// CfgHeight configures the consensus height.
	CfgHeight = "height"

	// CfgAccountAddr configures the account address.
	CfgAccountAddr = "stake.account.address"

	// CfgAmount configures the amount of stake in base units.
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

	// CfgAllowBeneficiary configures the beneficiary address.
	CfgAllowBeneficiary = "stake.allow.beneficiary"

	// CfgAllowAmountChange configures the allowance change.
	CfgAllowAmountChange = "stake.allow.amount_change"

	// CfgWithdrawSource configures the withdrawal source address.
	CfgWithdrawSource = "stake.withdraw.source"
)

var (
	commonAccountFlags      = flag.NewFlagSet("", flag.ContinueOnError)
	amountFlags             = flag.NewFlagSet("", flag.ContinueOnError)
	sharesFlags             = flag.NewFlagSet("", flag.ContinueOnError)
	commonEscrowFlags       = flag.NewFlagSet("", flag.ContinueOnError)
	commissionScheduleFlags = flag.NewFlagSet("", flag.ContinueOnError)
	accountInfoFlags        = flag.NewFlagSet("", flag.ContinueOnError)
	accountTransferFlags    = flag.NewFlagSet("", flag.ContinueOnError)
	accountBurnFlags        = flag.NewFlagSet("", flag.ContinueOnError)
	accountAllowFlags       = flag.NewFlagSet("", flag.ContinueOnError)
	accountWithdrawFlags    = flag.NewFlagSet("", flag.ContinueOnError)

	accountCmd = &cobra.Command{
		Use:   "account",
		Short: "account management commands",
	}

	accountInfoCmd = &cobra.Command{
		Use:   "info",
		Short: "get account info",
		Run:   doAccountInfo,
	}

	accountNonceCmd = &cobra.Command{
		Use:   "nonce",
		Short: "get account nonce",
		Run:   doAccountNonce,
	}

	accountValidateAddressCmd = &cobra.Command{
		Use:   "validate_address",
		Short: "validate account address",
		Run:   doValidateAddress,
	}

	accountTransferCmd = &cobra.Command{
		Use:   "gen_transfer",
		Short: "generate a transfer transaction",
		Run:   doAccountTransfer,
	}

	accountBurnCmd = &cobra.Command{
		Use:   "gen_burn",
		Short: "generate a burn transaction",
		Run:   doAccountBurn,
	}

	accountEscrowCmd = &cobra.Command{
		Use:   "gen_escrow",
		Short: "generate an escrow (stake) transaction",
		Run:   doAccountEscrow,
	}

	accountReclaimEscrowCmd = &cobra.Command{
		Use:   "gen_reclaim_escrow",
		Short: "generate a reclaim escrow (unstake) transaction",
		Run:   doAccountReclaimEscrow,
	}

	accountAmendCommissionScheduleCmd = &cobra.Command{
		Use:   "gen_amend_commission_schedule",
		Short: "generate an amend commission schedule transaction",
		Run:   doAccountAmendCommissionSchedule,
	}

	accountAllowCmd = &cobra.Command{
		Use:   "gen_allow",
		Short: "generate an allow transaction",
		Run:   doAccountAllow,
	}

	accountWithdrawCmd = &cobra.Command{
		Use:   "gen_withdraw",
		Short: "generate a withdraw transaction",
		Run:   doAccountWithdraw,
	}
)

func doAccountInfo(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	var addr api.Address
	if err := addr.UnmarshalText([]byte(viper.GetString(CfgAccountAddr))); err != nil {
		logger.Error("failed to parse account address",
			"err", err,
		)
		os.Exit(1)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	height := viper.GetInt64(CfgHeight)

	ctx := context.Background()
	acct := getAccount(ctx, addr, height, client)
	outgoingDelegationInfos := getDelegationInfosFor(ctx, addr, height, client)
	incomingDelegations := getDelegationsTo(ctx, addr, height, client)
	outgoingDebondingDelegationInfos := getDebondingDelegationInfosFor(ctx, addr, height, client)
	incomingDebondingDelegations := getDebondingDelegationsTo(ctx, addr, height, client)
	symbol := getTokenSymbol(ctx, client)
	exp := getTokenValueExponent(ctx, client)
	ctx = context.WithValue(ctx, prettyprint.ContextKeyTokenSymbol, symbol)
	ctx = context.WithValue(ctx, prettyprint.ContextKeyTokenValueExponent, exp)

	fmt.Printf("Account State for Height: %d\n", height)
	fmt.Println("Balance:")
	prettyPrintAccountBalanceAndDelegationsFrom(ctx, addr, acct.General, outgoingDelegationInfos, outgoingDebondingDelegationInfos, "  ", os.Stdout)
	fmt.Println()

	if len(acct.General.Allowances) > 0 {
		fmt.Println("Allowances for this Account:")
		prettyPrintAllowances(ctx, addr, acct.General.Allowances, "  ", os.Stdout)
		fmt.Println()
	}

	if len(incomingDelegations) > 0 {
		fmt.Println("Active Delegations to this Account:")
		prettyPrintDelegationsTo(ctx, addr, acct.Escrow.Active, incomingDelegations, "  ", os.Stdout)
		fmt.Println()
	}

	if len(incomingDebondingDelegations) > 0 {
		fmt.Println("Debonding Delegations to this Account:")
		prettyPrintDelegationsTo(ctx, addr, acct.Escrow.Debonding, incomingDebondingDelegations, "  ", os.Stdout)
		fmt.Println()
	}

	cs := acct.Escrow.CommissionSchedule
	if len(cs.Rates) > 0 || len(cs.Bounds) > 0 {
		fmt.Println("Commission Schedule:")
		cs.PrettyPrint(ctx, "  ", os.Stdout)
		fmt.Println()
	}

	sa := acct.Escrow.StakeAccumulator
	if len(sa.Claims) > 0 {
		fmt.Println("Stake Accumulator:")
		sa.PrettyPrint(ctx, "  ", os.Stdout)
		fmt.Println()
	}

	fmt.Printf("Nonce: %d\n", acct.General.Nonce)
}

func doAccountNonce(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	var addr api.Address
	if err := addr.UnmarshalText([]byte(viper.GetString(CfgAccountAddr))); err != nil {
		logger.Error("failed to parse account address",
			"err", err,
		)
		os.Exit(1)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	height := consensus.HeightLatest

	ctx := context.Background()
	acct := getAccount(ctx, addr, height, client)
	fmt.Println(acct.General.Nonce)
}

func doValidateAddress(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	addrStr := viper.GetString(CfgAccountAddr)
	var addr api.Address
	err := addr.UnmarshalText([]byte(addrStr))

	switch cmdFlags.Verbose() {
	case true:
		if err != nil {
			fmt.Printf("account address '%s' is not valid: %v\n", addrStr, err)
			os.Exit(1)
		}
		fmt.Printf("account address '%s' is valid\n", addrStr)
	default:
		if err != nil {
			os.Exit(1)
		}
	}
}

func doAccountTransfer(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	genesis := cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	var xfer api.Transfer
	if err := xfer.To.UnmarshalText([]byte(viper.GetString(CfgTransferDestination))); err != nil {
		logger.Error("failed to parse transfer destination account address",
			"err", err,
		)
		os.Exit(1)
	}
	if err := xfer.Amount.UnmarshalText([]byte(viper.GetString(CfgAmount))); err != nil {
		logger.Error("failed to parse transfer amount",
			"err", err,
		)
		os.Exit(1)
	}

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := api.NewTransferTx(nonce, fee, &xfer)

	cmdConsensus.SignAndSaveTx(cmdContext.GetCtxWithGenesisInfo(genesis), tx, nil)
}

func doAccountBurn(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	genesis := cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	var burn api.Burn
	if err := burn.Amount.UnmarshalText([]byte(viper.GetString(CfgAmount))); err != nil {
		logger.Error("failed to parse burn amount",
			"err", err,
		)
		os.Exit(1)
	}

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := api.NewBurnTx(nonce, fee, &burn)

	cmdConsensus.SignAndSaveTx(cmdContext.GetCtxWithGenesisInfo(genesis), tx, nil)
}

func doAccountEscrow(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	genesis := cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	var escrow api.Escrow
	if err := escrow.Account.UnmarshalText([]byte(viper.GetString(CfgEscrowAccount))); err != nil {
		logger.Error("failed to parse escrow account",
			"err", err,
		)
		os.Exit(1)
	}
	if err := escrow.Amount.UnmarshalText([]byte(viper.GetString(CfgAmount))); err != nil {
		logger.Error("failed to parse escrow amount",
			"err", err,
		)
		os.Exit(1)
	}

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := api.NewAddEscrowTx(nonce, fee, &escrow)

	cmdConsensus.SignAndSaveTx(cmdContext.GetCtxWithGenesisInfo(genesis), tx, nil)
}

func doAccountReclaimEscrow(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	genesis := cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	var reclaim api.ReclaimEscrow
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
	tx := api.NewReclaimEscrowTx(nonce, fee, &reclaim)

	cmdConsensus.SignAndSaveTx(cmdContext.GetCtxWithGenesisInfo(genesis), tx, nil)
}

func scanRateStep(dst *api.CommissionRateStep, raw string) error {
	var rateBI big.Int
	n, err := fmt.Sscanf(raw, "%d/%d", &dst.Start, &rateBI)
	if err != nil {
		return err
	}
	if n != 2 {
		return fmt.Errorf("scanned %d values (need 2)", n)
	}
	if err = dst.Rate.FromBigInt(&rateBI); err != nil {
		return fmt.Errorf("rate: %w", err)
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
		return fmt.Errorf("scanned %d values (need 3)", n)
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

	genesis := cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

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

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := api.NewAmendCommissionScheduleTx(nonce, fee, &amendCommissionSchedule)

	cmdConsensus.SignAndSaveTx(cmdContext.GetCtxWithGenesisInfo(genesis), tx, nil)
}

func doAccountAllow(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	genesis := cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	var allow api.Allow
	if err := allow.Beneficiary.UnmarshalText([]byte(viper.GetString(CfgAllowBeneficiary))); err != nil {
		logger.Error("failed to parse beneficiary account address",
			"err", err,
		)
		os.Exit(1)
	}
	amountRaw := viper.GetString(CfgAllowAmountChange)
	if len(amountRaw) < 1 {
		logger.Error("malformed allowance change amount")
		os.Exit(1)
	}
	if amountRaw[0] == '-' {
		allow.Negative = true
		amountRaw = amountRaw[1:]
	}
	if err := allow.AmountChange.UnmarshalText([]byte(amountRaw)); err != nil {
		logger.Error("failed to parse allowance change amount",
			"err", err,
		)
		os.Exit(1)
	}

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := api.NewAllowTx(nonce, fee, &allow)

	cmdConsensus.SignAndSaveTx(cmdContext.GetCtxWithGenesisInfo(genesis), tx, nil)
}

func doAccountWithdraw(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	genesis := cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	var withdraw api.Withdraw
	if err := withdraw.From.UnmarshalText([]byte(viper.GetString(CfgWithdrawSource))); err != nil {
		logger.Error("failed to parse source account address",
			"err", err,
		)
		os.Exit(1)
	}
	if err := withdraw.Amount.UnmarshalText([]byte(viper.GetString(CfgAmount))); err != nil {
		logger.Error("failed to parse withdraw amount",
			"err", err,
		)
		os.Exit(1)
	}

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := api.NewWithdrawTx(nonce, fee, &withdraw)

	cmdConsensus.SignAndSaveTx(cmdContext.GetCtxWithGenesisInfo(genesis), tx, nil)
}

func registerAccountCmd() {
	for _, v := range []*cobra.Command{
		accountInfoCmd,
		accountNonceCmd,
		accountValidateAddressCmd,
		accountTransferCmd,
		accountBurnCmd,
		accountEscrowCmd,
		accountReclaimEscrowCmd,
		accountAmendCommissionScheduleCmd,
		accountAllowCmd,
		accountWithdrawCmd,
	} {
		accountCmd.AddCommand(v)
	}

	accountInfoCmd.Flags().AddFlagSet(commonAccountFlags)
	accountInfoCmd.Flags().AddFlagSet(accountInfoFlags)
	accountNonceCmd.Flags().AddFlagSet(commonAccountFlags)
	accountValidateAddressCmd.Flags().AddFlagSet(commonAccountFlags)
	accountValidateAddressCmd.Flags().AddFlagSet(cmdFlags.VerboseFlags)
	accountTransferCmd.Flags().AddFlagSet(accountTransferFlags)
	accountBurnCmd.Flags().AddFlagSet(accountBurnFlags)
	accountEscrowCmd.Flags().AddFlagSet(commonEscrowFlags)
	accountEscrowCmd.Flags().AddFlagSet(amountFlags)
	accountReclaimEscrowCmd.Flags().AddFlagSet(commonEscrowFlags)
	accountReclaimEscrowCmd.Flags().AddFlagSet(sharesFlags)
	accountAmendCommissionScheduleCmd.Flags().AddFlagSet(commissionScheduleFlags)
	accountAllowCmd.Flags().AddFlagSet(accountAllowFlags)
	accountWithdrawCmd.Flags().AddFlagSet(accountWithdrawFlags)
}

func init() {
	commonAccountFlags.String(CfgAccountAddr, "", "account address")
	_ = viper.BindPFlags(commonAccountFlags)
	commonAccountFlags.AddFlagSet(cmdGrpc.ClientFlags)

	amountFlags.String(CfgAmount, "0", "amount of stake (in base units) for the transaction")
	_ = viper.BindPFlags(amountFlags)

	sharesFlags.String(CfgShares, "0", "amount of shares for the transaction")
	_ = viper.BindPFlags(sharesFlags)

	accountInfoFlags.Int64(CfgHeight, consensus.HeightLatest, "height at which to query for info (default to latest height)")
	_ = viper.BindPFlags(accountInfoFlags)

	accountTransferFlags.String(CfgTransferDestination, "", "transfer destination account address")
	_ = viper.BindPFlags(accountTransferFlags)
	accountTransferFlags.AddFlagSet(cmdConsensus.TxFlags)
	accountTransferFlags.AddFlagSet(amountFlags)
	accountTransferFlags.AddFlagSet(cmdFlags.AssumeYesFlag)

	accountBurnFlags.AddFlagSet(cmdConsensus.TxFlags)
	accountBurnFlags.AddFlagSet(amountFlags)
	accountBurnFlags.AddFlagSet(cmdFlags.AssumeYesFlag)

	commonEscrowFlags.String(CfgEscrowAccount, "", "address of the escrow account")
	_ = viper.BindPFlags(commonEscrowFlags)
	commonEscrowFlags.AddFlagSet(cmdConsensus.TxFlags)
	commonEscrowFlags.AddFlagSet(cmdFlags.AssumeYesFlag)

	commissionScheduleFlags.StringSlice(CfgCommissionScheduleRates, nil, fmt.Sprintf(
		"commission rate step. Multiple of this flag is allowed. "+
			"Each step is in the format start_epoch/rate_numerator. "+
			"The rate is rate_numerator divided by %v", api.CommissionRateDenominator,
	))
	commissionScheduleFlags.StringSlice(CfgCommissionScheduleBounds, nil, fmt.Sprintf(
		"commission rate bound step. Multiple of this flag is allowed. "+
			"Each step is in the format start_epoch/rate_min_numerator/rate_max_numerator. "+
			"The minimum rate is rate_min_numerator divided by %v, and the maximum rate is "+
			"rate_max_numerator divided by %v", api.CommissionRateDenominator, api.CommissionRateDenominator,
	))
	_ = viper.BindPFlags(commissionScheduleFlags)
	commissionScheduleFlags.AddFlagSet(cmdConsensus.TxFlags)
	commissionScheduleFlags.AddFlagSet(cmdFlags.AssumeYesFlag)

	accountAllowFlags.String(CfgAllowBeneficiary, "", "allowance beneficiary address")
	accountAllowFlags.String(CfgAllowAmountChange, "0", "allowance change amount (in base units)")
	_ = viper.BindPFlags(accountAllowFlags)
	accountAllowFlags.AddFlagSet(cmdConsensus.TxFlags)
	accountAllowFlags.AddFlagSet(cmdFlags.AssumeYesFlag)

	accountWithdrawFlags.String(CfgWithdrawSource, "", "withdraw source address")
	_ = viper.BindPFlags(accountWithdrawFlags)
	accountWithdrawFlags.AddFlagSet(cmdConsensus.TxFlags)
	accountWithdrawFlags.AddFlagSet(amountFlags)
	accountWithdrawFlags.AddFlagSet(cmdFlags.AssumeYesFlag)
}
