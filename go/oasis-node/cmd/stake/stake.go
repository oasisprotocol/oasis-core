// Package stake implements the staking sub-commands.
package stake

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/staking/api/token"
)

// CfgPublicKey configures the public key.
const CfgPublicKey = "public_key"

var (
	stakeCmd = &cobra.Command{
		Use:   "stake",
		Short: "staking backend utilities",
	}

	infoCmd = &cobra.Command{
		Use:   "info",
		Short: "query the common staking info",
		Run:   doInfo,
	}

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "list accounts",
		Run:   doList,
	}

	pubkey2AddressCmd = &cobra.Command{
		Use:   "pubkey2address",
		Short: "convert a public key (e.g. entity's ID) to an account address",
		Run:   doPubkey2Address,
	}

	logger = logging.GetLogger("cmd/stake")

	infoFlags           = flag.NewFlagSet("", flag.ContinueOnError)
	listFlags           = flag.NewFlagSet("", flag.ContinueOnError)
	pubkey2AddressFlags = flag.NewFlagSet("", flag.ContinueOnError)
)

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, api.Backend) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := api.NewStakingClient(conn)
	return conn, client
}

func getTokenSymbol(ctx context.Context, client api.Backend) string {
	symbol, err := client.TokenSymbol(ctx)
	if err != nil {
		logger.Error("failed to query token's symbol",
			"err", err,
		)
		os.Exit(1)
	}
	return symbol
}

func getTokenValueExponent(ctx context.Context, client api.Backend) uint8 {
	exp, err := client.TokenValueExponent(ctx)
	if err != nil {
		logger.Error("failed to query token's value exponent",
			"err", err,
		)
		os.Exit(1)
	}
	return exp
}

func getAccount(ctx context.Context, addr api.Address, height int64, client api.Backend) *api.Account {
	acct, err := client.Account(ctx, &api.OwnerQuery{Owner: addr, Height: height})
	if err != nil {
		logger.Error("failed to query account",
			"address", addr,
			"err", err,
		)
		os.Exit(1)
	}
	return acct
}

func getDelegationInfosFor(
	ctx context.Context,
	addr api.Address,
	height int64,
	client api.Backend,
) map[api.Address]*api.DelegationInfo {
	delInfos, err := client.DelegationInfosFor(ctx, &api.OwnerQuery{Owner: addr, Height: height})
	if err != nil {
		logger.Error("failed to query (outgoing) delegation infos for account",
			"address", addr,
			"err", err,
		)
		os.Exit(1)
	}
	return delInfos
}

func getDelegationsTo(
	ctx context.Context,
	addr api.Address,
	height int64,
	client api.Backend,
) map[api.Address]*api.Delegation {
	delegations, err := client.DelegationsTo(ctx, &api.OwnerQuery{Owner: addr, Height: height})
	if err != nil {
		logger.Error("failed to query (incoming) delegations to account",
			"address", addr,
			"err", err,
		)
		os.Exit(1)
	}
	return delegations
}

func getDebondingDelegationInfosFor(
	ctx context.Context,
	addr api.Address,
	height int64,
	client api.Backend,
) map[api.Address][]*api.DebondingDelegationInfo {
	delInfoLists, err := client.DebondingDelegationInfosFor(ctx, &api.OwnerQuery{Owner: addr, Height: height})
	if err != nil {
		logger.Error("failed to query (outgoing) debonding delegation infos for account",
			"address", addr,
			"err", err,
		)
		os.Exit(1)
	}
	return delInfoLists
}

func getDebondingDelegationsTo(
	ctx context.Context,
	addr api.Address,
	height int64,
	client api.Backend,
) map[api.Address][]*api.DebondingDelegation {
	delegations, err := client.DebondingDelegationsTo(ctx, &api.OwnerQuery{Owner: addr, Height: height})
	if err != nil {
		logger.Error("failed to query (incoming) debonding delegations to account",
			"address", addr,
			"err", err,
		)
		os.Exit(1)
	}
	return delegations
}

func doInfo(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	height := consensus.HeightLatest

	ctx := context.Background()
	symbol := getTokenSymbol(ctx, client)
	fmt.Printf("Token's ticker symbol: %s\n", symbol)
	exp := getTokenValueExponent(ctx, client)
	fmt.Printf("Token's value base-10 exponent: %d\n", exp)
	ctx = context.WithValue(ctx, prettyprint.ContextKeyTokenSymbol, symbol)
	ctx = context.WithValue(ctx, prettyprint.ContextKeyTokenValueExponent, exp)

	totalSupply, err := client.TotalSupply(ctx, height)
	if err != nil {
		logger.Error("failed to query total supply",
			"err", err,
		)
		os.Exit(1)
	}
	fmt.Print("Total supply: ")
	token.PrettyPrintAmount(ctx, *totalSupply, os.Stdout)
	fmt.Println()

	commonPool, err := client.CommonPool(ctx, height)
	if err != nil {
		logger.Error("failed to query common pool",
			"err", err,
		)
		os.Exit(1)
	}
	fmt.Print("Common pool: ")
	token.PrettyPrintAmount(ctx, *commonPool, os.Stdout)
	fmt.Println()

	lastBlockFees, err := client.LastBlockFees(ctx, height)
	if err != nil {
		logger.Error("failed to query last block fees",
			"err", err,
		)
		os.Exit(1)
	}
	fmt.Print("Last block fees: ")
	token.PrettyPrintAmount(ctx, *lastBlockFees, os.Stdout)
	fmt.Println()

	governanceDeposits, err := client.GovernanceDeposits(ctx, height)
	if err != nil {
		logger.Error("failed to query governance deposits",
			"err", err,
		)
		os.Exit(1)
	}
	fmt.Print("Governance deposits: ")
	token.PrettyPrintAmount(ctx, *governanceDeposits, os.Stdout)
	fmt.Println()

	thresholdsToQuery := []api.ThresholdKind{
		api.KindEntity,
		api.KindNodeValidator,
		api.KindNodeCompute,
		api.KindNodeStorage,
		api.KindNodeKeyManager,
		api.KindRuntimeCompute,
		api.KindRuntimeKeyManager,
	}
	for _, kind := range thresholdsToQuery {
		thres, err := client.Threshold(ctx, &api.ThresholdQuery{Kind: kind, Height: height})
		if err != nil {
			if errors.Is(err, api.ErrInvalidThreshold) {
				logger.Warn(fmt.Sprintf("invalid staking threshold kind: %s", kind))
				continue
			}
			logger.Error("failed to query staking threshold",
				"err", err,
			)
			os.Exit(1)
		}
		fmt.Printf("Staking threshold (%s): ", kind)
		token.PrettyPrintAmount(ctx, *thres, os.Stdout)
		fmt.Println()
	}
}

func doList(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	height := consensus.HeightLatest

	ctx := context.Background()

	addresses, err := client.Addresses(ctx, height)
	if err != nil {
		logger.Error("failed to query addresses",
			"err", err,
		)
		os.Exit(1)
	}

	for _, addr := range addresses {
		var acctString string
		switch cmdFlags.Verbose() {
		case true:
			// NOTE: getAccount()'s output doesn't contain an account's address,
			// so we need to add it manually.
			acctWithAddr := make(map[api.Address]*api.Account)
			acctWithAddr[addr] = getAccount(ctx, addr, height, client)
			prettyAcct, err := cmdCommon.PrettyJSONMarshal(acctWithAddr)
			if err != nil {
				logger.Error("failed to get pretty JSON of account",
					"err", err,
					"address", addr,
				)
				acctString = fmt.Sprintf("[invalid pretty JSON for account %s]", addr)
			} else {
				acctString = string(prettyAcct)
			}
		default:
			acctString = addr.String()
		}

		fmt.Println(acctString)
	}
}

func doPubkey2Address(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	pkString := viper.GetString(CfgPublicKey)
	if pkString == "" {
		logger.Error("cannot convert an empty public key")
		os.Exit(1)
	}

	var pk signature.PublicKey
	if err := pk.UnmarshalText([]byte(pkString)); err != nil {
		logger.Error("failed to parse public key",
			"err", err,
		)
		os.Exit(1)
	}

	fmt.Printf("%v\n", api.NewAddress(pk))
}

// Register registers the stake sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	registerAccountCmd()
	for _, v := range []*cobra.Command{
		infoCmd,
		listCmd,
		pubkey2AddressCmd,
		accountCmd,
	} {
		stakeCmd.AddCommand(v)
	}

	infoCmd.Flags().AddFlagSet(infoFlags)
	listCmd.Flags().AddFlagSet(listFlags)
	pubkey2AddressCmd.Flags().AddFlagSet(pubkey2AddressFlags)

	parentCmd.AddCommand(stakeCmd)
}

func init() {
	infoFlags.AddFlagSet(cmdGrpc.ClientFlags)

	listFlags.AddFlagSet(cmdFlags.VerboseFlags)
	listFlags.AddFlagSet(cmdGrpc.ClientFlags)

	pubkey2AddressFlags.String(CfgPublicKey, "", "Public key (Base64-encoded)")
	_ = viper.BindPFlags(pubkey2AddressFlags)
}
