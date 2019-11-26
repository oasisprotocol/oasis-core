// Package stake implements the stake token sub-commands.
package stake

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasislabs/oasis-core/go/staking/api"
)

var (
	stakeCmd = &cobra.Command{
		Use:   "stake",
		Short: "stake token backend utilities",
	}

	infoCmd = &cobra.Command{
		Use:   "info",
		Short: "query the common token info",
		Run:   doInfo,
	}

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "list accounts",
		Run:   doList,
	}

	logger = logging.GetLogger("cmd/stake")

	infoFlags = flag.NewFlagSet("", flag.ContinueOnError)
	listFlags = flag.NewFlagSet("", flag.ContinueOnError)
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

func doWithRetries(cmd *cobra.Command, descr string, fn func() error) {
	nrRetries := cmdFlags.Retries()
	for i := 0; i <= nrRetries; i++ {
		err := fn()
		switch err {
		case nil:
			return
		default:
			logger.Warn("failed to "+descr,
				"err", err,
				"attempt", i+1,
			)
		}
	}

	// Retries exhausted, just bail.
	os.Exit(1)
}

func doInfo(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	ctx := context.Background()

	doWithRetries(cmd, "query token total supply", func() error {
		q, err := client.TotalSupply(ctx, consensus.HeightLatest)
		if err != nil {
			return err
		}

		fmt.Printf("Total supply: %v\n", q)
		return nil
	})

	doWithRetries(cmd, "query token common pool", func() error {
		q, err := client.CommonPool(ctx, consensus.HeightLatest)
		if err != nil {
			return err
		}

		fmt.Printf("Common pool: %v\n", q)
		return nil
	})

	thresholdsToQuery := []api.ThresholdKind{
		api.KindEntity,
		api.KindValidator,
		api.KindCompute,
		api.KindStorage,
	}
	thresholds := make(map[api.ThresholdKind]*quantity.Quantity)
	doWithRetries(cmd, "query staking threshold(s)", func() error {
		for _, k := range thresholdsToQuery {
			if thresholds[k] != nil {
				continue
			}

			q, err := client.Threshold(ctx, &api.ThresholdQuery{Kind: k, Height: consensus.HeightLatest})
			if err != nil {
				return err
			}
			thresholds[k] = q
		}
		return nil
	})
	for _, k := range thresholdsToQuery {
		fmt.Printf("Staking threshold (%s): %v\n", k, thresholds[k])
	}
}

func doList(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	ctx := context.Background()

	var ids []signature.PublicKey
	doWithRetries(cmd, "query accounts", func() error {
		var err error
		ids, err = client.Accounts(ctx, consensus.HeightLatest)
		return err
	})

	for _, v := range ids {
		if !cmdFlags.Verbose() {
			fmt.Printf("%v\n", v)
			continue
		}

		ai := getAccountInfo(ctx, cmd, v, client)
		b, _ := json.Marshal(ai)
		fmt.Printf("%v\n", string(b))
	}
}

func getAccountInfo(ctx context.Context, cmd *cobra.Command, id signature.PublicKey, client api.Backend) *api.Account {
	var acct *api.Account
	doWithRetries(cmd, "query account "+id.String(), func() error {
		var err error
		acct, err = client.AccountInfo(ctx, &api.OwnerQuery{Owner: id, Height: consensus.HeightLatest})
		return err
	})

	return acct
}

// Register registers the stake sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	registerAccountCmd()
	for _, v := range []*cobra.Command{
		infoCmd,
		listCmd,
		accountCmd,
	} {
		stakeCmd.AddCommand(v)
	}

	infoCmd.Flags().AddFlagSet(infoFlags)
	listCmd.Flags().AddFlagSet(listFlags)

	parentCmd.AddCommand(stakeCmd)
}

func init() {
	infoFlags.AddFlagSet(cmdFlags.RetriesFlags)
	infoFlags.AddFlagSet(cmdGrpc.ClientFlags)

	listFlags.AddFlagSet(cmdFlags.RetriesFlags)
	listFlags.AddFlagSet(cmdFlags.VerboseFlags)
	listFlags.AddFlagSet(cmdGrpc.ClientFlags)
}
