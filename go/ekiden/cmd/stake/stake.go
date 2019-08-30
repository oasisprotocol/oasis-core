// Package stake implements the stake token sub-commands.
package stake

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	cmdFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	grpcStaking "github.com/oasislabs/ekiden/go/grpc/staking"
	"github.com/oasislabs/ekiden/go/staking/api"
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

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, grpcStaking.StakingClient) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := grpcStaking.NewStakingClient(conn)
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

	doWithRetries(cmd, "query token name", func() error {
		resp, err := client.GetName(ctx, &grpcStaking.GetNameRequest{})
		if err != nil {
			return err
		}
		fmt.Printf("Name: \"%v\"\n", resp.GetName())
		return nil
	})

	doWithRetries(cmd, "query token symbol", func() error {
		resp, err := client.GetSymbol(ctx, &grpcStaking.GetSymbolRequest{})
		if err != nil {
			return err
		}
		fmt.Printf("Symbol: \"%v\"\n", resp.GetSymbol())
		return nil
	})

	doWithRetries(cmd, "query token total supply", func() error {
		resp, err := client.GetTotalSupply(ctx, &grpcStaking.GetTotalSupplyRequest{})
		if err != nil {
			return err
		}

		var q api.Quantity
		if err = q.UnmarshalBinary(resp.GetTotalSupply()); err != nil {
			return err
		}
		fmt.Printf("Total supply: %v\n", q)
		return nil
	})

	doWithRetries(cmd, "query token common pool", func() error {
		resp, err := client.GetCommonPool(ctx, &grpcStaking.GetCommonPoolRequest{})
		if err != nil {
			return err
		}

		var q api.Quantity
		if err = q.UnmarshalBinary(resp.GetCommonPool()); err != nil {
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
	thresholds := make(map[api.ThresholdKind]*api.Quantity)
	doWithRetries(cmd, "query staking threshold(s)", func() error {
		for _, k := range thresholdsToQuery {
			if thresholds[k] != nil {
				continue
			}

			resp, err := client.GetThreshold(ctx, &grpcStaking.GetThresholdRequest{
				ThresholdKind: grpcStaking.GetThresholdRequest_ThresholdKind(k),
			})
			if err != nil {
				return err
			}

			var q api.Quantity
			if err = q.UnmarshalBinary(resp.GetThreshold()); err != nil {
				return err
			}
			thresholds[k] = &q
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
		resp, err := client.GetAccounts(ctx, &grpcStaking.GetAccountsRequest{})
		if err != nil {
			return err
		}

		for _, rawID := range resp.GetIds() {
			var id signature.PublicKey
			if err = id.UnmarshalBinary(rawID); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return nil
	})

	for _, v := range ids {
		if !cmdFlags.Verbose() {
			fmt.Printf("%v\n", v)
			continue
		}

		ai := getAccountInfo(ctx, cmd, v, client)
		fmt.Printf("%v\n", string(json.Marshal(ai)))
	}
}

type accountInfo struct {
	ID              signature.PublicKey `codec:"id"`
	GeneralBalance  api.Quantity        `codec:"general_balance"`
	EscrowBalance   api.Quantity        `codec:"escrow_balance"`
	DebondStartTime uint64              `codec:"debond_start_time"`
	Nonce           uint64              `codec:"nonce"`
}

func getAccountInfo(ctx context.Context, cmd *cobra.Command, id signature.PublicKey, client grpcStaking.StakingClient) *accountInfo {
	var ai accountInfo
	doWithRetries(cmd, "query account "+id.String(), func() error {
		rawID, _ := id.MarshalBinary()
		resp, err := client.GetAccountInfo(ctx, &grpcStaking.GetAccountInfoRequest{
			Id: rawID,
		})
		if err != nil {
			return err
		}
		// TODO: Query allowances when that is possible (#2000).

		ai.ID = id
		if err = ai.GeneralBalance.UnmarshalBinary(resp.GetGeneralBalance()); err != nil {
			return err
		}
		if err = ai.EscrowBalance.UnmarshalBinary(resp.GetEscrowBalance()); err != nil {
			return err
		}
		ai.DebondStartTime = resp.DebondStartTime
		ai.Nonce = resp.Nonce

		return nil
	})

	return &ai
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
