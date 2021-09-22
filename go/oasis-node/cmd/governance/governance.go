// Package governance implements the governance sub-commands.
package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	cmdContext "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/context"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

const (
	cfgProposalCancelUpgradeID   = "proposal.cancel_upgrade.id"
	cfgProposalUpgradeDescriptor = "proposal.upgrade.descriptor"

	cfgVote           = "vote"
	cfgVoteProposalID = "vote.proposal.id"

	cfgProposalID = "proposal.id"

	cfgIncludeClosed = "include_closed"
)

var (
	governanceFlags     = flag.NewFlagSet("", flag.ContinueOnError)
	submitProposalFlags = flag.NewFlagSet("", flag.ContinueOnError)
	castVoteFlags       = flag.NewFlagSet("", flag.ContinueOnError)
	proposalFlags       = flag.NewFlagSet("", flag.ContinueOnError)
	listProposalsFlags  = flag.NewFlagSet("", flag.ContinueOnError)

	governanceCmd = &cobra.Command{
		Use:   "governance",
		Short: "governance backend utilities",
	}

	submitProposalCmd = &cobra.Command{
		Use:   "gen_submit_proposal",
		Short: "generate a submit proposal transaction",
		Run:   doGenSubmitProposal,
	}

	castVoteCmd = &cobra.Command{
		Use:   "gen_cast_vote",
		Short: "generate a cast vote transaction",
		Run:   doGenCastVote,
	}

	proposalInfoCmd = &cobra.Command{
		Use:   "proposal_info",
		Short: "displays proposal info",
		Run:   doProposalInfo,
	}

	proposalVotesCmd = &cobra.Command{
		Use:   "proposal_votes",
		Short: "displays votes for a proposal",
		Run:   doProposalVotes,
	}

	listProposalsCmd = &cobra.Command{
		Use:   "list_proposals",
		Short: "lists active proposals",
		Run:   doListProposals,
	}

	logger = logging.GetLogger("cmd/governance")
)

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, governance.Backend) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := governance.NewGovernanceClient(conn)
	return conn, client
}

func doGenSubmitProposal(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	genesis := cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	var tx *transaction.Transaction
	switch {
	// Upgrade descriptor.
	case viper.GetString(cfgProposalUpgradeDescriptor) != "":
		descriptorBytes, err := ioutil.ReadFile(viper.GetString(cfgProposalUpgradeDescriptor))
		if err != nil {
			logger.Error("failed to read upgrade descriptor",
				"err", err,
			)
			os.Exit(1)
		}

		var desc upgrade.Descriptor
		if err = json.Unmarshal(descriptorBytes, &desc); err != nil {
			logger.Error("can't parse upgrade descriptor",
				"err", err,
			)
			os.Exit(1)
		}

		if err = desc.ValidateBasic(); err != nil {
			logger.Error("submitted upgrade descriptor is not valid",
				"err", err,
			)
			os.Exit(1)
		}

		tx = governance.NewSubmitProposalTx(nonce, fee, &governance.ProposalContent{
			Upgrade: &governance.UpgradeProposal{
				Descriptor: desc,
			},
		})
	case viper.GetUint64(cfgProposalCancelUpgradeID) != 0:
		tx = governance.NewSubmitProposalTx(nonce, fee, &governance.ProposalContent{
			CancelUpgrade: &governance.CancelUpgradeProposal{
				ProposalID: viper.GetUint64(cfgProposalCancelUpgradeID),
			},
		})
	default:
		logger.Error(fmt.Sprintf("missing required arguments: either '%v' or '%v' required",
			cfgProposalUpgradeDescriptor, cfgProposalCancelUpgradeID,
		))
		os.Exit(1)
	}

	cmdConsensus.SignAndSaveTx(cmdContext.GetCtxWithGenesisInfo(genesis), tx, nil)
}

func doGenCastVote(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	genesis := cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	id := viper.GetUint64(cfgVoteProposalID)
	if id == 0 {
		logger.Error("vote proposal ID required")
		os.Exit(1)
	}

	var vote governance.Vote
	if err := vote.UnmarshalText([]byte(viper.GetString(cfgVote))); err != nil {
		logger.Error("failed to parse vote",
			"err", err,
		)
		os.Exit(1)
	}

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := governance.NewCastVoteTx(nonce, fee, &governance.ProposalVote{
		ID:   id,
		Vote: vote,
	})
	cmdConsensus.SignAndSaveTx(cmdContext.GetCtxWithGenesisInfo(genesis), tx, nil)
}

func doProposalInfo(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	id := viper.GetUint64(cfgProposalID)
	if id == 0 {
		logger.Error("proposal ID required")
		os.Exit(1)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	ctx := context.Background()
	proposal, err := client.Proposal(ctx, &governance.ProposalQuery{Height: consensus.HeightLatest, ProposalID: id})
	if err != nil {
		logger.Error("error querying proposal", "err", err)
		os.Exit(1)
	}

	prettyProposal, err := cmdCommon.PrettyJSONMarshal(proposal)
	if err != nil {
		logger.Error("failed to get pretty JSON of proposal",
			"err", err,
		)
		os.Exit(1)
	}
	fmt.Println(string(prettyProposal))
}

func doProposalVotes(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	id := viper.GetUint64(cfgProposalID)
	if id == 0 {
		logger.Error("proposal ID required")
		os.Exit(1)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	ctx := context.Background()
	votes, err := client.Votes(ctx, &governance.ProposalQuery{Height: consensus.HeightLatest, ProposalID: id})
	if err != nil {
		logger.Error("error querying proposal votes", "err", err)
		os.Exit(1)
	}

	prettyVotes, err := cmdCommon.PrettyJSONMarshal(votes)
	if err != nil {
		logger.Error("failed to get pretty JSON of votes",
			"err", err,
		)
		os.Exit(1)
	}
	fmt.Println(string(prettyVotes))
}

func doListProposals(cmd *cobra.Command, args []string) {
	var err error
	if err = cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	ctx := context.Background()

	var proposals []*governance.Proposal
	switch viper.GetBool(cfgIncludeClosed) {
	case true:
		proposals, err = client.Proposals(ctx, consensus.HeightLatest)
	case false:
		proposals, err = client.ActiveProposals(ctx, consensus.HeightLatest)
	}
	if err != nil {
		logger.Error("error querying proposals", "err", err)
		os.Exit(1)
	}

	prettyProposals, err := cmdCommon.PrettyJSONMarshal(proposals)
	if err != nil {
		logger.Error("failed to get pretty JSON of proposals",
			"err", err,
		)
		os.Exit(1)
	}
	fmt.Println(string(prettyProposals))
}

// Register registers the governance sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	for _, c := range []*cobra.Command{
		submitProposalCmd,
		castVoteCmd,
		proposalInfoCmd,
		proposalVotesCmd,
		listProposalsCmd,
	} {
		governanceCmd.AddCommand(c)
	}

	submitProposalCmd.Flags().AddFlagSet(submitProposalFlags)
	castVoteCmd.Flags().AddFlagSet(castVoteFlags)

	proposalInfoCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)
	proposalInfoCmd.Flags().AddFlagSet(proposalFlags)

	proposalVotesCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)
	proposalVotesCmd.Flags().AddFlagSet(proposalFlags)

	listProposalsCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)
	listProposalsCmd.Flags().AddFlagSet(listProposalsFlags)

	parentCmd.AddCommand(governanceCmd)
}

func init() {
	governanceFlags.AddFlagSet(cmdSigner.Flags)
	governanceFlags.AddFlagSet(cmdSigner.CLIFlags)
	_ = viper.BindPFlags(governanceFlags)

	submitProposalFlags.String(cfgProposalUpgradeDescriptor, "", "Path to the proposal upgrade descriptor")
	submitProposalFlags.Uint64(cfgProposalCancelUpgradeID, 0, "Cancel upgrade proposal ID")
	_ = viper.BindPFlags(submitProposalFlags)
	submitProposalFlags.AddFlagSet(cmdConsensus.TxFlags)
	submitProposalFlags.AddFlagSet(cmdFlags.AssumeYesFlag)

	castVoteFlags.String(cfgVote, "", "Vote to be cast (yes, no, abstain)")
	castVoteFlags.Uint64(cfgVoteProposalID, 0, "Cast vote proposal ID")
	_ = viper.BindPFlags(castVoteFlags)
	castVoteFlags.AddFlagSet(cmdConsensus.TxFlags)
	castVoteFlags.AddFlagSet(cmdFlags.AssumeYesFlag)

	proposalFlags.Uint64(cfgProposalID, 0, "Proposal ID")
	_ = viper.BindPFlags(proposalFlags)

	listProposalsFlags.Bool(cfgIncludeClosed, false, "Include closed proposals.")
	_ = viper.BindPFlags(listProposalsFlags)
}
