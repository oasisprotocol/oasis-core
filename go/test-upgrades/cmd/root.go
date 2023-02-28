// Package cmd implements commands for oasis-net-runner executable.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-net-runner/fixtures"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

const (
	cfgConfigFile  = "config"
	cfgLogFmt      = "log.format"
	cfgLogLevel    = "log.level"
	cfgLogNoStdout = "log.no_stdout"

	cfgNetworkDatadir = "network_datadir"
	cfgSocket         = "sock"
	cfgRuntimeID      = "runtime_id"

	cfgOasisNodeBinary = "oasis_node"
)

var (
	rootCmd = &cobra.Command{
		Use:     "oasis-test-upgrades",
		Short:   "Oasis test upgrades",
		Version: version.SoftwareVersion,
		RunE:    runRoot,
	}

	upgradeCmd = &cobra.Command{
		Use:   "perform-upgrade",
		Short: "submit and vote for a network upgrade proposal",
		Run:   doPerformUpgrade,
	}

	resetStateCmd = &cobra.Command{
		Use:   "reset-state",
		Short: "resets consensus state on nodes",
		Run:   doResetConsensusState,
	}

	// TODO: test runtime coommand.

	rootFlags       = flag.NewFlagSet("", flag.ContinueOnError)
	resetStateFlags = flag.NewFlagSet("", flag.ContinueOnError)

	cfgFile         string
	networkDatadir  string
	socket          string
	oasisNodeBinary string
	runtimeID       common.Namespace
)

// RootCmd returns the root command's structure that will be executed, so that
// it can be used to alter the configuration and flags of the command.
func RootCmd() *cobra.Command {
	return rootCmd
}

// Execute spawns the main entry point after handing the config file.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func initEnv(cmd *cobra.Command) (*env.Env, error) {
	// Initialize the root dir.
	rootDir := env.GetRootDir()
	if err := rootDir.Init(cmd); err != nil {
		return nil, err
	}
	env := env.New(rootDir)

	var ok bool
	defer func() {
		if !ok {
			env.Cleanup()
		}
	}()

	var logFmt logging.Format
	if err := logFmt.Set(viper.GetString(cfgLogFmt)); err != nil {
		return nil, fmt.Errorf("root: failed to set log format: %w", err)
	}

	var logLevel logging.Level
	if err := logLevel.Set(viper.GetString(cfgLogLevel)); err != nil {
		return nil, fmt.Errorf("root: failed to set log level: %w", err)
	}

	// Initialize logging.
	logFile := filepath.Join(env.Dir(), "net-runner.log")
	w, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("root: failed to open log file: %w", err)
	}

	var logWriter io.Writer = w
	if !viper.GetBool(cfgLogNoStdout) {
		logWriter = io.MultiWriter(os.Stdout, w)
	}
	if err := logging.Initialize(logWriter, logFmt, logLevel, nil); err != nil {
		return nil, fmt.Errorf("root: failed to initialize logging: %w", err)
	}

	ok = true
	return env, nil
}

func runRoot(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true

	// Initialize the base dir, logging, etc.
	rootEnv, err := initEnv(cmd)
	if err != nil {
		return err
	}
	defer rootEnv.Cleanup()
	logger := logging.GetLogger("test-upgrades")

	logger.Info("network datadir", "datadir", networkDatadir)

	return nil
}

func loadEntities(path string) ([]*entity.Entity, []signature.Signer, error) {
	var entities []*entity.Entity
	var signers []signature.Signer

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		if match, _ := regexp.MatchString("entity-\\d", f.Name()); !match { // nolint: staticcheck
			continue
		}
		entityPath := filepath.Join(path, f.Name())
		// Load entity.
		factory, err := fileSigner.NewFactory(entityPath, signature.SignerEntity)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create entity file signer: %w (%s)", err, entityPath)
		}
		entity, sig, err := entity.Load(entityPath, factory)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load entity: %w (%s)", err, entityPath)
		}

		entities = append(entities, entity)
		signers = append(signers, sig)
	}

	return entities, signers, nil
}

func voteForProposal(ctx context.Context, entity *entity.Entity, signer signature.Signer, nodeCtrl *oasis.Controller, proposalID uint64) error {
	// Query entity nonce.
	account, err := nodeCtrl.Staking.Account(ctx, &api.OwnerQuery{Height: consensus.HeightLatest, Owner: staking.NewAddress(entity.ID)})
	if err != nil {
		return fmt.Errorf("failed to query entity account: %w", err)
	}

	// Ensure entity has some stake.
	if account.Escrow.Active.Balance.IsZero() {
		// Self-delegate some stake.
		tx := staking.NewAddEscrowTx(account.General.Nonce, &transaction.Fee{Gas: 2000}, &staking.Escrow{
			Account: staking.NewAddress(entity.ID),
			Amount:  *quantity.NewFromUint64(10),
		})
		sigTx, err := transaction.Sign(signer, tx)
		if err != nil {
			return fmt.Errorf("failed to sign add escrow transaction: %w", err)
		}
		if err = nodeCtrl.Consensus.SubmitTx(ctx, sigTx); err != nil {
			return fmt.Errorf("failed to submit add escrow transaction: %w", err)
		}
	}

	// Vote for proposal.
	vote := governance.ProposalVote{
		ID:   proposalID,
		Vote: governance.VoteYes,
	}
	tx := governance.NewCastVoteTx(account.General.Nonce+1, &transaction.Fee{Gas: 2000}, &vote)
	sigTx, err := transaction.Sign(signer, tx)
	if err != nil {
		return fmt.Errorf("failed to sign cast vote transaction: %w", err)
	}

	err = nodeCtrl.Consensus.SubmitTx(ctx, sigTx)
	switch {
	case errors.Is(err, governance.ErrNotEligible):
		// Entity is not eligible to vote.
	case err == nil:
		// Vote cast.
	default:
		// Unexpected error.
		return fmt.Errorf("failed to submit cast vote transaction: %w", err)
	}

	return nil
}

func doPerformUpgrade(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	// Initialize the base dir, logging, etc.
	rootEnv, err := initEnv(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "root: failed to initialize root environment: %s", err)
		os.Exit(1)
	}
	defer rootEnv.Cleanup()
	logger := logging.GetLogger("net-runner")

	if networkDatadir == "" {
		logger.Error("network datadir not set")
		os.Exit(1)
	}

	entities, signers, err := loadEntities(networkDatadir)
	if err != nil {
		logger.Error("failed to load network entities", "err", err)
		os.Exit(1)
	}

	if len(entities) == 0 {
		logger.Error("no network entities found")
		os.Exit(1)
	}

	logger.Info("loaded entities", "num", len(entities), "signers", len(signers))

	nodeCtrl, err := oasis.NewController(socket)
	if err != nil {
		logger.Error("failed to create node controller", "err", err)
		os.Exit(1)
	}

	logger.Info("waiting for client node to become ready")
	if err = nodeCtrl.WaitReady(ctx); err != nil {
		logger.Error("failed to wait for node to become ready", "err", err)
		os.Exit(1)
	}
	logger.Info("client node ready")

	chainCtx, err := nodeCtrl.Consensus.GetChainContext(ctx)
	if err != nil {
		logger.Error("failed to get chain context", "err", err)
		os.Exit(1)
	}
	signature.SetChainContext(chainCtx)

	epoch, err := nodeCtrl.Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		logger.Error("failed to get current epoch", "err", err)
		os.Exit(1)
	}

	// Load governance parameters.
	govParams, err := nodeCtrl.Governance.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		logger.Error("failed to load governance consensus parameters", "err", err)
		os.Exit(1)
	}

	// Submit an upgrade proposal.
	entity := entities[0]
	account, err := nodeCtrl.Staking.Account(ctx, &api.OwnerQuery{Height: consensus.HeightLatest, Owner: staking.NewAddress(entity.ID)})
	if err != nil {
		logger.Error("failed to query entity account", "err", err)
		os.Exit(1)
	}

	proposal := &governance.ProposalContent{Upgrade: &governance.UpgradeProposal{
		Descriptor: upgrade.Descriptor{
			Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
			Handler:   "oasis-test-upgrade-nonexistent",
			Target:    version.Versions, // TODO: This should be the next version.
			Epoch:     epoch + govParams.UpgradeMinEpochDiff + 1,
		},
	}}
	logger.Info("submitting upgrade proposal", "proposal", proposal)
	tx := governance.NewSubmitProposalTx(account.General.Nonce, &transaction.Fee{
		Amount: *quantity.NewFromUint64(0),
		Gas:    10_000,
	}, proposal)
	sigTx, err := transaction.Sign(signers[0], tx)
	if err != nil {
		logger.Error("failed signing submit proposal transaction", "err", err)
		os.Exit(1)
	}
	if err = nodeCtrl.Consensus.SubmitTx(ctx, sigTx); err != nil {
		logger.Error("failed submitting proposal transaction", "err", err)
		os.Exit(1)
	}
	// Ensure proposal created.
	aps, err := nodeCtrl.Governance.ActiveProposals(ctx, consensus.HeightLatest)
	if err != nil {
		logger.Error("failed querying active proposals", "err", err)
		os.Exit(1)
	}
	var activeProposal *governance.Proposal
	for i, p := range aps {
		if p.Content.Equals(proposal) {
			activeProposal = p
			break
		}
		if i == len(aps)-1 {
			logger.Error("submitted proposal not found")
			os.Exit(1)
		}
	}
	logger.Info("proposal active", "proposal", activeProposal)

	// Vote on the proposal.
	for i, entity := range entities {
		if err = voteForProposal(ctx, entity, signers[i], nodeCtrl, activeProposal.ID); err != nil {
			logger.Error("failed to vote on proposal", "err", err)
			os.Exit(1)
		}
	}

	// List votes for the proposal.
	votes, err := nodeCtrl.Governance.Votes(ctx, &governance.ProposalQuery{Height: consensus.HeightLatest, ProposalID: activeProposal.ID})
	if err != nil {
		logger.Error("failed to query proposal votes", "err", err)
		os.Exit(1)
	}
	logger.Info("proposal votes", "votes", votes)
}

func doResetConsensusState(cmd *cobra.Command, args []string) {
	// Initialize the base dir, logging, etc.
	rootEnv, err := initEnv(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "root: failed to initialize root environment: %s", err)
		os.Exit(1)
	}
	defer rootEnv.Cleanup()
	logger := logging.GetLogger("test-upgrades")

	if networkDatadir == "" {
		logger.Error("network datadir not set")
		os.Exit(1)
	}

	// Load all node data directories.
	var nodeDirs []string
	files, err := ioutil.ReadDir(networkDatadir)
	if err != nil {
		logger.Error("reading datadir", "err", err)
		os.Exit(1)
	}
	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		if match, _ := regexp.MatchString("(client|compute|validator|keymanager)-\\d", f.Name()); !match { // nolint: staticcheck
			continue
		}
		nodeDirs = append(nodeDirs, filepath.Join(networkDatadir, f.Name()))
	}

	// Reset state on all nodes.
	for _, nodeDir := range nodeDirs {
		logger.Info("resetting node state", "node", nodeDir, "binary", oasisNodeBinary)
		cmd := exec.Command(oasisNodeBinary, "unsafe-reset", "--datadir", nodeDir)
		if err = cmd.Run(); err != nil {
			logger.Error("resetting node state", "err", err, "out", cmd.Stdout, "stderr", cmd.Stderr)
			os.Exit(1)
		}
	}
}

func init() {
	cmdCommon.SetBasicVersionTemplate(rootCmd)

	logFmt := logging.FmtJSON
	logLevel := logging.LevelInfo

	rootFlags.StringVar(&cfgFile, cfgConfigFile, "", "config file")
	rootFlags.Var(&logFmt, cfgLogFmt, "log format")
	rootFlags.Var(&logLevel, cfgLogLevel, "log level")
	rootFlags.Bool(cfgLogNoStdout, false, "do not mutiplex logs to stdout")
	rootFlags.StringVar(&networkDatadir, cfgNetworkDatadir, "", "network datadir")
	rootFlags.StringVar(&socket, cfgSocket, "", "oasis-node internal UNIX socket address")
	_ = viper.BindPFlags(rootFlags)

	rootCmd.PersistentFlags().AddFlagSet(rootFlags)
	rootCmd.PersistentFlags().AddFlagSet(env.Flags)
	rootCmd.Flags().AddFlagSet(fixtures.DefaultFixtureFlags)
	rootCmd.Flags().AddFlagSet(fixtures.FileFixtureFlags)

	rootCmd.AddCommand(upgradeCmd)
	rootCmd.AddCommand(resetStateCmd)

	resetStateFlags.StringVar(&oasisNodeBinary, cfgOasisNodeBinary, "oasis-node", "path to the oasis-node binary")
	resetStateCmd.Flags().AddFlagSet(resetStateFlags)

	cobra.OnInitialize(func() {
		if cfgFile != "" {
			viper.SetConfigFile(cfgFile)
			if err := viper.ReadInConfig(); err != nil {
				cmdCommon.EarlyLogAndExit(err)
			}
		}

		viper.Set(cmdFlags.CfgDebugDontBlameOasis, true)
	})
}
