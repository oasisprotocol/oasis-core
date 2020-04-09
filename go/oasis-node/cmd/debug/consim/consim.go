// Package consim implements the mock consensus simulator.
package consim

import (
	"context"
	"crypto"
	"encoding/hex"
	"fmt"
	"math/rand"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/tendermint/tendermint/abci/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/crypto/drbg"
	"github.com/oasislabs/oasis-core/go/common/crypto/mathrand"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	registryApp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry"
	stakingApp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking"
	genesisFile "github.com/oasislabs/oasis-core/go/genesis/file"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
)

const (
	cfgNumKept      = "consim.num_kept"
	cfgMemDB        = "consim.memdb"
	cfgWorkload     = "consim.workload"
	cfgWorkloadSeed = "consim.workload.seed"
)

var (
	logger = logging.GetLogger("cmd/consim")

	flagsConsim = flag.NewFlagSet("", flag.ContinueOnError)

	conSimCmd = &cobra.Command{
		Use:   "consim",
		Short: "mock consensus simulator",
		RunE:  doRun,
	}
)

func doRun(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true

	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		return fmt.Errorf("datadir is mandatory")
	}

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	// Load the genesis document.
	genesisProvider, err := genesisFile.DefaultFileProvider()
	if err != nil {
		logger.Error("failed to initialize genesis provider",
			"err", err,
		)
		return err
	}
	genesisDoc, err := genesisProvider.GetGenesisDocument()
	if err != nil {
		logger.Error("failed to get genesis document",
			"err", err,
		)
		return err
	}
	genesisDoc.SetChainContext()
	tmChainID := genesisDoc.ChainContext()[:tmtypes.MaxChainIDLen]

	// Initialize the DRBG and workload.
	rngSrc, err := drbg.New(crypto.SHA512, []byte(viper.GetString(cfgWorkloadSeed)), nil, []byte("consim workload generator"))
	if err != nil {
		logger.Error("failed to initialize DRBG",
			"err", err,
		)
		return err
	}

	workload, err := newWorkload(rand.New(mathrand.New(rngSrc)))
	if err != nil {
		logger.Error("failed to create workload",
			"err", err,
		)
		return err
	}
	defer workload.Cleanup()

	if err = workload.Init(genesisDoc); err != nil {
		logger.Error("failed to initialize workload",
			"err", err,
		)
		return err
	}

	// Initialize the mock chain backend.
	txAuthApp := stakingApp.New()
	cfg := &mockChainCfg{
		dataDir: dataDir,
		apps: []abci.Application{
			registryApp.New(),
			txAuthApp, // This is the staking app.
		},
		genesisDoc:    genesisDoc,
		tmChainID:     tmChainID,
		txAuthHandler: txAuthApp.(abci.TransactionAuthHandler),
		numVersions:   viper.GetInt64(cfgNumKept),
		memDB:         viper.GetBool(cfgMemDB),
	}
	mockChain, err := initMockChain(ctx, cfg)
	if err != nil {
		logger.Error("failed to initialize mock chain backend",
			"err", err,
		)
		return err
	}
	defer mockChain.close()
	chainState, err := mockChain.stateToGenesis(ctx)
	if err != nil {
		logger.Error("failed to obtain chain state",
			"err", err,
		)
		return err
	}

	// Start the workload.
	cancelCh, errCh := make(chan struct{}), make(chan error)
	defer close(cancelCh)
	txVecCh, err := workload.Start(chainState, cancelCh, errCh)
	if err != nil {
		logger.Error("failed to start workload",
			"err", err,
		)
		return err
	}

	var checkedTxes, deliveredTxes, numBlocks uint64
	start := time.Now()

	// Emulate the tendermint block generation loop.
txLoop:
	for {
		var (
			txVec []BlockTx
			ok    bool
		)
		select {
		case err = <-errCh:
			logger.Error("workload error",
				"err", err,
			)
			return err
		case txVec, ok = <-txVecCh:
			if !ok {
				break txLoop
			}
		}

		mockChain.beginBlock()

		// CheckTx all the pending transactions for this block.
		var toDeliver []BlockTx
		for _, v := range txVec {
			txCode := mockChain.checkTx(v.Tx)
			if txCode != v.Code {
				logger.Error("CheckTx response code mismatch",
					"tx", hex.EncodeToString(v.Tx),
					"code", txCode,
				)
				return fmt.Errorf("consim: CheckTx response code mismatch")
			} else if v.Code == types.CodeTypeOK {
				toDeliver = append(toDeliver, v)
			}

			checkedTxes++
		}

		// DeliverTx all the pending transactions for this block.
		for _, v := range toDeliver {
			txCode := mockChain.deliverTx(v.Tx)
			if txCode != types.CodeTypeOK {
				logger.Error("DeliverTx failed",
					"tx", hex.EncodeToString(v.Tx),
					"code", txCode,
				)
				return fmt.Errorf("consim: DeliverTx response code mismatch")
			}

			deliveredTxes++
		}

		mockChain.endBlock()

		numBlocks++
	}

	elapsed := time.Since(start)
	logger.Info("transaction processing complete",
		"time", elapsed,
		"check_tx_per_sec", float64(checkedTxes)/elapsed.Seconds(),
		"deliver_tx_per_sec", float64(deliveredTxes)/elapsed.Seconds(),
		"blocks_per_sec", float64(numBlocks)/elapsed.Seconds(),
	)

	// Dump the final state to a JSON document.
	finalGenesis, err := mockChain.stateToGenesis(ctx)
	if err != nil {
		logger.Error("failed to obtain state dump",
			"err", err,
		)
		return err
	}

	if err = workload.Finalize(finalGenesis); err != nil {
		logger.Error("failed to finalize workload",
			"err", err,
		)
		return err
	}

	if err = finalGenesis.WriteFileJSON(filepath.Join(dataDir, "dump.json")); err != nil {
		logger.Error("failed to write state dump",
			"err", err,
		)
		return err
	}

	return nil
}

// Register registers the consim sub-command.
func Register(parentCmd *cobra.Command) {
	conSimCmd.Flags().AddFlagSet(cmdFlags.GenesisFileFlags)
	conSimCmd.Flags().AddFlagSet(flagsConsim)
	conSimCmd.Flags().AddFlagSet(fileTxsFlag)
	conSimCmd.Flags().AddFlagSet(xferFlags)
	parentCmd.AddCommand(conSimCmd)
}

func init() {
	flagsConsim.Int64(cfgNumKept, 0, "number of versions kept (0 = all)")
	flagsConsim.Bool(cfgMemDB, false, "use memory to store state")
	flagsConsim.String(cfgWorkload, fileWorkloadName, "workload to execute")
	flagsConsim.String(cfgWorkloadSeed, "seeeeeeeeeeeeeeeeeeeeeeeeeeeeeed", "DRBG seed for workloads")
	_ = viper.BindPFlags(flagsConsim)
}
