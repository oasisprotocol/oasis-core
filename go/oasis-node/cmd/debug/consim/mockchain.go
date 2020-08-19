package consim

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/tendermint/tendermint/abci/types"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci"
	tendermint "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryApp "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry"
	stakingApp "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade"
)

type mockChainCfg struct {
	dataDir       string
	apps          []tendermint.Application
	genesisDoc    *genesis.Document
	tmChainID     string
	txAuthHandler tendermint.TransactionAuthHandler
	numVersions   uint64
	memDB         bool
}

type mockChain struct {
	cfg *mockChainCfg

	mux        *abci.MockABCIMux
	timeSource *simTimeSource

	tmChainID string

	now    time.Time
	hash   []byte
	height int64
}

func (m *mockChain) beginBlock() {
	m.height++
	m.now = m.now.Add(time.Second)

	m.mux.BeginBlock(types.RequestBeginBlock{
		Hash: m.hash,
		Header: tmproto.Header{
			ChainID: m.tmChainID,
			Height:  m.height,
			Time:    m.now,
		},
	})
}

func (m *mockChain) checkTx(tx []byte) uint32 {
	checkResp := m.mux.CheckTx(types.RequestCheckTx{
		Tx:   tx,
		Type: types.CheckTxType_New,
	})
	return checkResp.Code
}

func (m *mockChain) deliverTx(tx []byte) uint32 {
	deliverResp := m.mux.DeliverTx(types.RequestDeliverTx{
		Tx: tx,
	})
	if deliverResp.Code != types.CodeTypeOK {
		logger.Debug("deliverTx failure",
			"code", deliverResp.Code,
			"log", deliverResp.Log,
		)
	}
	return deliverResp.Code
}

func (m *mockChain) endBlock() {
	m.mux.EndBlock(types.RequestEndBlock{
		Height: m.height,
	})

	respCommit := m.mux.Commit()
	m.hash = respCommit.Data

	logger.Debug("block generated",
		"height", m.height,
		"hash", hex.EncodeToString(m.hash),
	)
}

func (m *mockChain) stateToGenesis(ctx context.Context) (*genesis.Document, error) {
	var err error

	doc := &genesis.Document{
		Height:  m.height,
		Time:    m.now,
		ChainID: m.cfg.genesisDoc.ChainID,
	}

	// Dump the application state.
	qHeight := m.height + 1 // Fuck if I know.
	for _, v := range m.cfg.apps {
		qfi := v.QueryFactory()
		switch qf := qfi.(type) {
		case *registryApp.QueryFactory:
			var query registryApp.Query
			if query, err = qf.QueryAt(ctx, qHeight); err != nil {
				return nil, fmt.Errorf("consim/mockchain: failed to create registry query: %w", err)
			}
			regGen, qErr := query.Genesis(ctx)
			if qErr != nil {
				return nil, fmt.Errorf("consim/mockchain: failed to query registry state: %w", qErr)
			}
			doc.Registry = *regGen
		case *stakingApp.QueryFactory:
			var query stakingApp.Query
			if query, err = qf.QueryAt(ctx, qHeight); err != nil {
				return nil, fmt.Errorf("consim/mockchain: failed to create staking query: %w", err)
			}
			stGen, qErr := query.Genesis(ctx)
			if qErr != nil {
				return nil, fmt.Errorf("consim/mockchain: failed to query staking state: %w", qErr)
			}
			doc.Staking = *stGen
		default:
			logger.Warn("unsupported query factory",
				"type", fmt.Sprintf("%T", qf),
			)
		}
	}

	// The timesource is "special".
	tGen, _ := m.timeSource.StateToGenesis(ctx, qHeight)
	doc.Beacon = *tGen

	return doc, nil
}

func (m *mockChain) close() {
	m.mux.MockClose()
}

func initMockChain(ctx context.Context, cfg *mockChainCfg) (*mockChain, error) {
	// Initialize an ephemeral local signer.
	localSigner, err := memory.NewSigner(rand.Reader)
	if err != nil {
		logger.Error("failed to initialize local signer",
			"err", err,
		)
		return nil, err
	}

	// Initialize the mock ABCI backend.
	muxCfg := &abci.ApplicationConfig{
		DataDir:                   cfg.dataDir,
		StorageBackend:            "badger",
		HaltEpochHeight:           math.MaxUint64,
		MinGasPrice:               0, // XXX: Should this be configurable?
		OwnTxSigner:               localSigner.Public(),
		MemoryOnlyStorage:         cfg.memDB,
		InitialHeight:             uint64(cfg.genesisDoc.Height),
		CheckpointerCheckInterval: 1 * time.Minute,
	}
	if cfg.numVersions > 0 {
		muxCfg.Pruning.Strategy = abci.PruneKeepN
		muxCfg.Pruning.NumKept = cfg.numVersions
	}
	mux, err := abci.NewMockMux(ctx, upgrade.NewDummyUpgradeManager(), muxCfg)
	if err != nil {
		logger.Error("failed to initialize mock mux",
			"err", err,
		)
		return nil, err
	}

	m := &mockChain{
		cfg:        cfg,
		mux:        mux,
		timeSource: newSimTimeSource(&cfg.genesisDoc.Beacon),
		tmChainID:  cfg.tmChainID,
		now:        cfg.genesisDoc.Time,
	}
	m.mux.MockSetEpochtime(m.timeSource)
	m.mux.MockSetTransactionAuthHandler(cfg.txAuthHandler)
	for _, v := range cfg.apps {
		_ = mux.MockRegisterApp(v)
	}

	// InitChain.
	muxInfo := m.mux.Info(types.RequestInfo{})
	rawGenesisDoc, _ := json.Marshal(cfg.genesisDoc)

	switch muxInfo.LastBlockHeight {
	case 0:
		_ = m.mux.InitChain(types.RequestInitChain{
			Time:            m.now,
			ChainId:         m.tmChainID,
			AppStateBytes:   rawGenesisDoc,
			ConsensusParams: nil,
			InitialHeight:   cfg.genesisDoc.Height,
		})
		respCommit := m.mux.Commit()
		m.hash = respCommit.Data
	default:
		m.height = muxInfo.LastBlockHeight
		m.hash = muxInfo.LastBlockAppHash
		m.now = m.now.Add(time.Duration(m.height) * time.Second)
		logger.Warn("existing ABCI state exists, skipping InitChain",
			"height", m.height,
			"hash", hex.EncodeToString(m.hash),
		)
	}

	return m, nil
}
