package abci

import (
	"encoding/base64"
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
)

func (mux *abciMux) decodeTx(ctx *api.Context, rawTx []byte) (*transaction.Transaction, *transaction.SignedTransaction, error) {
	params := mux.state.ConsensusParameters()
	if params == nil {
		ctx.Logger().Debug("decodeTx: state not yet initialized")
		return nil, nil, consensus.ErrNoCommittedBlocks
	}

	if params.MaxTxSize > 0 && uint64(len(rawTx)) > params.MaxTxSize {
		// This deliberately avoids logging the rawTx since spamming the
		// logs is also bad.
		ctx.Logger().Debug("received oversized transaction",
			"tx_size", len(rawTx),
		)
		return nil, nil, consensus.ErrOversizedTx
	}

	// Unmarshal envelope and verify transaction.
	var sigTx transaction.SignedTransaction
	if err := cbor.Unmarshal(rawTx, &sigTx); err != nil {
		ctx.Logger().Debug("failed to unmarshal signed transaction",
			"tx", base64.StdEncoding.EncodeToString(rawTx),
		)
		return nil, nil, err
	}
	var tx transaction.Transaction
	if err := sigTx.Open(&tx); err != nil {
		ctx.Logger().Debug("failed to verify transaction signature",
			"tx", base64.StdEncoding.EncodeToString(rawTx),
		)
		return nil, nil, err
	}
	if err := tx.SanityCheck(); err != nil {
		ctx.Logger().Debug("bad transaction",
			"tx", base64.StdEncoding.EncodeToString(rawTx),
		)
		return nil, nil, err
	}

	return &tx, &sigTx, nil
}

func (mux *abciMux) processTx(ctx *api.Context, tx *transaction.Transaction, txSize int) error {
	// Lookup method handler.
	app := mux.appsByMethod[tx.Method]
	if app == nil {
		ctx.Logger().Debug("unknown method",
			"tx", tx,
			"method", tx.Method,
		)
		return fmt.Errorf("mux: unknown method: %s", tx.Method)
	}

	// Pass the transaction through the fee handler if configured.
	//
	// Ignore fees for critical protocol methods to ensure they are processed in a block. Note that
	// this relies on method handlers to prevent DoS.
	if txAuthHandler := mux.state.txAuthHandler; txAuthHandler != nil && !tx.Method.IsCritical() {
		if err := txAuthHandler.AuthenticateTx(ctx, tx); err != nil {
			ctx.Logger().Debug("failed to authenticate transaction (pre-execute)",
				"tx", tx,
				"tx_signer", ctx.TxSigner(),
				"method", tx.Method,
				"err", err,
			)
			return err
		}
	}

	// Charge gas based on the size of the transaction.
	params := mux.state.ConsensusParameters()
	if err := ctx.Gas().UseGas(txSize, consensusGenesis.GasOpTxByte, params.GasCosts); err != nil {
		return err
	}

	// Route to correct handler.
	ctx.Logger().Debug("dispatching",
		"app", app.Name(),
		"tx", tx,
	)

	if err := app.ExecuteTx(ctx, tx); err != nil {
		return err
	}

	//  Pass the transaction through the PostExecuteTx handler if configured.
	if txAuthHandler := mux.state.txAuthHandler; txAuthHandler != nil {
		if err := txAuthHandler.PostExecuteTx(ctx, tx); err != nil {
			ctx.Logger().Debug("failed to authenticate transaction (post-execute)",
				"tx", tx,
				"tx_signer", ctx.TxSigner(),
				"method", tx.Method,
				"err", err,
			)
			return err
		}
	}

	return nil
}

func (mux *abciMux) executeTx(ctx *api.Context, rawTx []byte) error {
	tx, sigTx, err := mux.decodeTx(ctx, rawTx)
	if err != nil {
		return err
	}

	// Set authenticated transaction signer.
	ctx.SetTxSigner(sigTx.Signature.PublicKey)

	// If we are in CheckTx mode and there is a pending upgrade in this block, make sure to reject
	// any transactions before processing as they may potentially query incompatible state.
	if upgrader := mux.state.Upgrader(); upgrader != nil && ctx.IsCheckOnly() {
		hasUpgrade, err := upgrader.HasPendingUpgradeAt(ctx, ctx.BlockHeight()+1)
		if err != nil {
			return fmt.Errorf("failed to check for pending upgrades: %w", err)
		}
		if hasUpgrade {
			return transaction.ErrUpgradePending
		}
	}

	return mux.processTx(ctx, tx, len(rawTx))
}

func (mux *abciMux) EstimateGas(caller signature.PublicKey, tx *transaction.Transaction) (transaction.Gas, error) {
	if tx == nil {
		return 0, consensus.ErrInvalidArgument
	}

	// Certain modules, in particular the beacon require InitChain or BeginBlock
	// to have completed before initialization is complete.
	if mux.state.BlockHeight() == 0 {
		return 0, consensus.ErrNoCommittedBlocks
	}

	// As opposed to other transaction dispatch entry points (CheckTx/DeliverTx), this method can
	// be called in parallel to the consensus layer and to other invocations.
	//
	// For simulation mode, time will be filled in by NewContext from last block time.
	ctx := mux.state.NewContext(api.ContextSimulateTx, time.Time{})
	defer ctx.Close()

	// Modify transaction to include maximum possible gas in order to estimate the upper limit on
	// the serialized transaction size. For amount, use a reasonable amount (in theory the actual
	// amount could be bigger depending on the gas price).
	tx.Fee = &transaction.Fee{
		Gas: transaction.Gas(math.MaxUint64),
	}
	_ = tx.Fee.Amount.FromUint64(math.MaxUint64)

	ctx.SetTxSigner(caller)
	mockSignedTx := transaction.SignedTransaction{
		Signed: signature.Signed{
			Blob: cbor.Marshal(tx),
			// Signature is fixed-size, so we can leave it as default.
		},
	}
	txSize := len(cbor.Marshal(mockSignedTx))

	// Ignore any errors that occurred during simulation as we only need to estimate gas even if the
	// transaction seems like it will fail.
	_ = mux.processTx(ctx, tx, txSize)

	return ctx.Gas().GasUsed(), nil
}
