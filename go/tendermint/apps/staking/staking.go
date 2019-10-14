// Package staking implements the staking application.
package staking

import (
	"bytes"
	"encoding/hex"
	"sort"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/tendermint/api"
)

var (
	_ abci.Application = (*stakingApplication)(nil)
)

type stakingApplication struct {
	logger *logging.Logger

	state *abci.ApplicationState

	debugGenesisState *staking.Genesis
}

func (app *stakingApplication) Name() string {
	return AppName
}

func (app *stakingApplication) TransactionTag() byte {
	return TransactionTag
}

func (app *stakingApplication) Blessed() bool {
	return false
}

func (app *stakingApplication) Dependencies() []string {
	return nil
}

func (app *stakingApplication) GetState(height int64) (interface{}, error) {
	return newImmutableState(app.state, height)
}

func (app *stakingApplication) OnRegister(state *abci.ApplicationState, queryRouter abci.QueryRouter) {
	app.state = state

	// Register the query handlers.
	queryRouter.AddRoute(QueryTotalSupply, nil, app.queryTotalSupply)
	queryRouter.AddRoute(QueryCommonPool, nil, app.queryCommonPool)
	queryRouter.AddRoute(QueryThresholds, nil, app.queryThresholds)
	queryRouter.AddRoute(QueryAccounts, nil, app.queryAccounts)
	queryRouter.AddRoute(QueryAccountInfo, api.QueryGetByIDRequest{}, app.queryAccountInfo)
	queryRouter.AddRoute(QueryDebondingInterval, nil, app.queryDebondingInterval)
	queryRouter.AddRoute(QueryGenesis, nil, app.queryGenesis)
}

func (app *stakingApplication) OnCleanup() {
}

func (app *stakingApplication) SetOption(types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *stakingApplication) CheckTx(ctx *abci.Context, tx []byte) error {
	request := &Tx{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("CheckTx: failed to unmarshal",
			"err", err,
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "staking/tendermint: failed to unmarshal tx")
	}

	return app.executeTx(ctx, app.state.CheckTxTree(), request)
}

func (app *stakingApplication) ForeignCheckTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

type thresholdUpdate struct {
	k staking.ThresholdKind
	v staking.Quantity
}

type thresholdUpdates []thresholdUpdate

func (u thresholdUpdates) Len() int           { return len(u) }
func (u thresholdUpdates) Swap(i, j int)      { u[i], u[j] = u[j], u[i] }
func (u thresholdUpdates) Less(i, j int) bool { return u[i].k < u[j].k }

type ledgerUpdate struct {
	id      signature.PublicKey
	account *ledgerEntry
}

type ledgerUpdates []ledgerUpdate

func (u ledgerUpdates) Len() int           { return len(u) }
func (u ledgerUpdates) Swap(i, j int)      { u[i], u[j] = u[j], u[i] }
func (u ledgerUpdates) Less(i, j int) bool { return bytes.Compare(u[i].id[:], u[j].id[:]) < 0 }

func (app *stakingApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesis.Document) error {
	st := &doc.Staking
	if app.debugGenesisState != nil {
		if len(st.Ledger) > 0 {
			app.logger.Error("InitChain: debug genesis state and actual genesis state provided")
			return errors.New("staking/tendermint: multiple genesis states specified")
		}
		st = app.debugGenesisState
	}

	var (
		state       = NewMutableState(app.state.DeliverTxTree())
		totalSupply staking.Quantity
	)

	state.setDebondingInterval(st.DebondingInterval)
	state.setAcceptableTransferPeers(st.AcceptableTransferPeers)

	if st.Thresholds != nil {
		var ups thresholdUpdates
		for k, v := range st.Thresholds {
			if !v.IsValid() {
				app.logger.Error("InitChain: invalid threshold",
					"threshold", k,
					"quantity", v,
				)
				return errors.New("staking/tendermint: invalid genesis threshold")
			}
			ups = append(ups, thresholdUpdate{k, v})
		}

		// Make sure that we apply threshold updates in a canonical order.
		sort.Stable(ups)
		for _, u := range ups {
			state.setThreshold(u.k, &u.v)
		}
	}

	if !st.CommonPool.IsValid() {
		return errors.New("staking/tendermint: invalid genesis state CommonPool")
	}
	if err := totalSupply.Add(&st.CommonPool); err != nil {
		app.logger.Error("InitChain: failed to add common pool",
			"err", err,
		)
		return errors.Wrap(err, "staking/tendermint: failed to add common pool")
	}

	var ups ledgerUpdates
	for k, v := range st.Ledger {
		var id signature.PublicKey
		_ = id.UnmarshalBinary(k[:])

		if !v.GeneralBalance.IsValid() {
			app.logger.Error("InitChain: invalid genesis general balance",
				"id", id,
				"general_balance", v.GeneralBalance,
			)
			return errors.New("staking/tendermint: invalid genesis general balance")
		}
		if !v.EscrowBalance.IsValid() {
			app.logger.Error("InitChain: invalid genesis escrow balance",
				"id", id,
				"escrow_balance", v.EscrowBalance,
			)
			return errors.New("staking/tendermint: invalid genesis escrow balance")
		}

		account := &ledgerEntry{
			GeneralBalance:  v.GeneralBalance,
			EscrowBalance:   v.EscrowBalance,
			DebondStartTime: v.DebondStartTime,
			Nonce:           v.Nonce,
		}
		ups = append(ups, ledgerUpdate{id, account})
		if err := totalSupply.Add(&account.GeneralBalance); err != nil {
			app.logger.Error("InitChain: failed to add general balance",
				"err", err,
			)
			return errors.Wrap(err, "staking/tendermint: failed to add general balance")
		}
		if err := totalSupply.Add(&account.EscrowBalance); err != nil {
			app.logger.Error("InitChain: failed to add escrow balance",
				"err", err,
			)
			return errors.Wrap(err, "staking/tendermint: failed to add escrow balance")
		}
	}

	// Make sure that we apply ledger updates in a canonical order.
	sort.Stable(ups)
	for _, u := range ups {
		state.setAccount(u.id, u.account)
	}

	if totalSupply.Cmp(&st.TotalSupply) != 0 {
		app.logger.Error("InitChain: total supply mismatch",
			"expected", st.TotalSupply,
			"actual", st.TotalSupply,
		)
	}

	state.setCommonPool(&st.CommonPool)
	state.setTotalSupply(&totalSupply)

	app.logger.Debug("InitChain: allocations complete",
		"debonding_interval", st.DebondingInterval,
		"common_pool", st.CommonPool,
		"total_supply", totalSupply,
	)

	return nil
}

func (app *stakingApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	return nil
}

func (app *stakingApplication) DeliverTx(ctx *abci.Context, tx []byte) error {
	request := &Tx{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("DeliverTx: failed to unmarshal",
			"err", err,
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "staking/tendermint: failed to unmarshal tx")
	}

	return app.executeTx(ctx, app.state.DeliverTxTree(), request)
}

func (app *stakingApplication) ForeignDeliverTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *stakingApplication) EndBlock(request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *stakingApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) {
}

func (app *stakingApplication) queryTotalSupply(s, r interface{}) ([]byte, error) {
	state := s.(*immutableState)
	return state.rawTotalSupply()
}

func (app *stakingApplication) queryCommonPool(s, r interface{}) ([]byte, error) {
	state := s.(*immutableState)
	return state.rawCommonPool()
}

func (app *stakingApplication) queryThresholds(s, r interface{}) ([]byte, error) {
	state := s.(*immutableState)

	thresholds, err := state.Thresholds()
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(thresholds), nil
}

func (app *stakingApplication) queryAccounts(s, r interface{}) ([]byte, error) {
	state := s.(*immutableState)
	return state.rawAccounts()
}

func (app *stakingApplication) queryAccountInfo(s, r interface{}) ([]byte, error) {
	request := r.(*api.QueryGetByIDRequest)
	state := s.(*immutableState)

	ent := state.account(request.ID)
	resp := QueryAccountInfoResponse{
		GeneralBalance:  ent.GeneralBalance,
		EscrowBalance:   ent.EscrowBalance,
		DebondStartTime: ent.DebondStartTime,
		Nonce:           ent.Nonce,
	}
	return cbor.Marshal(resp), nil
}

func (app *stakingApplication) queryDebondingInterval(s, r interface{}) ([]byte, error) {
	state := s.(*immutableState)
	return state.rawDebondingInterval()
}

func (app *stakingApplication) queryGenesis(s, r interface{}) ([]byte, error) {
	state := s.(*immutableState)

	totalSupply, err := state.totalSupply()
	if err != nil {
		return nil, err
	}

	commonPool, err := state.CommonPool()
	if err != nil {
		return nil, err
	}

	thresholds, err := state.Thresholds()
	if err != nil {
		return nil, err
	}

	debondingInterval, err := state.debondingInterval()
	if err != nil {
		return nil, err
	}

	accounts, err := state.accounts()
	if err != nil {
		return nil, err
	}
	ledger := make(map[signature.MapKey]*staking.GenesisLedgerEntry)
	for _, acctID := range accounts {
		acct := state.account(acctID)
		ledger[acctID.ToMapKey()] = &staking.GenesisLedgerEntry{
			GeneralBalance:  acct.GeneralBalance,
			EscrowBalance:   acct.EscrowBalance,
			DebondStartTime: acct.DebondStartTime,
			Nonce:           acct.Nonce,
		}
	}

	gen := staking.Genesis{
		TotalSupply:       *totalSupply,
		CommonPool:        *commonPool,
		Thresholds:        thresholds,
		DebondingInterval: debondingInterval,
		Ledger:            ledger,
	}
	return cbor.Marshal(gen), nil
}

func (app *stakingApplication) executeTx(ctx *abci.Context, tree *iavl.MutableTree, tx *Tx) error {
	state := NewMutableState(tree)

	if tx.TxTransfer != nil {
		return app.transfer(ctx, state, &tx.TxTransfer.SignedTransfer)
	} else if tx.TxBurn != nil {
		return app.burn(ctx, state, &tx.TxBurn.SignedBurn)
	} else if tx.TxAddEscrow != nil {
		return app.addEscrow(ctx, state, &tx.TxAddEscrow.SignedEscrow)
	} else if tx.TxReclaimEscrow != nil {
		return app.reclaimEscrow(ctx, state, &tx.TxReclaimEscrow.SignedReclaimEscrow)
	} else {
		return staking.ErrInvalidArgument
	}
}

func (app *stakingApplication) transfer(ctx *abci.Context, state *MutableState, signedXfer *staking.SignedTransfer) error {
	var xfer staking.Transfer
	if err := signedXfer.Open(staking.TransferSignatureContext, &xfer); err != nil {
		app.logger.Error("Transfer: invalid signature",
			"signed_xfer", signedXfer,
		)
		return staking.ErrInvalidSignature
	}

	fromID := signedXfer.Signature.PublicKey
	from := state.account(fromID)
	if from.Nonce != xfer.Nonce {
		app.logger.Error("Transfer: invalid account nonce",
			"from", fromID,
			"account_nonce", from.Nonce,
			"xfer_nonce", xfer.Nonce,
		)
		return staking.ErrInvalidNonce
	}

	if fromID.Equal(xfer.To) {
		// Handle transfer to self as just a balance check.
		if from.GeneralBalance.Cmp(&xfer.Tokens) < 0 {
			err := staking.ErrInsufficientBalance
			app.logger.Error("Transfer: self-transfer greater than balance",
				"err", err,
				"from", fromID,
				"to", xfer.To,
				"amount", xfer.Tokens,
			)
			return err
		}
	} else {
		// Source and destination MUST be separate accounts with how
		// staking.Move is implemented.
		to := state.account(xfer.To)
		if err := staking.Move(&to.GeneralBalance, &from.GeneralBalance, &xfer.Tokens); err != nil {
			app.logger.Error("Transfer: failed to move balance",
				"err", err,
				"from", fromID,
				"to", xfer.To,
				"amount", xfer.Tokens,
			)
			return err
		}

		state.setAccount(xfer.To, to)
	}

	from.Nonce++
	state.setAccount(fromID, from)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("Transfer: executed transfer",
			"from", fromID,
			"to", xfer.To,
			"amount", xfer.Tokens,
		)

		ctx.EmitData(&Output{
			OutputTransfer: &staking.TransferEvent{
				From:   fromID,
				To:     xfer.To,
				Tokens: xfer.Tokens,
			},
		})
	}

	return nil
}

func (app *stakingApplication) burn(ctx *abci.Context, state *MutableState, signedBurn *staking.SignedBurn) error {
	var burn staking.Burn
	if err := signedBurn.Open(staking.BurnSignatureContext, &burn); err != nil {
		app.logger.Error("Burn: invalid signature",
			"signed_burn", signedBurn,
		)
		return staking.ErrInvalidSignature
	}

	id := signedBurn.Signature.PublicKey
	from := state.account(id)
	if from.Nonce != burn.Nonce {
		app.logger.Error("Burn: invalid account nonce",
			"from", id,
			"account_nonce", from.Nonce,
			"burn_nonce", burn.Nonce,
		)
		return staking.ErrInvalidNonce
	}

	if err := from.GeneralBalance.Sub(&burn.Tokens); err != nil {
		app.logger.Error("Burn: failed to burn tokens",
			"err", err,
			"from", id, "amount", burn.Tokens,
		)
		return err
	}

	totalSupply, _ := state.totalSupply()

	from.Nonce++
	_ = totalSupply.Sub(&burn.Tokens)

	state.setAccount(id, from)
	state.setTotalSupply(totalSupply)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("Burn: burnt tokens",
			"from", id,
			"amount", burn.Tokens,
		)

		ctx.EmitData(&Output{
			OutputBurn: &staking.BurnEvent{
				Owner:  id,
				Tokens: burn.Tokens,
			},
		})
	}

	return nil
}

func (app *stakingApplication) addEscrow(ctx *abci.Context, state *MutableState, signedEscrow *staking.SignedEscrow) error {
	var escrow staking.Escrow
	if err := signedEscrow.Open(staking.EscrowSignatureContext, &escrow); err != nil {
		app.logger.Error("AddEscrow: invalid signature",
			"signed_escrow", signedEscrow,
		)
		return staking.ErrInvalidSignature
	}

	id := signedEscrow.Signature.PublicKey
	from := state.account(id)
	if from.Nonce != escrow.Nonce {
		app.logger.Error("AddEscrow: invalid account nonce",
			"from", id,
			"account_nonce", from.Nonce,
			"escrow_nonce", escrow.Nonce,
		)
		return staking.ErrInvalidNonce
	}

	if err := staking.Move(&from.EscrowBalance, &from.GeneralBalance, &escrow.Tokens); err != nil {
		app.logger.Error("AddEscrow: failed to escrow tokens",
			"err", err,
			"from", id,
			"amount", escrow.Tokens,
		)
		return err
	}

	from.Nonce++
	state.setAccount(id, from)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("AddEscrow: escrowed tokens",
			"from", id,
			"amount", escrow.Tokens,
		)

		ctx.EmitData(&Output{
			OutputAddEscrow: &staking.EscrowEvent{
				Owner:  signedEscrow.Signature.PublicKey,
				Tokens: escrow.Tokens,
			},
		})
	}

	return nil
}

func (app *stakingApplication) reclaimEscrow(ctx *abci.Context, state *MutableState, signedReclaim *staking.SignedReclaimEscrow) error {
	var reclaim staking.ReclaimEscrow
	if err := signedReclaim.Open(staking.ReclaimEscrowSignatureContext, &reclaim); err != nil {
		app.logger.Error("ReclaimEscrow: invalid signature",
			"signed_reclaim", signedReclaim,
		)
		return staking.ErrInvalidSignature
	}

	id := signedReclaim.Signature.PublicKey
	from := state.account(id)
	if from.Nonce != reclaim.Nonce {
		app.logger.Error("ReclaimEscrow: invalid account nonce",
			"from", id,
			"account_nonce", from.Nonce,
			"reclaim_nonce", reclaim.Nonce,
		)
		return staking.ErrInvalidNonce
	}

	debondingInterval, err := state.debondingInterval()
	if err != nil {
		app.logger.Error("ReclaimEscrow: failed to query debonding interval",
			"err", err,
		)
		return err
	}
	var (
		now      = uint64(ctx.Now().Unix())
		debondAt = from.DebondStartTime + debondingInterval
	)
	if now < debondAt {
		app.logger.Error("ReclaimEscrow: in debonding interval",
			"from", id,
			"now", now,
			"debond_at", debondAt,
		)
		return staking.ErrDebonding
	}

	if err := staking.Move(&from.GeneralBalance, &from.EscrowBalance, &reclaim.Tokens); err != nil {
		app.logger.Error("ReclaimEscrow: failed to release tokens",
			"err", err,
			"from", id,
			"amount", reclaim.Tokens,
		)
		return err
	}

	from.Nonce++
	state.setAccount(id, from)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("ReleaseEscrow: released tokens",
			"from", id,
			"amount", reclaim.Tokens,
		)

		ctx.EmitData(&Output{
			OutputReclaimEscrow: &staking.ReclaimEscrowEvent{
				Owner:  signedReclaim.Signature.PublicKey,
				Tokens: reclaim.Tokens,
			},
		})
	}

	return nil
}

// EnsureSufficientStake ensures that the account owned by id has sufficient
// stake to meet the sum of the thresholds specified.  The thresholds vector
// can have multiple instances of the same threshold kind specified, in which
// case it will be factored in repeatedly.
func EnsureSufficientStake(appState *abci.ApplicationState, ctx *abci.Context, id signature.PublicKey, thresholds []staking.ThresholdKind) error {
	var state *MutableState
	if ctx.IsCheckOnly() {
		state = NewMutableState(appState.CheckTxTree())
	} else {
		state = NewMutableState(appState.DeliverTxTree())
	}

	m, err := state.Thresholds()
	if err != nil {
		return errors.Wrap(err, "staking/tendermint: failed to query thresholds")
	}
	escrowBalance := state.EscrowBalance(id)

	var targetThreshold staking.Quantity
	for _, v := range thresholds {
		qty := m[v]
		if err = targetThreshold.Add(&qty); err != nil {
			return errors.Wrap(err, "staking/tendermint: failed to accumulate threshold")
		}
	}

	if escrowBalance.Cmp(&targetThreshold) < 0 {
		return staking.ErrInsufficientStake
	}

	return nil
}

// Snapshot is a snapshot of the escrow balances and thresholds that can be
// used in lieu of repeated queries to `EnsureSufficientStake` at a given
// height.  This should be favored when repeated queries are going to
// be made.
type Snapshot struct {
	thresholds map[staking.ThresholdKind]staking.Quantity
	balances   map[signature.MapKey]*staking.Quantity
}

// EnsureSufficientStake ensures that the account owned by id has sufficient
// stake to meet the sum of the thresholds specified.  The thresholds vector
// can have multiple instances of the same threshold kind specified, in which
// case it will be factored in repeatedly.
func (snap *Snapshot) EnsureSufficientStake(id signature.PublicKey, thresholds []staking.ThresholdKind) error {
	escrowBalance := snap.balances[id.ToMapKey()]
	if escrowBalance == nil {
		escrowBalance = staking.NewQuantity()
	}

	var targetThreshold staking.Quantity
	for _, v := range thresholds {
		qty := snap.thresholds[v]
		if err := targetThreshold.Add(&qty); err != nil {
			return errors.Wrap(err, "staking/tendermint: failed to accumulate threshold")
		}
	}

	if escrowBalance.Cmp(&targetThreshold) < 0 {
		return staking.ErrInsufficientStake
	}

	return nil
}

// NewSnapshot creates a new staking snapshot.
func NewSnapshot(appState *abci.ApplicationState, ctx *abci.Context) (*Snapshot, error) {
	var state *MutableState
	if ctx.IsCheckOnly() {
		state = NewMutableState(appState.CheckTxTree())
	} else {
		state = NewMutableState(appState.DeliverTxTree())
	}

	thresholds, err := state.Thresholds()
	if err != nil {
		return nil, errors.Wrap(err, "staking/tendermint: failed to query thresholds")
	}

	accounts, err := state.accounts()
	if err != nil {
		return nil, errors.Wrap(err, "staking/tendermint: failed to query accounts")
	}

	balances := make(map[signature.MapKey]*staking.Quantity)
	for _, v := range accounts {
		if balance := state.EscrowBalance(v); !balance.IsZero() {
			balances[v.ToMapKey()] = balance
		}
	}

	return &Snapshot{
		thresholds: thresholds,
		balances:   balances,
	}, nil
}

// New constructs a new staking application instance.
func New(debugGenesisState *staking.Genesis) abci.Application {
	return &stakingApplication{
		logger:            logging.GetLogger("tendermint/staking"),
		debugGenesisState: debugGenesisState,
	}
}
