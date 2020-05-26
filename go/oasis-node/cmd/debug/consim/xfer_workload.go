package consim

import (
	"fmt"
	"math/rand"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	// TODO: Should these be made configurable?
	transferNumAccounts = 10
	transferFundAmount  = 1000
	transferAmount      = 1

	xferWorkloadName = "xfer"

	cfgXferIterations = "consim.workload.xfer.iterations"
)

var xferFlags = flag.NewFlagSet("", flag.ContinueOnError)

type xferWorkload struct {
	ch chan []BlockTx

	rng *rand.Rand

	fundingAccount *xferAccount
	accounts       []*xferAccount
}

type xferAccount struct {
	signer  signature.Signer
	address staking.Address
	nonce   uint64
	balance quantity.Quantity
}

func (w *xferWorkload) Init(doc *genesis.Document) error {
	// Check/fix the genesis document.
	//
	// Right now the workload is blissfully gas unaware, and will break if
	// staking transfer transactions actually cost gas.  Fossil fuels are
	// bad for the environment, transactions should be nuclear powered
	// instead.
	if doc.Staking.Parameters.GasCosts[staking.GasOpTransfer] > 0 {
		logger.Warn("consim/workload/xfer: forcing transfer op gas cost to zero")
		doc.Staking.Parameters.GasCosts[staking.GasOpTransfer] = 0
	}
	if doc.Consensus.Parameters.GasCosts[consensusGenesis.GasOpTxByte] > 0 {
		logger.Warn("consim/workload/xfer: forcing per-byte gas cost to zero")
		doc.Consensus.Parameters.GasCosts[consensusGenesis.GasOpTxByte] = 0
	}

	// Ensure the genesis doc has the debug test entity to be used to
	// fund the accounts.
	testEntity, _, _ := entity.TestEntity()
	testAccount := doc.Staking.Ledger[staking.NewAddress(testEntity.ID)]
	if testAccount == nil {
		return fmt.Errorf("consim/workload/xfer: test entity not present in genesis")
	}
	if !xferHasEnoughBalance(&testAccount.General.Balance, transferFundAmount*transferNumAccounts) {
		return fmt.Errorf("consim/workload/xfer: test entity has insufficient balance")
	}

	return nil
}

func (w *xferWorkload) Start(initialState *genesis.Document, cancelCh <-chan struct{}, errCh chan<- error) (<-chan []BlockTx, error) {
	// Initialize the funding account.
	testEntity, testSigner, _ := entity.TestEntity()
	testAccountAddr := staking.NewAddress(testEntity.ID)
	testAccount := initialState.Staking.Ledger[testAccountAddr]
	w.fundingAccount = &xferAccount{
		signer:  testSigner,
		address: testAccountAddr,
		nonce:   testAccount.General.Nonce,
		balance: testAccount.General.Balance,
	}

	// Initialize the test accounts.
	for i := 0; i < transferNumAccounts; i++ {
		accSigner, err := memory.NewSigner(w.rng)
		if err != nil {
			return nil, fmt.Errorf("consim/workload/xfer: failed to create signer: %w", err)
		}

		acc := &xferAccount{
			signer:  accSigner,
			address: staking.NewAddress(accSigner.Public()),
		}
		if lacc := initialState.Staking.Ledger[acc.address]; lacc != nil {
			acc.nonce = lacc.General.Nonce
			acc.balance = lacc.General.Balance
		}
		w.accounts = append(w.accounts, acc)
	}

	w.ch = make(chan []BlockTx)

	go w.worker(cancelCh, errCh)

	return w.ch, nil
}

func (w *xferWorkload) Finalize(finalState *genesis.Document) error {
	for _, acc := range w.accounts {
		lacc := finalState.Staking.Ledger[acc.address]
		if lacc == nil {
			return fmt.Errorf("consim/workload/xfer: account missing: %v", acc.address)
		}
		if lacc.General.Nonce != acc.nonce {
			return fmt.Errorf(
				"consim/workload/xfer: nonce mismatch: %v (expected: %v, actual: %v)",
				acc.address, acc.nonce, lacc.General.Nonce,
			)
		}
		if lacc.General.Balance.Cmp(&acc.balance) != 0 {
			return fmt.Errorf(
				"consim/workload/xfer: balance mismatch: %v (expected: %v, actual: %v)",
				acc.address, acc.balance, lacc.General.Balance,
			)
		}
	}
	return nil
}

func (w *xferWorkload) Cleanup() {}

func (w *xferWorkload) worker(cancelCh <-chan struct{}, errCh chan<- error) {
	defer close(w.ch)

	// Fund all the accounts.
	// Note: This needs to be done 1 tx/block(?).
	for _, v := range w.accounts {
		tx, err := xferGenTx(w.fundingAccount, v, transferFundAmount)
		if err != nil {
			errCh <- err
			return
		}
		w.ch <- []BlockTx{BlockTx{Tx: tx}}
	}

	numAccounts, numIterations := len(w.accounts), viper.GetInt(cfgXferIterations)

	// Shuffle tokens around till bored.
	for nBlocks := 0; nBlocks < numIterations; nBlocks++ {
		// Check for cancelation due to errors.
		select {
		case <-cancelCh:
			return
		default:
		}

		numTxsInBlock := w.rng.Intn(numAccounts)

		var xferTxs []BlockTx
		fromPerm := w.rng.Perm(numAccounts)
		toPerm := w.rng.Perm(numAccounts)
		for i := 0; i < numTxsInBlock; i++ {
			from := w.accounts[fromPerm[i]]
			if !xferHasEnoughBalance(&from.balance, transferAmount) {
				continue
			}
			to := w.accounts[toPerm[i]]
			if from.signer.Public().Equal(to.signer.Public()) {
				// The helper doesn't support this at the moment.
				continue
			}
			tx, err := xferGenTx(from, to, transferAmount)
			if err != nil {
				errCh <- err
				return
			}
			xferTxs = append(xferTxs, BlockTx{
				Tx: tx,
			})
		}
		if len(xferTxs) > 0 {
			w.ch <- xferTxs
		}
	}
}

func xferGenTx(from, to *xferAccount, amount uint64) ([]byte, error) {
	// TODO: At some point this should pay gas, for now don't under
	// the assumption that transactions are free.
	xfer := &staking.Transfer{
		To: to.address,
	}
	if err := xfer.Tokens.FromUint64(amount); err != nil {
		return nil, err
	}

	var fee transaction.Fee
	tx := staking.NewTransferTx(from.nonce, &fee, xfer)
	signedTx, err := transaction.Sign(from.signer, tx)
	if err != nil {
		return nil, err
	}

	logger.Debug("TX",
		"from", from.address,
		"to", to.address,
		"nonce", from.nonce,
	)

	// Update the state on the assumption that the tx will be submitted
	// successfully.
	//
	// Note: The Move call will break if from == to, so don't do that.
	from.nonce++
	if err = quantity.Move(&to.balance, &from.balance, &xfer.Tokens); err != nil {
		return nil, err
	}

	return cbor.Marshal(signedTx), nil
}

func xferHasEnoughBalance(bal *quantity.Quantity, amnt uint64) bool {
	var target quantity.Quantity
	if err := target.FromUint64(amnt); err != nil {
		return false
	}

	return bal.Cmp(&target) >= 0
}

func newXferWorkload(rng *rand.Rand) (Workload, error) {
	return &xferWorkload{
		rng: rng,
	}, nil
}

func init() {
	xferFlags.Int(cfgXferIterations, 10000, "number of iterations")
	_ = viper.BindPFlags(xferFlags)
}
