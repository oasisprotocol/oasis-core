// +build gofuzz

package fuzz

import (
	"context"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/fuzz"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/epochtime_mock"
	registryApp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry"
	stakingApp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking"
)

var (
	txSigner signature.Signer = memory.NewTestSigner("consensus-fuzz")

	// FuzzableApps is a list of ABCI apps the fuzzer can fuzz.
	FuzzableApps []abci.Application = []abci.Application{
		epochtimemock.New(),
		registryApp.New(),
		stakingApp.New(),
	}

	// FuzzableMethods is a list of all the apps' transaction methods that are fuzzable.
	FuzzableMethods []transaction.MethodName
)

func init() {
	for _, app := range FuzzableApps {
		FuzzableMethods = append(FuzzableMethods, app.Methods()...)
	}
}

func Fuzz(data []byte) int {
	var err error

	ctx := context.Background()

	var pruneCfg abci.PruneConfig

	appConfig := &abci.ApplicationConfig{
		DataDir:         "/tmp/oasis-node-fuzz-consensus",
		Pruning:         pruneCfg,
		HaltEpochHeight: 1000000,
		MinGasPrice:     1,
	}

	// The muxer will start with the previous state, if it exists (the state database isn't cleared).
	muxer, _ := abci.NewMockMux(ctx, appConfig)
	defer muxer.MockClose()

	for _, app := range FuzzableApps {
		muxer.MockRegisterApp(app)
	}

	if len(data) < 2 {
		return -1
	}
	meth := int(data[0])
	if meth >= len(FuzzableMethods) {
		return -1
	}

	methodName := FuzzableMethods[meth]

	blob, _ := fuzz.NewFilledInstance(data, methodName.BodyType())

	tx := &transaction.Transaction{
		Method: methodName,
		Body: cbor.Marshal(blob),
	}

	signedTx, err := transaction.Sign(txSigner, tx)
	if err != nil {
		panic("error signing transaction")
	}

	txBlob := cbor.Marshal(&signedTx)

	// Check the transaction.
	checkReq := types.RequestCheckTx{
		Tx: txBlob,
		Type: types.CheckTxType_New,
	}
	muxer.CheckTx(checkReq)

	// And try executing it too.
	deliverReq := types.RequestDeliverTx{
		Tx: txBlob,
	}
	muxer.DeliverTx(deliverReq)

	return 0
}
