package e2e

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasislabs/oasis-core/go/runtime/client/api"
	"github.com/oasislabs/oasis-core/go/runtime/transaction"
)

var (
	BasicSwdp scenario.Scenario = newBasicSwdpImpl()
)

type basicSwdpImpl struct {
	basicImpl

	logger *logging.Logger
}

func newBasicSwdpImpl() scenario.Scenario {
	sc := &basicSwdpImpl{
		basicImpl: basicImpl{
			// The client is implemented in this file using the Go oasis-client API;
			// we don't need an external binary to communicate with the blockchain.
			clientBinary: "",
		},
		logger: logging.GetLogger("scenario/e2e/basic_swdp"),
	}
	return sc
}

func (sc *basicSwdpImpl) Name() string {
	return "basic-swdp"
}

// Constructs and returns the network fixture (= all services) for the tests in this file.
// Unlike most other e2e tests in oasis-core, we use the `simple-swdp` runtime (as opposed to simple-keyvalue),
// lets us exercse the stateless worker.
func (sc *basicSwdpImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Use the simple-swdp runtime.
	simpleSwdpRuntimeBinary, err := resolveRuntimeBinary("simple-swdp")
	if err != nil {
		return nil, err
	}
	f.Runtimes[1].Binary = simpleSwdpRuntimeBinary

	return f, nil
}

// Information needed to register a stateless worker; see
// Rust for reference field documentation.
type statelessWorkerInfo struct {
	ID       common.Namespace   `json:"ID"`
	Runtimes []common.Namespace `json:"runtimes"`
}

func (sc *basicSwdpImpl) Run(childEnv *env.Env) error {
	if err := sc.net.Start(); err != nil {
		return err
	}

	ctx := context.Background()

	sc.logger.Info("waiting for nodes to register",
		"num_nodes", sc.net.NumRegisterNodes(),
	)
	if err := sc.net.Controller().WaitNodesRegistered(ctx, sc.net.NumRegisterNodes()); err != nil {
		return err
	}
	c := sc.net.ClientController().RuntimeClient

	sc.logger.Info("submitting transaction to runtime")

	var workerId, runtimeId, runtimeId2 common.Namespace
	_ = workerId.UnmarshalHex("123")
	_ = runtimeId.UnmarshalHex("99123")
	_ = runtimeId2.UnmarshalHex("99789")
	var rsp transaction.TxnOutput
	rawRsp, err := c.SubmitTx(ctx, &api.SubmitTxRequest{
		RuntimeID: runtimeID,
		Data: cbor.Marshal(&transaction.TxnCall{
			Method: "swdp_register_worker",
			Args: statelessWorkerInfo{
				ID:       workerId,
				Runtimes: []common.Namespace{runtimeId, runtimeId2},
			},
		}),
	})
	if err != nil {
		return fmt.Errorf("failed to submit runtime tx: %w", err)
	}
	if err = cbor.Unmarshal(rawRsp, &rsp); err != nil {
		return fmt.Errorf("malformed tx output from runtime: %w", err)
	}
	if rsp.Error != nil {
		return fmt.Errorf("runtime tx failed: %s", *rsp.Error)
	}

	sc.logger.Info("Transaction successful", "return value", rsp.Success)

	return nil
}
