package e2e

import (
	"context"
	"fmt"
	"time"

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
			clientBinary: "", // We use a Go client.
		},
		logger: logging.GetLogger("scenario/e2e/basic_swdp"),
	}
	return sc
}

func (sc *basicSwdpImpl) Name() string {
	return "basic-swdp"
}

func (sc *basicSwdpImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Use the simple-swdp runtime (as opposed to the default simple-keyvalue).
	simpleSwdpRuntimeBinary, err := resolveRuntimeBinary("simple-swdp")
	if err != nil {
		return nil, err
	}
	f.Runtimes[1].Binary = simpleSwdpRuntimeBinary

	return f, nil
}

// XXX: Reuse other worker-info structs? From where?
type workerInfo struct {
	Name    string `json:"name"`
	Address string `json:"address"`
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

	var rsp transaction.TxnOutput
	rawRsp, err := c.SubmitTx(ctx, &api.SubmitTxRequest{
		RuntimeID: runtimeID,
		Data: cbor.Marshal(&transaction.TxnCall{
			Method: "swdp_register_worker",
			Args: workerInfo{
				Name:    "MyWorker",
				Address: "0.0.0.0:999",
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

	// Wait for changes to propagate (???)
	// XXX: How do I wait for a TX to complete? Do I need to?
	sc.logger.Info("sleeping 30s just in case")
	time.Sleep(30 * time.Second)

	return nil
}
