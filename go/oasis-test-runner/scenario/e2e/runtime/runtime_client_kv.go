package runtime

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
)

var BasicKVTestClient = NewBinaryTestClient(
	"simple-keyvalue-client",
	nil,
)

// KeyValueTestClient is a client that exercises the simple key-value
// test runtime.
type KeyValueTestClient struct {
	sc *runtimeImpl
}

func (cli *KeyValueTestClient) Init(scenario *runtimeImpl) error {
	cli.sc = scenario
	return nil
}

func (cli *KeyValueTestClient) Start(ctx context.Context, childEnv *env.Env) error {
	panic("not implemented")
}

func (cli *KeyValueTestClient) Wait() error {
	panic("not implemented")
}

func (cli *KeyValueTestClient) Clone() TestClient {
	panic("not implemented")
}

func NewKeyValueTestClient() *KeyValueTestClient {
	panic("not implemented")
}

func (sc *runtimeImpl) submitKeyValueRuntimeInsertTx(
	ctx context.Context,
	id common.Namespace,
	key, value string,
	nonce uint64,
) error {
	_, err := sc.submitRuntimeTx(ctx, id, "insert", struct {
		Key   string `json:"key"`
		Value string `json:"value"`
		Nonce uint64 `json:"nonce"`
	}{
		Key:   key,
		Value: value,
		Nonce: nonce,
	})
	return err
}

func (sc *runtimeImpl) submitKeyValueRuntimeGetTx(
	ctx context.Context,
	id common.Namespace,
	key string,
	nonce uint64,
) (string, error) {
	rawRsp, err := sc.submitRuntimeTx(ctx, runtimeID, "get", struct {
		Key   string `json:"key"`
		Nonce uint64 `json:"nonce"`
	}{
		Key:   key,
		Nonce: nonce,
	})
	if err != nil {
		return "", fmt.Errorf("failed to submit get tx to runtime: %w", err)
	}

	var rsp string
	if err = cbor.Unmarshal(rawRsp, &rsp); err != nil {
		return "", fmt.Errorf("failed to unmarshal response from runtime: %w", err)
	}

	return rsp, nil
}
