package runtime

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
)

var (
	BasicKVTestClient = NewBinaryTestClient(
		"simple-keyvalue-client",
		nil,
	)
	BasicKVEncTestClient = NewBinaryTestClient(
		"simple-keyvalue-enc-client",
		nil,
	)
)

// TestClient is the interface exposed to implement a runtime test
// client that executes a pre-determined workload against a given runtime.
type TestClient interface {
	Init(*runtimeImpl) error
	Start(context.Context, *env.Env) error
	Wait() error

	// Clone returns a clone of a RuntimeTestClient instance, in a state
	// that is ready for Init.
	Clone() TestClient
}

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

// BinaryTestClient is a client that exercises an arbitrary runtime
// by fork/exec-ing another binary.
type BinaryTestClient struct {
	ctx context.Context
	sc  *runtimeImpl

	binary string
	args   []string

	cmd   *exec.Cmd
	errCh chan error
}

func (cli *BinaryTestClient) Init(scenario *runtimeImpl) error {
	cli.sc = scenario
	return nil
}

func (cli *BinaryTestClient) Start(ctx context.Context, childEnv *env.Env) error {
	// Setup the client
	d, err := childEnv.NewSubDir("client")
	if err != nil {
		return err
	}

	w, err := d.NewLogWriter("client.log")
	if err != nil {
		return err
	}

	args := []string{
		"--node-address", "unix:" + cli.sc.Net.Clients()[0].SocketPath(),
		"--runtime-id", runtimeID.String(),
	}
	args = append(args, cli.args...)

	binary := cli.resolveClientBinary()
	cmd := exec.Command(binary, args...)
	cmd.SysProcAttr = env.CmdAttrs
	cmd.Stdout = w
	cmd.Stderr = w

	cli.sc.Logger.Info("launching client",
		"binary", binary,
		"args", strings.Join(args, " "),
	)

	// Start the client
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("scenario/e2e: failed to start client: %w", err)
	}

	// Wire up the termination handler
	cli.cmd = cmd
	cli.errCh = make(chan error)
	go func() {
		cli.errCh <- cmd.Wait()
	}()

	cli.ctx = ctx

	return nil
}

func (cli *BinaryTestClient) Wait() error {
	var err error

	// Wait for the network to fail, the context to be canceled, or the
	// client to terminate on it's own.
	select {
	case err = <-cli.sc.Net.Errors():
		_ = cli.cmd.Process.Kill()
	case <-cli.ctx.Done():
		err = cli.ctx.Err()
		_ = cli.cmd.Process.Kill()
	case err = <-cli.errCh:
	}

	return err
}

func (cli *BinaryTestClient) Kill() error {
	return cli.cmd.Process.Kill()
}

func (cli *BinaryTestClient) Clone() TestClient {
	return &BinaryTestClient{
		binary: cli.binary,
		args:   append([]string{}, cli.args...),
	}
}

func (cli *BinaryTestClient) resolveClientBinary() string {
	cbDir, _ := cli.sc.Flags.GetString(cfgClientBinaryDir)
	return filepath.Join(cbDir, cli.binary)
}

func NewBinaryTestClient(binary string, args []string) *BinaryTestClient {
	return &BinaryTestClient{
		binary: binary,
		args:   args,
	}
}
