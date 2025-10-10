package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// TxnCall is a transaction call in the test runtime.
type TxnCall struct {
	// Sender is the sender.
	Sender []byte `json:"sender"`
	// Nonce is a nonce.
	Nonce uint64 `json:"nonce"`
	// Method is the called method name.
	Method string `json:"method"`
	// Args are the method arguments.
	Args any `json:"args"`
}

// TxnOutput is a transaction call output in the test runtime.
type TxnOutput struct {
	// Success can be of any type.
	Success cbor.RawMessage
	// Error is a string describing the error message.
	Error *string
}

func (sc *Scenario) submitRuntimeTx(
	ctx context.Context,
	id common.Namespace,
	sender string,
	nonce uint64,
	method string,
	args any,
) (cbor.RawMessage, uint64, error) {
	// Submit a transaction and check the result.
	metaRsp, err := sc.submitRuntimeTxMeta(ctx, id, sender, nonce, method, args)
	if err != nil {
		return nil, 0, err
	}
	rsp, err := unpackRawTxResp(metaRsp.Output)
	if err != nil {
		return nil, 0, err
	}
	return rsp, metaRsp.Round, nil
}

func (sc *Scenario) submitRuntimeQuery(
	ctx context.Context,
	id common.Namespace,
	round uint64,
	method string,
	args any,
) (cbor.RawMessage, error) {
	ctrl := sc.Net.ClientController()
	if ctrl == nil {
		return nil, fmt.Errorf("client controller not available")
	}
	c := ctrl.RuntimeClient

	resp, err := c.Query(ctx, &runtimeClient.QueryRequest{RuntimeID: id, Round: round, Method: method, Args: cbor.Marshal(args)})
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	return resp.Data, nil
}

func (sc *Scenario) submitRuntimeTxMeta(
	ctx context.Context,
	id common.Namespace,
	sender string,
	nonce uint64,
	method string,
	args any,
) (*runtimeClient.SubmitTxMetaResponse, error) {
	ctrl := sc.Net.ClientController()
	if ctrl == nil {
		return nil, fmt.Errorf("client controller not available")
	}
	c := ctrl.RuntimeClient

	resp, err := c.SubmitTxMeta(ctx, &runtimeClient.SubmitTxRequest{
		RuntimeID: id,
		Data: cbor.Marshal(&TxnCall{
			Sender: []byte(sender),
			Nonce:  nonce,
			Method: method,
			Args:   args,
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to submit runtime meta tx: %w", err)
	}
	if resp.CheckTxError != nil {
		return nil, fmt.Errorf("check tx failed: %s", resp.CheckTxError.Message)
	}

	return resp, nil
}

func unpackRawTxResp(rawRsp []byte) (cbor.RawMessage, error) {
	var rsp TxnOutput
	if err := cbor.Unmarshal(rawRsp, &rsp); err != nil {
		return nil, fmt.Errorf("malformed tx output from runtime: %w", err)
	}
	if rsp.Error != nil {
		return nil, fmt.Errorf("runtime tx failed: %s", *rsp.Error)
	}
	return rsp.Success, nil
}

func (sc *Scenario) submitConsensusXferTxMeta(
	ctx context.Context,
	xfer staking.Transfer,
	sender string,
	nonce uint64,
) (*runtimeClient.SubmitTxMetaResponse, error) {
	return sc.submitRuntimeTxMeta(ctx, KeyValueRuntimeID, sender, nonce, "consensus_transfer", struct {
		Transfer staking.Transfer `json:"transfer"`
	}{
		Transfer: xfer,
	})
}

func (sc *Scenario) submitRuntimeInMsg(ctx context.Context, id common.Namespace, sender string, nonce uint64, method string, args any) error {
	ctrl := sc.Net.ClientController()
	if ctrl == nil {
		return fmt.Errorf("client controller not available")
	}

	// Queue a runtime message and wait for it to be processed.
	tx := roothash.NewSubmitMsgTx(0, &transaction.Fee{Gas: 10_000}, &roothash.SubmitMsg{
		ID:  id,
		Tag: 42,
		Data: cbor.Marshal(&TxnCall{
			Sender: []byte(sender),
			Nonce:  nonce,
			Method: method,
			Args:   args,
		}),
	})
	signer := memorySigner.NewTestSigner("oasis in msg test signer: " + time.Now().String())
	sigTx, err := transaction.Sign(signer, tx)
	if err != nil {
		return fmt.Errorf("failed to sign SubmitMsg transaction: %w", err)
	}

	// Start watching roothash events.
	ch, sub, err := ctrl.Roothash.WatchEvents(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to watch events: %w", err)
	}
	defer sub.Close()

	err = ctrl.Consensus.SubmitTx(ctx, sigTx)
	if err != nil {
		return fmt.Errorf("failed to submit SubmitMsg transaction: %w", err)
	}

	// Wait for processed event.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	sc.Logger.Info("waiting for incoming message processed event")
	callerAddr := staking.NewAddress(signer.Public())
	for {
		select {
		case ev := <-ch:
			if ev.InMsgProcessed == nil {
				continue
			}

			if !ev.InMsgProcessed.Caller.Equal(callerAddr) {
				return fmt.Errorf("unexpected caller address (got: %s expected: %s)", ev.InMsgProcessed.Caller, callerAddr)
			}
			if ev.InMsgProcessed.Tag != 42 {
				return fmt.Errorf("unexpected tag (got: %d expected: %d)", ev.InMsgProcessed.Tag, 42)
			}
		case <-ctx.Done():
			return ctx.Err()
		}

		break
	}

	return nil
}
