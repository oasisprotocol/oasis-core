package host

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

var (
	// ErrInvalidArgument is the error returned when any of the passed method arguments is invalid.
	ErrInvalidArgument = fmt.Errorf("runtime: invalid argument")
	// ErrCheckTxFailed is the error returned when a transaction is rejected by the runtime.
	ErrCheckTxFailed = fmt.Errorf("runtime: check tx failed")
	// ErrInternal is the error returned when an unspecified internal error occurs.
	ErrInternal = fmt.Errorf("runtime: internal error")
)

// RichRuntime provides higher-level functions for talking with a runtime.
type RichRuntime interface {
	Runtime

	// CheckTx requests the runtime to check a given transaction.
	CheckTx(
		ctx context.Context,
		rb *block.Block,
		lb *consensus.LightBlock,
		epoch beacon.EpochTime,
		maxMessages uint32,
		batch transaction.RawBatch,
	) ([]protocol.CheckTxResult, error)

	// Query requests the runtime to answer a runtime-specific query.
	Query(
		ctx context.Context,
		rb *block.Block,
		lb *consensus.LightBlock,
		epoch beacon.EpochTime,
		maxMessages uint32,
		method string,
		args []byte,
	) ([]byte, error)

	// ConsensusSync requests the runtime to sync its light client up to the given consensus height.
	ConsensusSync(ctx context.Context, height uint64) error
}

type richRuntime struct {
	Runtime
}

// Implements RichRuntime.
func (r *richRuntime) CheckTx(
	ctx context.Context,
	rb *block.Block,
	lb *consensus.LightBlock,
	epoch beacon.EpochTime,
	maxMessages uint32,
	batch transaction.RawBatch,
) ([]protocol.CheckTxResult, error) {
	if rb == nil || lb == nil {
		return nil, ErrInvalidArgument
	}

	resp, err := r.Call(ctx, &protocol.Body{
		RuntimeCheckTxBatchRequest: &protocol.RuntimeCheckTxBatchRequest{
			ConsensusBlock: *lb,
			Inputs:         batch,
			Block:          *rb,
			Epoch:          epoch,
			MaxMessages:    maxMessages,
		},
	})
	switch {
	case err != nil:
		return nil, errors.WithContext(ErrInternal, err.Error())
	case resp.RuntimeCheckTxBatchResponse == nil:
		return nil, errors.WithContext(ErrInternal, "malformed runtime response")
	case len(resp.RuntimeCheckTxBatchResponse.Results) != len(batch):
		return nil, errors.WithContext(ErrInternal, "malformed runtime response: incorrect number of results")
	}
	return resp.RuntimeCheckTxBatchResponse.Results, nil
}

// Implements RichRuntime.
func (r *richRuntime) Query(
	ctx context.Context,
	rb *block.Block,
	lb *consensus.LightBlock,
	epoch beacon.EpochTime,
	maxMessages uint32,
	method string,
	args []byte,
) ([]byte, error) {
	if rb == nil {
		return nil, ErrInvalidArgument
	}

	resp, err := r.Call(ctx, &protocol.Body{
		RuntimeQueryRequest: &protocol.RuntimeQueryRequest{
			ConsensusBlock: *lb,
			Header:         rb.Header,
			Epoch:          epoch,
			MaxMessages:    maxMessages,
			Method:         method,
			Args:           args,
		},
	})
	switch {
	case err != nil:
		return nil, err
	case resp.RuntimeQueryResponse == nil:
		return nil, errors.WithContext(ErrInternal, "malformed runtime response")
	}
	return resp.RuntimeQueryResponse.Data, nil
}

func (r *richRuntime) ConsensusSync(ctx context.Context, height uint64) error {
	resp, err := r.Call(ctx, &protocol.Body{
		RuntimeConsensusSyncRequest: &protocol.RuntimeConsensusSyncRequest{
			Height: height,
		},
	})
	switch {
	case err != nil:
		return err
	case resp.RuntimeConsensusSyncResponse == nil:
		return errors.WithContext(ErrInternal, "malformed runtime response")
	}
	return nil
}

// NewRichRuntime creates a new higher-level wrapper for a given runtime. It provides additional
// convenience functions for talking with a runtime.
func NewRichRuntime(rt Runtime) RichRuntime {
	return &richRuntime{Runtime: rt}
}

// RuntimeLogger is a Writer that interprets data written to it as JSON-formatted
// runtime logs, and re-logs the messages as oasis-node logs. For example, it
// translates runtime log levels to oasis-node log levels, because the two have
// slightly different formats.
//
// It hardcodes some assumptions about the format of the runtime logs.
type RuntimeLogWrapper struct {
	// Logger for wrapper-internal info/errors.
	logger *logging.Logger
	// Loggers for the runtime, one for each module inside the runtime.
	rtLoggers map[string]*logging.Logger
	// Key-value pairs to append to each log entry.
	suffixes []interface{}
	// Buffer for accumulating incoming log entries from the runtime.
	buf []byte
}

// NewRuntimeLogWrapper creates a new RuntimeLogWrapper.
func NewRuntimeLogWrapper(logger *logging.Logger, suffixes ...interface{}) *RuntimeLogWrapper {
	return &RuntimeLogWrapper{
		logger:    logger,
		suffixes:  suffixes,
		rtLoggers: make(map[string]*logging.Logger),
	}
}

// Implements io.Writer
func (w *RuntimeLogWrapper) Write(chunk []byte) (int, error) {
	w.buf = append(w.buf, chunk...)

	// Find and process any full lines that have accumulated in the buffer.
	// We assume one line per log entry.
	for i := len(w.buf) - len(chunk); i < len(w.buf); i++ {
		if w.buf[i] == '\n' {
			w.processLogLine(w.buf[:i])
			w.buf = w.buf[i+1:]
			i = 0
		}
	}

	// Prevent the buffer from growing indefinitely in case runtime logs
	// don't contain newlines (e.g. because of unexpected log format).
	if len(w.buf) > 10_000_000 {
		w.logger.Warn("runtime log buffer is too large, dropping logs")
		w.buf = w.buf[:0]
	}

	// Always report success. Even if log lines were malformed, we processed them
	// and reported the malformedness.
	return len(chunk), nil
}

// rtLogger returns the logger for the given module, creating it if needed.
func (w *RuntimeLogWrapper) rtLogger(module string) *logging.Logger {
	if l, ok := w.rtLoggers[module]; ok {
		return l
	}
	l := logging.GetBaseLogger(module).With(w.suffixes...)
	w.rtLoggers[module] = l
	return l
}

func (w RuntimeLogWrapper) processLogLine(line []byte) {
	// Interpret line as JSON.
	var m map[string]interface{}
	if err := json.Unmarshal(line, &m); err != nil {
		w.logger.Warn("non-JSON log line from runtime", "log_line", string(line), "err", err)
		return
	}

	// Destructure JSON into key-value pairs, parse common fields.
	var kv []interface{}
	var msg string
	var level string
	var module string
	for k, v := range m {
		if k == "msg" {
			if _msg, ok := v.(string); ok {
				msg = _msg
			} else {
				w.logger.Warn("malformed log line from runtime", "log_line", string(line), "err", "msg is not a string")
				return
			}
		} else if k == "level" {
			level, _ = v.(string)
		} else if k == "module" {
			module, _ = v.(string)
			if module == "" {
				module = "runtime"
			}
			// Enforce "runtime" scope in the module name.
			if !(module == "runtime" || strings.HasPrefix(module, "runtime/")) {
				module = "runtime/" + module
			}
		} else {
			kv = append(kv, k, v)
		}
	}

	// Output the log.
	rtLogger := w.rtLogger(module)
	switch level {
	case "DEBG":
		rtLogger.Debug(msg, kv...)
	case "INFO":
		rtLogger.Info(msg, kv...)
	case "WARN":
		rtLogger.Warn(msg, kv...)
	case "ERRO":
		rtLogger.Error(msg, kv...)
	default:
		w.logger.Warn("log line from runtime has no known error level set, using INFO", "log_line", string(line))
	}
}
