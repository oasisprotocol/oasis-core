package transaction

import "github.com/oasisprotocol/oasis-core/go/common/cbor"

// NOTE: These types must be synchronized with runtime/src/transaction/types.rs.

// TxnCall is a transaction call.
type TxnCall struct {
	// Method is the called method name.
	Method string `json:"method"`
	// Args are the method arguments.
	Args interface{} `json:"args"`
}

// TxnOutput is a transaction call output.
type TxnOutput struct {
	// Success can be of any type.
	Success cbor.RawMessage
	// Error is a string describing the error message.
	Error *string
}

// TxnCheckResult is the result of a successful CheckTx call.
type TxnCheckResult struct {
	// PredictedReadWriteSet is the predicted read/write set.
	PredictedReadWriteSet ReadWriteSet `json:"predicted_rw_set"`
}
