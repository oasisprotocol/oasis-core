package transaction

// NOTE: These types must be synchronized with runtime/src/transaction/types.rs.

// TxnCall is a transaction call.
type TxnCall struct {
	// Method is the called method name.
	Method string `codec:"method"`
	// Args are the method arguments.
	Args interface{} `codec:"args"`
}

// TxnOutput is a transaction call output.
type TxnOutput struct {
	// Success can be of any type.
	Success interface{}
	// Error is a string describing the error message.
	Error *string
}

// TxnCheckResult is the result of a successful CheckTx call.
type TxnCheckResult struct {
	// PredictedReadWriteSet is the predicted read/write set.
	PredictedReadWriteSet ReadWriteSet `codec:"predicted_rw_set"`
}
