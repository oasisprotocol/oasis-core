package transaction

// TxnOutput is an enum that has either Success or Error defined, depending on
// the result of the transaction call.
// It is meant for deserializing CBOR of the corresponding Rust enum defined in
// runtime/src/transaction/types.rs.
type TxnOutput struct {
	// Success can be of any type.
	Success interface{}
	// Error is a string describing the error message.
	Error *string
}
