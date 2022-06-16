package sgx

// VerifiedQuote is an extract from a remote attestation quote that has undergone verification.
type VerifiedQuote struct {
	ReportData []byte
	Identity   EnclaveIdentity
}
