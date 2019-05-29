// Package api implementes the key manager API and common data types.
package api

// InitResponse is the initialzation RPC response, returned as part of a
// SignedInitResponse from the key manager enclave.
type InitResponse struct {
	IsSecure bool   `codec:"is_secure"`
	Checksum []byte `codec:"checksum"`
}

// SignedInitResponse is the signed initialization RPC response, returned
// from the key manager enclave.
type SignedInitResponse struct {
	InitResponse InitResponse `codec:"init_response"`
	Signature    []byte       `codec:"signature"`
}
