package sgx

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
)

var (
	// FortanixDummyMrSigner is the MRSIGNER value corresponding to the
	// dummy signing key that is used by the Fortanix Rust SGX SDK's
	// enclave-runner.
	FortanixDummyMrSigner MrSigner

	fortanixDummyKey *rsa.PrivateKey
)

// UnsafeFortanixDummyKey returns the Fortanix dummy signing key.
//
// This MUST only ever be used for launching test enclaves.
func UnsafeFortanixDummyKey() *rsa.PrivateKey {
	if !cmdFlags.DebugDontBlameOasis() {
		return nil
	}
	return fortanixDummyKey
}

// This is the "dummy" enclave signing key extracted from the
// Fortanix Rust SGX SDK's enclave-runner, converted to
// PEM format from the DER representation via:
//
//  openssl rsa -in dummy.priv.der -inform der -out /tmp/dummy.priv.pem
//
// Bug reports of any kind regarding the existence of this private
// key in the git repository (especially those sent to our bug bounty
// program) will be ignored and mercilessly mocked.
//
// Source: https://github.com/fortanix/rust-sgx/blob/master/enclave-runner/src/dummy.key
const fortanixDummyPrivateKeyPEM = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`

func init() {
	var err error
	blk, _ := pem.Decode([]byte(fortanixDummyPrivateKeyPEM))
	fortanixDummyKey, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		panic("failed to parse dummy key DER: " + err.Error())
	}

	if err = FortanixDummyMrSigner.FromPublicKey(fortanixDummyKey.Public().(*rsa.PublicKey)); err != nil {
		panic("failed to derive dummy key MrSigner: " + err.Error())
	}
}
