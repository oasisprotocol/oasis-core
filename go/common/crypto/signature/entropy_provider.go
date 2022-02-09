package signature

// StaticEntropyProvider is the interface implemented by signers that support providing persistent
// static entropy that is entirely independent from a keypair.
type StaticEntropyProvider interface {
	// StaticEntropy returns PrivateKeySize bytes of cryptographic entropy that/ is independent from
	// the Signer's private key.  The value of this entropy is constant for the lifespan of the
	// signer's underlying key pair.
	StaticEntropy() ([]byte, error)
}
