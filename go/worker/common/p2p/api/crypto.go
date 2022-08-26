package api

import (
	"errors"

	libp2pCrypto "github.com/libp2p/go-libp2p/core/crypto"
	libp2pCryptoPb "github.com/libp2p/go-libp2p/core/crypto/pb"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

var (
	errCryptoNotSupported = errors.New("worker/common/p2p: crypto op not supported")

	libp2pContext = signature.NewContext("oasis-core/worker: libp2p")
)

type p2pSigner struct {
	signer signature.Signer
}

func (s *p2pSigner) Bytes() ([]byte, error) {
	return nil, errCryptoNotSupported
}

func (s *p2pSigner) Equals(other libp2pCrypto.Key) bool {
	return false
}

func (s *p2pSigner) Raw() ([]byte, error) {
	if sep, ok := s.signer.(signature.StaticEntropyProvider); ok {
		// Instead of exposing the private key material, we return persistent static entropy
		// independent from the private key. Since this is only used in the QUIC transport to
		// derive the reset key, this seems like a sensible thing to do.
		return sep.StaticEntropy()
	}
	return nil, errCryptoNotSupported
}

func (s *p2pSigner) Type() libp2pCryptoPb.KeyType {
	return libp2pCryptoPb.KeyType_Ed25519
}

func (s *p2pSigner) Sign(msg []byte) ([]byte, error) {
	return s.signer.ContextSign(libp2pContext, msg)
}

func (s *p2pSigner) GetPublic() libp2pCrypto.PubKey {
	pubKey, err := publicKeyToPubKey(s.signer.Public())
	if err != nil {
		panic(err)
	}

	return pubKey
}

// SignerToPrivKey converts a Signer to a libp2pCrypto.PrivKey.
func SignerToPrivKey(signer signature.Signer) libp2pCrypto.PrivKey {
	return &p2pSigner{
		signer: signer,
	}
}

// PubKeyToPublicKey converts a libp2pCrypto.PubKey to a PublicKey.
func PubKeyToPublicKey(pubKey libp2pCrypto.PubKey) (signature.PublicKey, error) {
	var pk signature.PublicKey
	if pubKey.Type() != libp2pCrypto.Ed25519 {
		return pk, errCryptoNotSupported
	}

	raw, err := pubKey.Raw()
	if err != nil {
		return pk, err
	}

	if err = pk.UnmarshalBinary(raw); err != nil {
		return pk, err
	}

	return pk, nil
}

func publicKeyToPubKey(pk signature.PublicKey) (libp2pCrypto.PubKey, error) {
	return &libp2pPublicKey{
		inner: pk,
	}, nil
}

type libp2pPublicKey struct {
	inner signature.PublicKey
}

func (k *libp2pPublicKey) Bytes() ([]byte, error) {
	return libp2pCrypto.MarshalPublicKey(k)
}

func (k *libp2pPublicKey) Equals(other libp2pCrypto.Key) bool {
	otherK, ok := other.(*libp2pPublicKey)
	if !ok {
		return false
	}

	return k.inner.Equal(otherK.inner)
}

func (k *libp2pPublicKey) Raw() ([]byte, error) {
	return k.inner[:], nil
}

func (k *libp2pPublicKey) Type() libp2pCryptoPb.KeyType {
	return libp2pCryptoPb.KeyType_Ed25519
}

func (k *libp2pPublicKey) Verify(data, sig []byte) (bool, error) {
	return k.inner.Verify(libp2pContext, data, sig), nil
}

func unmarshalPublicKey(data []byte) (libp2pCrypto.PubKey, error) {
	var inner signature.PublicKey
	if err := inner.UnmarshalBinary(data); err != nil {
		return nil, err
	}

	return &libp2pPublicKey{
		inner: inner,
	}, nil
}

func init() {
	libp2pCrypto.PubKeyUnmarshallers[libp2pCryptoPb.KeyType_Ed25519] = unmarshalPublicKey

	// There should be exactly 0 reasons why libp2p will ever need to
	// unmarshal a private key, as we explicitly pass in a signer.
	//
	// Ensure that it will fail.
	libp2pCrypto.PrivKeyUnmarshallers[libp2pCryptoPb.KeyType_Ed25519] = nil
}
