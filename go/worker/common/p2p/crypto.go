package p2p

import (
	"errors"

	libp2pCrypto "github.com/libp2p/go-libp2p-core/crypto"
	libp2pCryptoPb "github.com/libp2p/go-libp2p-core/crypto/pb"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
)

var errCryptoNotSupported = errors.New("worker/common/p2p: crypto op not supported")

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
	return nil, errCryptoNotSupported
}

func (s *p2pSigner) Type() libp2pCryptoPb.KeyType {
	return libp2pCryptoPb.KeyType_Ed25519
}

func (s *p2pSigner) Sign(msg []byte) ([]byte, error) {
	return s.signer.Sign(msg)
}

func (s *p2pSigner) GetPublic() libp2pCrypto.PubKey {
	pubKey, err := publicKeyToPubKey(s.signer.Public())
	if err != nil {
		panic(err)
	}

	return pubKey
}

func signerToPrivKey(signer signature.Signer) libp2pCrypto.PrivKey {
	return &p2pSigner{
		signer: signer,
	}
}

func pubKeyToPublicKey(pubKey libp2pCrypto.PubKey) (signature.PublicKey, error) {
	if pubKey.Type() != libp2pCrypto.Ed25519 {
		return nil, errCryptoNotSupported
	}

	raw, err := pubKey.Raw()
	if err != nil {
		return nil, err
	}

	var pk signature.PublicKey
	if err = pk.UnmarshalBinary(raw); err != nil {
		return nil, err
	}

	return pk, nil
}

func publicKeyToPubKey(pk signature.PublicKey) (libp2pCrypto.PubKey, error) {
	pubKey, err := libp2pCrypto.UnmarshalEd25519PublicKey(pk[:])
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}
