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
	signerPub := s.signer.Public()
	pubKey, err := libp2pCrypto.UnmarshalEd25519PublicKey(signerPub[:])
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
