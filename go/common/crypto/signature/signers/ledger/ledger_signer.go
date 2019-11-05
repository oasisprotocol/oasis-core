package ledger

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/oasislabs/ledger-go"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
)

const (
	ETH_CLA        byte = 0xE0
	ETH_INS_CONFIG byte = 0x06
	ETH_INS_DERIVE byte = 0x02
	ETH_INS_SIGN   byte = 0x04
)

type Signer struct {
	device *ledger_go.Ledger
}

// NewSigner will attempt to initialize a Ledger Signer by running
// FindLedger. This will connect to the first Ledger device found.
func NewSigner() (*Signer, error) {
	device, err := ledger_go.FindLedger()
	if err != nil {
		return nil, err
	}
	return &Signer{device}, nil
}

func (s *Signer) Public() signature.PublicKey {
	derivationPath := accounts.DefaultRootDerivationPath
	path := make([]byte, 1+4*len(derivationPath))
	path[0] = byte(len(derivationPath))
	for i, component := range derivationPath {
		binary.BigEndian.PutUint32(path[1+4*i:], component)
	}

	header := []byte{ETH_CLA, ETH_INS_DERIVE, 0, 0, byte(len(path))}
	message := append(header, path...)

	response, err := s.device.Exchange(message)
	if err != nil {
		return nil
	}
	pkLength := int(response[0])
	addrLength := int(response[pkLength+1])
	return response[pkLength+2 : pkLength+2+addrLength]
}

func (s *Signer) Sign(tx []byte) ([]byte, error) {
	derivationPath := accounts.DefaultRootDerivationPath
	path := make([]byte, 1+4*len(derivationPath))
	path[0] = byte(len(derivationPath))
	for i, component := range derivationPath {
		binary.BigEndian.PutUint32(path[1+4*i:], component)
	}

	payload := append(path, tx...)
	header := []byte{ETH_CLA, ETH_INS_SIGN, 0, 0, byte(len(payload))}

	message := append(header, payload...)
	response, err := s.device.Exchange(message)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (s *Signer) ContextSign(context signature.Context, message []byte) ([]byte, error) {
	return nil, nil
}

func (s *Signer) String() string {
	return "Ledger Signer"
}

func (s *Signer) Reset() {
	s.device.Close()
}

func (s *Signer) UnsafeBytes() []byte {
	return nil
}
