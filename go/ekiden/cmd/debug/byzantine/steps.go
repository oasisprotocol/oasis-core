package byzantine

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/file"
	memorySigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
)

const (
	defaultRuntimeIDHex = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	defaultRuntimeID signature.PublicKey
	fakeAddresses    = []node.Address{
		node.Address{
			TCPAddr: net.TCPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 11004,
			},
		},
	}
	fakeRAK             signature.Signer
	fakeCapabilitiesSGX node.Capabilities
)

func initDefaultIdentity(dataDir string) (*identity.Identity, error) {
	signerFactory := fileSigner.NewFactory(dataDir, signature.SignerNode, signature.SignerP2P, signature.SignerEntity)
	id, err := identity.LoadOrGenerate(dataDir, signerFactory)
	if err != nil {
		return nil, errors.Wrap(err, "identity LoadOrGenerate")
	}
	return id, nil
}

func init() {
	if err := defaultRuntimeID.UnmarshalHex(defaultRuntimeIDHex); err != nil {
		panic(fmt.Sprintf("default runtime ID UnmarshalHex: %+v", err))
	}
	var err error
	fakeRAK, err = memorySigner.NewFactory().Generate(signature.SignerUnknown, rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("memory signer factory Generate failed: %+v", err))
	}
	quote := make([]byte, ias.QuoteLen)
	binary.LittleEndian.PutUint16(quote[0:], 1)
	rakHash := node.RAKHash(fakeRAK.Public())
	copy(quote[ias.QuoteBodyLen+ias.OffsetReportReportData:], rakHash[:])
	fakeCapabilitiesSGX.TEE = &node.CapabilityTEE{
		Hardware: node.TEEHardwareIntelSGX,
		Attestation: cbor.Marshal(ias.AVRBundle{
			Body: json.Marshal(&ias.AttestationVerificationReport{
				Timestamp:             time.Now().UTC().Format(ias.TimestampFormat),
				ISVEnclaveQuoteStatus: ias.QuoteOK,
				ISVEnclaveQuoteBody:   quote,
			}),
			// Everything we do is simulated, and we wouldn't be able to get a real signed AVR.
		}),
		RAK: fakeRAK.Public(),
	}
}
