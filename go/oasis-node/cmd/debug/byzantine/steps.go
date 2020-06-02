package byzantine

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
)

const (
	defaultRuntimeIDHex = "8000000000000000000000000000000000000000000000000000000000000000"
)

var (
	defaultRuntimeID common.Namespace
	fakeAddresses    = []node.Address{
		node.Address{
			TCPAddr: net.TCPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 11004,
			},
		},
	}
)

func initDefaultIdentity(dataDir string) (*identity.Identity, error) {
	signerFactory, err := fileSigner.NewFactory(dataDir, signature.SignerNode, signature.SignerP2P, signature.SignerEntity, signature.SignerConsensus)
	if err != nil {
		return nil, fmt.Errorf("identity NewFactory: %w", err)
	}
	id, err := identity.LoadOrGenerate(dataDir, signerFactory, false)
	if err != nil {
		return nil, fmt.Errorf("identity LoadOrGenerate: %w", err)
	}
	return id, nil
}

// Initializes fake CapabilitiesSGX and RAK.
// To also populate EnclaveIdentity in the Quote from
// runtime.version.fake_enclave flag, this function requires viper to be
// initialized and the flag registered first.
func initFakeCapabilitiesSGX() (signature.Signer, *node.Capabilities, error) {
	// Get fake RAK.
	fr, err := memorySigner.NewFactory().Generate(signature.SignerUnknown, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	rakHash := node.RAKHash(fr.Public())

	// Read EnclaveIdentity from cmd.
	// Requires viper to be initialized before that!
	v := viper.GetString(CfgVersionFakeEnclaveID)
	enclaveIdentity := sgx.EnclaveIdentity{}
	if v != "" {
		if err = enclaveIdentity.UnmarshalHex(v); err != nil {
			return nil, nil, err
		}
	}

	// Manage ISVEnclaveQuoteBody.
	quote := ias.Quote{
		Body: ias.Body{
			Version: 1,
		},
		Report: ias.Report{
			Attributes: sgx.Attributes{
				Flags: sgx.AttributeDebug,
			},
			MRENCLAVE: enclaveIdentity.MrEnclave,
			MRSIGNER:  enclaveIdentity.MrSigner,
		},
	}
	copy(quote.Report.ReportData[:], rakHash[:])

	quoteBinary, err := quote.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	// Manage AVRBundle's Body.
	body, _ := json.Marshal(&ias.AttestationVerificationReport{
		Version:               4,
		Timestamp:             time.Now().UTC().Format(ias.TimestampFormat),
		ISVEnclaveQuoteStatus: ias.QuoteOK,
		ISVEnclaveQuoteBody:   quoteBinary,
	})

	// Populate TEE attribute.
	fc := node.Capabilities{}
	fc.TEE = &node.CapabilityTEE{
		Hardware: node.TEEHardwareIntelSGX,
		Attestation: cbor.Marshal(ias.AVRBundle{
			Body: body,
			// Everything we do is simulated, and we wouldn't be able to get a real signed AVR.
		}),
		RAK: fr.Public(),
	}

	return fr, &fc, nil
}

func init() {
	if err := defaultRuntimeID.UnmarshalHex(defaultRuntimeIDHex); err != nil {
		panic(fmt.Sprintf("default runtime ID UnmarshalHex: %+v", err))
	}
}
