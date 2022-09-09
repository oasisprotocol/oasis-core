package byzantine

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	sgxQuote "github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
)

func initDefaultIdentity(dataDir string) (*identity.Identity, error) {
	signerRoles := append([]signature.SignerRole{signature.SignerEntity}, identity.RequiredSignerRoles...)
	signerFactory, err := fileSigner.NewFactory(dataDir, signerRoles...)
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
func initFakeCapabilitiesSGX(nodeID signature.PublicKey) (signature.Signer, *node.Capabilities, error) {
	// Get fake RAK.
	fr, err := memorySigner.NewFactory().Generate(signature.SignerUnknown, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	rakHash := node.HashRAK(fr.Public())

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

	// Generate attestation signature.
	h := node.HashAttestation(quote.Report.ReportData[:], nodeID, 1)
	attestationSig, err := signature.Sign(fr, node.AttestationSignatureContext, h)
	if err != nil {
		return nil, nil, err
	}

	// Populate TEE attribute.
	fc := node.Capabilities{}
	fc.TEE = &node.CapabilityTEE{
		Hardware: node.TEEHardwareIntelSGX,
		Attestation: cbor.Marshal(node.SGXAttestation{
			Versioned: cbor.NewVersioned(node.LatestSGXAttestationVersion),
			Quote: sgxQuote.Quote{
				IAS: &ias.AVRBundle{
					Body: body,
					// Everything we do is simulated, and we wouldn't be able to get a real signed AVR.
				},
			},
			Height:    1,
			Signature: attestationSig.Signature,
		}),
		RAK: fr.Public(),
	}

	return fr, &fc, nil
}
