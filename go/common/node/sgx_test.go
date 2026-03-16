package node

import (
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
)

func TestSGXConstraintsV0(t *testing.T) {
	require := require.New(t)

	raw, err := os.ReadFile("testdata/sgx_constraints_v0.bin")
	require.NoError(err, "Read test vector")

	var sc SGXConstraints
	err = cbor.Unmarshal(raw, &sc)
	require.NoError(err, "Decode V0 SGX constraints")

	err = sc.ValidateBasic(nil, true)
	require.NoError(err, "ValidateBasic V0 SGX constraints")

	enc := cbor.Marshal(sc)
	require.EqualValues(enc, raw, "serialization should round-trip")
}

func TestSGXConstraintsV1(t *testing.T) {
	require := require.New(t)

	var mrEnclave sgx.MrEnclave
	err := mrEnclave.UnmarshalHex("9479d8eddfd7b1b700319419551dc340f688c2ef519a5e18657ecf32981dbd9e")
	require.NoError(err)
	var mrSigner sgx.MrSigner
	err = mrSigner.UnmarshalHex("4025dab7ebda1fbecc4e3637606e021214d0f41c6d0422fd378b2a8b88818459")
	require.NoError(err)

	sc := SGXConstraints{
		Versioned: cbor.NewVersioned(1),
		Enclaves: []sgx.EnclaveIdentity{
			{
				MrEnclave: mrEnclave,
				MrSigner:  mrSigner,
			},
		},
		Policy: &quote.Policy{
			IAS: &ias.QuotePolicy{},
			PCS: &pcs.QuotePolicy{
				TCBValidityPeriod:          30,
				MinTCBEvaluationDataNumber: 12,
			},
		},
	}
	err = sc.ValidateBasic(nil, true)
	require.Error(err, "ValidateBasic V1 SGX constraints without PCS support")
	err = sc.ValidateBasic(&TEEFeatures{}, true)
	require.Error(err, "ValidateBasic V1 SGX constraints without PCS support")
	err = sc.ValidateBasic(&TEEFeatures{SGX: TEEFeaturesSGX{PCS: true}}, true)
	require.NoError(err, "ValidateBasic V1 SGX constraints")
}

func TestSGXConstraintsV1NilPolicy(t *testing.T) {
	require := require.New(t)

	sc := SGXConstraints{
		Versioned: cbor.NewVersioned(1),
	}
	err := sc.ValidateBasic(&TEEFeatures{SGX: TEEFeaturesSGX{PCS: true}}, true)
	require.NoError(err, "ValidateBasic V1 SGX constraints with nil policy")
}

func TestSGXConstraintsKMAPolicyValidation(t *testing.T) {
	tests := []struct {
		name                string
		cfg                 *TEEFeatures
		isFeatureVersion261 bool
		kmaPolicy           *quote.Policy
		errContains         string
	}{
		{
			name:                "non-nil key manager access policy before 26.1 is invalid",
			cfg:                 &TEEFeatures{SGX: TEEFeaturesSGX{PCS: true}},
			isFeatureVersion261: false,
			kmaPolicy:           &quote.Policy{},
			errContains:         "policy should be nil",
		},
		{
			name:                "key manager access policy is valid",
			cfg:                 &TEEFeatures{SGX: TEEFeaturesSGX{PCS: true}},
			isFeatureVersion261: true,
			kmaPolicy:           &quote.Policy{},
		},
		{
			name:                "tdx policy in key manager access policy requires tdx feature",
			cfg:                 &TEEFeatures{SGX: TEEFeaturesSGX{PCS: true}},
			isFeatureVersion261: true,
			kmaPolicy: &quote.Policy{
				PCS: &pcs.QuotePolicy{
					TDX: &pcs.TdxQuotePolicy{},
				},
			},
			errContains: "TDX policy not supported",
		},
		{
			name:                "non-empty IAS key manager access policy not allowed",
			cfg:                 &TEEFeatures{SGX: TEEFeaturesSGX{PCS: true}},
			isFeatureVersion261: true,
			kmaPolicy: &quote.Policy{
				IAS: &ias.QuotePolicy{},
			},
			errContains: "IAS not allowed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc := SGXConstraints{
				Versioned:              cbor.NewVersioned(1),
				KeyManagerAccessPolicy: tc.kmaPolicy,
			}

			err := sc.ValidateBasic(tc.cfg, tc.isFeatureVersion261)
			if tc.errContains == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.ErrorContains(t, err, tc.errContains)
		})
	}
}

func TestSGXConstraintsResolvePolicy(t *testing.T) {
	defaultPolicy := &quote.Policy{
		PCS: &pcs.QuotePolicy{TCBValidityPeriod: 20},
	}
	kmaPolicy := &quote.Policy{
		PCS: &pcs.QuotePolicy{TCBValidityPeriod: 10},
	}

	for _, tc := range []struct {
		name         string
		useKMAPolicy bool
		kmaPolicy    *quote.Policy
		want         *quote.Policy
	}{
		{
			name:         "use default when no key manager access policy override",
			useKMAPolicy: true,
			kmaPolicy:    nil,
			want:         defaultPolicy,
		},
		{
			name:         "use key manager access policy override",
			useKMAPolicy: true,
			kmaPolicy:    kmaPolicy,
			want:         kmaPolicy,
		},
		{
			name:         "use default when key manager access policy exists but should be ignored",
			useKMAPolicy: false,
			kmaPolicy:    kmaPolicy,
			want:         defaultPolicy,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := SGXConstraints{
				Versioned:              cbor.NewVersioned(1),
				Policy:                 defaultPolicy,
				KeyManagerAccessPolicy: tc.kmaPolicy,
			}
			got := sc.ResolvePolicy(tc.useKMAPolicy)
			require.EqualValues(t, tc.want, got)
		})
	}
}

func TestSGXAttestationV0(t *testing.T) {
	require := require.New(t)

	raw, err := os.ReadFile("testdata/sgx_attestation_v0.bin")
	require.NoError(err, "Read test vector")

	var sa SGXAttestation
	err = cbor.Unmarshal(raw, &sa)
	require.NoError(err, "Decode V0 SGX attestation")

	err = sa.ValidateBasic(nil)
	require.NoError(err, "ValidateBasic V0 SGX attestation")

	enc := cbor.Marshal(sa)
	require.EqualValues(enc, raw, "serialization should round-trip")
}

func TestSGXAttestationV1(t *testing.T) {
	require := require.New(t)

	sa := SGXAttestation{
		Versioned: cbor.NewVersioned(1),
	}
	err := sa.ValidateBasic(nil)
	require.Error(err, "ValidateBasic V1 SGX attestation without PCS support")
	err = sa.ValidateBasic(&TEEFeatures{})
	require.Error(err, "ValidateBasic V1 SGX attestation without PCS support")
	err = sa.ValidateBasic(&TEEFeatures{SGX: TEEFeaturesSGX{PCS: true}})
	require.NoError(err, "ValidateBasic V1 SGX attestation")

	raw, err := os.ReadFile("testdata/sgx_attestation_v1.bin")
	require.NoError(err, "Read test vector")

	err = cbor.Unmarshal(raw, &sa)
	require.NoError(err, "Decode V1 SGX attestation")

	err = sa.ValidateBasic(nil)
	require.Error(err, "ValidateBasic V1 SGX attestation without PCS support")
	err = sa.ValidateBasic(&TEEFeatures{})
	require.Error(err, "ValidateBasic V1 SGX attestation without PCS support")
	err = sa.ValidateBasic(&TEEFeatures{SGX: TEEFeaturesSGX{PCS: true}})
	require.NoError(err, "ValidateBasic V1 SGX attestation")

	enc := cbor.Marshal(sa)
	require.EqualValues(enc, raw, "serialization should round-trip")
}

func TestHashAttestation(t *testing.T) {
	require := require.New(t)

	var nodeID signature.PublicKey
	_ = nodeID.UnmarshalHex("47aadd91516ac548decdb436fde957992610facc09ba2f850da0fe1b2be96119")

	rekRaw, _ := hex.DecodeString("7992610facc09ba2f850da0fe1b2be9611947aadd91516ac548decdb436fde95")
	var rek x25519.PublicKey
	copy(rek[:], rekRaw)

	h := HashAttestation([]byte("foo bar"), nodeID, 42, nil)
	require.EqualValues("0f01a5084bbf432427873cbce5f8c3bff76bc22b9d1e0674b852e43698abb195", hex.EncodeToString(h))

	h = HashAttestation([]byte("foo bar"), nodeID, 42, &rek)
	require.EqualValues("9a288bd33ba7a4c2eefdee68e4c08c1a34c369302ef8176a3bfdb4fedcec333e", hex.EncodeToString(h))
}

// TestKeyManagerAccessPolicySanity checks that attestation verification uses
// the stricter key manager access policy when requested and falls back to the
// default policy otherwise.
func TestKeyManagerAccessPolicySanity(t *testing.T) {
	require := require.New(t)

	pcs.SetSkipVerify()
	defer pcs.UnsetSkipVerify()

	// Build a raw SGX report (384 bytes) with a known RAK hash in ReportData.
	var rak signature.PublicKey
	rakHash := HashRAK(rak)

	var rawReport [384]byte
	copy(rawReport[320:], rakHash[:])

	mockQuote, err := pcs.NewMockQuote(rawReport[:])
	require.NoError(err, "NewMockQuote")

	sa := SGXAttestation{
		Versioned: cbor.NewVersioned(LatestSGXAttestationVersion),
		Quote: quote.Quote{
			PCS: &pcs.QuoteBundle{
				Quote: mockQuote,
			},
		},
	}

	sc := SGXConstraints{
		Versioned: cbor.NewVersioned(1),
		Enclaves:  []sgx.EnclaveIdentity{{}},
		Policy: &quote.Policy{
			PCS: &pcs.QuotePolicy{},
		},
		KeyManagerAccessPolicy: &quote.Policy{
			PCS: &pcs.QuotePolicy{Disabled: true},
		},
	}

	var nodeID signature.PublicKey
	cfg := &TEEFeatures{SGX: TEEFeaturesSGX{PCS: true}}

	err = sa.Verify(cfg, time.Now(), 0, &sc, rak, nil, nodeID)
	require.Error(err, "attestation should be rejected when key manager access policy is used")
	require.ErrorContains(err, "PCS quotes are disabled by policy")
}

func FuzzSGXConstraints(f *testing.F) {
	// Add some V0 constraints.
	raw, err := os.ReadFile("testdata/sgx_constraints_v0.bin")
	require.NoError(f, err)
	f.Add(raw)
	// Add some V1 constraints.
	raw, err = os.ReadFile("testdata/sgx_constraints_v1.bin")
	require.NoError(f, err)
	f.Add(raw)

	// Fuzz.
	f.Fuzz(func(t *testing.T, data []byte) {
		var sc SGXConstraints
		err := cbor.Unmarshal(data, &sc)
		if err != nil {
			return
		}

		enc := cbor.Marshal(sc)
		var dec SGXConstraints
		err = cbor.Unmarshal(enc, &dec)
		require.NoError(t, err, "round-trip should work")
	})
}

func FuzzSGXAttestation(f *testing.F) {
	// Add some V0 attestations.
	raw, err := os.ReadFile("testdata/sgx_attestation_v0.bin")
	require.NoError(f, err)
	f.Add(raw)
	// Add some V1 attestations.
	raw, err = os.ReadFile("testdata/sgx_attestation_v1.bin")
	require.NoError(f, err)
	f.Add(raw)

	// Fuzz.
	f.Fuzz(func(t *testing.T, data []byte) {
		var sa SGXAttestation
		err := cbor.Unmarshal(data, &sa)
		if err != nil {
			return
		}

		enc := cbor.Marshal(sa)
		var dec SGXAttestation
		err = cbor.Unmarshal(enc, &dec)
		require.NoError(t, err, "round-trip should work")
	})
}
