package node

import (
	"encoding/hex"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
)

func TestSGXConstraintsV0(t *testing.T) {
	require := require.New(t)

	raw, err := ioutil.ReadFile("testdata/sgx_constraints_v0.bin")
	require.NoError(err, "Read test vector")

	var sc SGXConstraints
	err = cbor.Unmarshal(raw, &sc)
	require.NoError(err, "Decode V0 SGX constraints")

	err = sc.ValidateBasic(nil)
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
	err = sc.ValidateBasic(nil)
	require.Error(err, "ValidateBasic V1 SGX constraints without PCS support")
	err = sc.ValidateBasic(&TEEFeatures{})
	require.Error(err, "ValidateBasic V1 SGX constraints without PCS support")
	err = sc.ValidateBasic(&TEEFeatures{SGX: TEEFeaturesSGX{PCS: true}})
	require.NoError(err, "ValidateBasic V1 SGX constraints")
}

func TestSGXAttestationV0(t *testing.T) {
	require := require.New(t)

	raw, err := ioutil.ReadFile("testdata/sgx_attestation_v0.bin")
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

	raw, err := ioutil.ReadFile("testdata/sgx_attestation_v1.bin")
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
	h := HashAttestation([]byte("foo bar"), nodeID, 42)
	hHex := hex.EncodeToString(h)
	require.EqualValues("0f01a5084bbf432427873cbce5f8c3bff76bc22b9d1e0674b852e43698abb195", hHex)
}

func FuzzSGXConstraints(f *testing.F) {
	// Add some V0 constraints.
	raw, err := ioutil.ReadFile("testdata/sgx_constraints_v0.bin")
	require.NoError(f, err)
	f.Add(raw)
	// Add some V1 constraints.
	raw, err = ioutil.ReadFile("testdata/sgx_constraints_v1.bin")
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
	raw, err := ioutil.ReadFile("testdata/sgx_attestation_v0.bin")
	require.NoError(f, err)
	f.Add(raw)
	// Add some V1 attestations.
	raw, err = ioutil.ReadFile("testdata/sgx_attestation_v1.bin")
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
