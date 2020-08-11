// Package drbg implements the HMAC_DRBG construct as per NIST Special
// Publication 800-90A Revision 1.
package drbg

import (
	"crypto"
	"crypto/hmac"
	"errors"
	"math"
)

const (
	// MaxLength is the maximum length of the input entropy, personalization
	// nonce, and additional input bit strings in bytes.
	//
	// Note: SP 800-90A R1 allows 8 bits more than the value used.
	MaxLength = math.MaxUint32 // 2^35 - 8 bits.

	// ReseedInterval is the maximum number of requests that can be made
	// before a reseed operation is required.
	ReseedInterval = 1 << 48

	maxBytesPerRequest = 1 << 16 // 2^19 bits.
)

// Drbg is a keyed and initialized HMAC_DRBG instance.
//
// Note: This implementation does not support reseeding, and if the internal
// counter is exceeded, the instance will be rendered unusable.  The limit is
// sufficiently large that it will not be hit under realistic usage.
type Drbg struct {
	v             []byte
	k             []byte
	reseedCounter uint64
	hash          crypto.Hash
}

// Read reads len(p) bytes from HMAC_DRBG.  It will always succeed completely
// (n = len(p)) or not at all.  On failures, any partial reads already copied
// into p will be overwritten by NUL bytes.
//
// Note: 0 length reads are a no-op and do not advance the HMAC_DRBG state.
func (r *Drbg) Read(p []byte) (n int, err error) {
	toRead, off := len(p), 0
	for toRead > 0 {
		readSz := toRead
		if readSz > maxBytesPerRequest {
			readSz = maxBytesPerRequest
		}

		b, err := r.generate(readSz, nil)
		if err != nil {
			for i := 0; i < off; i++ {
				p[i] = 0
			}
			return 0, err
		}

		copy(p[off:], b)
		off += readSz
		toRead -= readSz
	}

	return off, nil
}

func (r *Drbg) generate(requestedNumberOfBytes int, additionalInput []byte) ([]byte, error) {
	if requestedNumberOfBytes < 0 {
		return nil, errors.New("drbg: invalid output size requested")
	}
	if requestedNumberOfBytes > maxBytesPerRequest {
		return nil, errors.New("drbg: excessive output size requested")
	}
	if len(additionalInput) > MaxLength {
		return nil, errors.New("drbg: excessive additionalInput size")
	}

	// 10.1.2.5 Generating Pseudorandom Bits Using HMAC_DRBG

	// HMAC_DRBG Generate Process:

	// 1. If reseed_counter > reseed_interval, then return an indication
	// that a reseed is required.
	if r.reseedCounter > ReseedInterval {
		return nil, errors.New("drbg: reseed required")
	}

	// 2. If additional_input != Null, then (Key, V) = HMAC_DRBG_Update
	// (additional_input, Key, V).
	if len(additionalInput) != 0 {
		r.update(additionalInput)
	}

	// 3. temp = Null.
	outLen := r.hash.Size()
	tempSize := ((requestedNumberOfBytes + outLen - 1) / outLen) * outLen
	temp := make([]byte, 0, tempSize)

	// 4. While (len (temp) < requested_number_of_bits) do:
	for len(temp) < requestedNumberOfBytes {
		// 4.1 V = HMAC (Key, V).
		r.v = updateV(r.hash, r.k, r.v)

		// 4.2 temp = temp || V.
		temp = append(temp, r.v...)
	}

	// 5. returned_bits = leftmost (temp, requested_number_of_bits).
	temp = temp[:requestedNumberOfBytes]

	// 6. (Key, V) = HMAC_DRBG_Update (additional_input, Key, V).
	r.update(additionalInput)

	// 7. reseed_counter = reseed_counter + 1.
	r.reseedCounter++

	// 8. Return (SUCCESS, returned_bits, Key, V, reseed_counter).
	return temp, nil
}

func (r *Drbg) update(providedData []byte) {
	// 10.1.2.2 The HMAC_DRBG Update Function (Update)

	// HMAC_DRBG Update Process:

	// 1. K = HMAC (K, V || 0x00 || provided_data).
	k := updateK(r.hash, r.k, r.v, providedData, 0x00)

	// 2. V = HMAC (K, V).
	v := updateV(r.hash, k, r.v)

	// 3. If (provided_data = Null), then return K and V.
	if len(providedData) == 0 {
		r.v, r.k = v, k
		return
	}

	// 4. K = HMAC (K, V || 0x01 || provided_data).
	k = updateK(r.hash, k, v, providedData, 0x01)

	// 5. V = HMAC (K, V).
	v = updateV(r.hash, k, v)

	// 6. Return (K, V).
	r.v, r.k = v, k
}

// nolint: gas
func updateK(hash crypto.Hash, k, v, providedData []byte, b byte) []byte {
	mac := hmac.New(hash.New, k)
	_, _ = mac.Write(v)
	_, _ = mac.Write([]byte{b})
	if len(providedData) > 0 {
		_, _ = mac.Write(providedData)
	}
	return mac.Sum(nil)
}

// nolint: gas
func updateV(hash crypto.Hash, k, v []byte) []byte {
	mac := hmac.New(hash.New, k)
	_, _ = mac.Write(v)
	return mac.Sum(nil)
}

// New creates a new HMAC_DRBG instance with the specified configuration.
func New(hash crypto.Hash, entropyInput, nonce, personalizationString []byte) (*Drbg, error) {
	outLen := hash.Size()
	minLen := outLen / 2
	eiLen, nonceLen, psLen := len(entropyInput), len(nonce), len(personalizationString)
	if eiLen < minLen {
		return nil, errors.New("drbg: insufficient entropyInput")
	}
	if eiLen > MaxLength {
		return nil, errors.New("drbg: excessive entropyInput size")
	}
	if nonceLen > MaxLength {
		return nil, errors.New("drbg: excessive nonce size")
	}
	if psLen > MaxLength {
		return nil, errors.New("drbg: excessive personalizationString size")
	}

	// 10.1.2.3 Instantiation of HMAC_DRBG

	// HMAC_DRBG Instantiate Process:

	// 1. seed_material = entropy_input || nonce || personalization_string.
	seedMaterial := make([]byte, 0, eiLen+nonceLen+psLen)
	seedMaterial = append(seedMaterial, entropyInput...)
	seedMaterial = append(seedMaterial, nonce...)
	seedMaterial = append(seedMaterial, personalizationString...)

	// 2. Key = 0x00 00...00. Comment: outlen bits.
	key := make([]byte, outLen)

	// 3. V = 0x01 01...01. Comment: outlen bits.
	v := make([]byte, outLen)
	for i := range v {
		v[i] = 0x01
	}

	// Comment: Update Key and V.
	rng := &Drbg{
		v:             v,
		k:             key,
		reseedCounter: 1, // 5. reseed_counter = 1.
		hash:          hash,
	}

	// 4. (Key, V) = HMAC_DRBG_Update (seed_material, Key, V).
	rng.update(seedMaterial)

	// 6. Return (V, Key, reseed_counter).
	return rng, nil
}
