package signature

import (
	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
)

// BatchVerifier accumulates batch entries with Add, before performing
// batch verification with Verify.
type BatchVerifier struct {
	verifier *ed25519.BatchVerifier

	results    []error
	resultsMap map[int]int // verifier -> results mapping
	hasError   bool
}

// Reset resets a batch for reuse.
//
// Note: This method will reuse the internal entires slice to reduce memory
// reallocations.  If the next batch is known to be significantly smaller
// it may be more memory efficient to simply create a new batch.
func (v *BatchVerifier) Reset() {
	switch v.verifier {
	case nil:
		v.verifier = ed25519.NewBatchVerifier()
	default:
		v.verifier.Reset()
	}
	v.results = v.results[:0]
	v.resultsMap = make(map[int]int)
	v.hasError = false
}

// Add adds a (public key, context, message, signature) quad to the current
// batch.
//
// Note: Errors detected while preparing a entry for the validator will
// be stored in the verifier state, to be returned when the verification
// is done.
func (v *BatchVerifier) Add(
	publicKey PublicKey,
	context Context,
	message []byte,
	sig []byte,
) {
	if v.resultsMap == nil {
		v.Reset()
	}

	// In some cases we can skip doing the verification entirely, in
	// which case, we pre-emptively tag the entry as a failure, and
	// don't bother adding it to the actual batch verifier.

	pushResult := func(err error) {
		resIndex := len(v.results)
		verIndex := len(v.resultsMap)

		v.results = append(v.results, err)
		switch err {
		case nil:
			v.resultsMap[verIndex] = resIndex
		default:
			v.hasError = true
		}
	}

	if len(sig) != SignatureSize {
		pushResult(ErrMalformedSignature)
		return
	}
	if publicKey.IsBlacklisted() {
		pushResult(ErrForbiddenPublicKey)
		return
	}

	// Prepare the context using our janky domain separation.
	data, err := PrepareSignerMessage(context, message)
	if err != nil {
		pushResult(err)
		return
	}

	// Everything seems sensible, add to the verifier.
	cachingVerifier.AddWithOptions(v.verifier, publicKey[:], data, sig, defaultOptions)
	pushResult(nil)
}

// AddError adds an invalid entry to the current batch.  This is useful
// to simplify the process of creating and processing a batch.
func (v *BatchVerifier) AddError(err error) {
	if v.resultsMap == nil {
		v.Reset()
	}

	v.results = append(v.results, err)
	v.hasError = true
}

// Verify checks all entries in the current batch, returning true if all
// entries in the current batch are valid.  If one or more signature is
// invalid, the returned error vector will provide information about
// each individual entry.
func (v *BatchVerifier) Verify() (bool, []error) {
	if v.resultsMap == nil {
		v.Reset()
	}

	allOk, validSigs := v.verifier.Verify(nil)
	if !allOk {
		switch len(v.resultsMap) {
		case 0:
			// This is a false negative.  We don't always add to the batch,
			// and the batch verifier treats verifying an empty batch as
			// a failure.
			allOk = true
		default:
			// Populate the signature verification failures.
			for i, ok := range validSigs {
				if !ok {
					v.results[v.resultsMap[i]] = ErrVerifyFailed
				}
			}
		}
	}

	// Copy so that nothing bad happens on verifier reuse.
	ret := make([]error, 0, len(v.results))
	ret = append(ret, v.results...)

	return allOk && !v.hasError, ret
}

// NewBatchVerifier creates an empty BatchVerifier.
func NewBatchVerifier() *BatchVerifier {
	return &BatchVerifier{
		verifier:   ed25519.NewBatchVerifier(),
		resultsMap: make(map[int]int),
	}
}

// NewBatchVerifierWithCapacity creates an empty BatchVerifier, with
// preallocations for a pre-determined batch size hint.
func NewBatchVerifierWithCapacity(n int) *BatchVerifier {
	return &BatchVerifier{
		verifier:   ed25519.NewBatchVerifierWithCapacity(n),
		results:    make([]error, 0, n),
		resultsMap: make(map[int]int),
	}
}
