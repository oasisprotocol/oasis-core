package pcs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
)

// serviceStoreName is the service name for the common store to use for SGX-related persistent data.
const serviceStoreName = "runtime_host_sgx"

// QuoteService is a service for resolving raw quotes into quote bundles that include all of the
// needed collateral.
type QuoteService interface {
	// ResolveQuote resolves a given raw quote into a full bundle with the required collateral.
	ResolveQuote(ctx context.Context, rawQuote []byte, quotePolicy *QuotePolicy) (*QuoteBundle, error)
}

type cachingQuoteService struct {
	client Client
	cache  *tcbCache
	logger *logging.Logger
}

// NewCachingQuoteService creates a new caching quote service.
func NewCachingQuoteService(
	client Client,
	store *persistent.CommonStore,
) QuoteService {
	serviceStore := store.GetServiceStore(serviceStoreName)
	logger := logging.GetLogger("common/sgx/pcs/cqs")

	return &cachingQuoteService{
		client: client,
		cache:  newTcbCache(serviceStore, logger),
		logger: logger,
	}
}

func (qs *cachingQuoteService) verifyBundle(quote Quote, quotePolicy *QuotePolicy, tcbBundle *TCBBundle, which string) error {
	if tcbBundle == nil {
		return fmt.Errorf("nil bundle is not valid")
	}
	_, err := quote.Verify(quotePolicy, time.Now(), tcbBundle)
	var tcbErr *TCBOutOfDateError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &tcbErr):
		qs.logger.Error("TCB is not up to date",
			"which", which,
			"kind", tcbErr.Kind,
			"tcb_status", tcbErr.Status.String(),
			"advisory_ids", tcbErr.AdvisoryIDs,
		)
		return tcbErr
	default:
		return fmt.Errorf("quote verification failed (%s bundle): %w", which, err)
	}
}

func (qs *cachingQuoteService) ResolveQuote(ctx context.Context, rawQuote []byte, quotePolicy *QuotePolicy) (*QuoteBundle, error) {
	var quote Quote
	size, err := quote.UnmarshalBinaryWithTrailing(rawQuote, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse quote: %w", err)
	}

	// Check what information we need to retrieve based on what is in the quote.
	sig, ok := quote.Signature().(*QuoteSignatureECDSA_P256)
	if !ok {
		return nil, fmt.Errorf("unsupported attestation key type: %s", sig.AttestationKeyType())
	}

	switch sig.CertificationData().(type) {
	case *CertificationData_PCKCertificateChain:
		// We have a PCK certificate chain and so are good to go.
	case *CertificationData_PPID:
		// We have a PPID, need to retrieve PCK certificate first.
		// TODO: Fetch PCK certificate based on PPID and include it in the quote, replacing the
		//       PPID certification data with the PCK certificate chain certification data.
		//       e.g. sp.GetPCKCertificateChain(ctx, nil, data.PPID, data.CPUSVN, data.PCESVN, data.PCEID)
		//
		//	 Due to aesmd QuoteEx APIs not supporting certification data this currently
		//       cannot be easily implemented. Instead we rely on a quote provider to be installed.
		return nil, fmt.Errorf("PPID certification data not yet supported; please install a quote provider")
	default:
		return nil, fmt.Errorf("unsupported certification data type: %s", sig.CertificationData().CertificationDataType())
	}

	// Verify PCK certificate and extract the information required to get the TCB bundle.
	pckInfo, err := sig.VerifyPCK(time.Now())
	if err != nil {
		return nil, fmt.Errorf("PCK verification failed: %w", err)
	}

	// Verify the quote so we can catch errors early (the runtime and later consensus layer will
	// also do their own verification).
	// Check bundles in order: fresh first, then cached, then try downloading again if there was
	// no scheduled refresh this time.
	getTcbBundle := func(update UpdateType) (*TCBBundle, error) {
		var fresh *TCBBundle

		cached, refresh := qs.cache.check(pckInfo.FMSPC)
		if refresh {
			if fresh, err = qs.client.GetTCBBundle(ctx, quote.Header().TeeType(), pckInfo.FMSPC, update); err != nil {
				qs.logger.Warn("error downloading TCB refresh",
					"err", err,
					"update", update,
				)
			}
			if err = qs.verifyBundle(quote, quotePolicy, fresh, "fresh"); err == nil {
				qs.cache.cache(fresh, pckInfo.FMSPC)
				return fresh, nil
			}
			qs.logger.Warn("error verifying downloaded TCB refresh",
				"err", err,
				"update", update,
			)
		}

		if err = qs.verifyBundle(quote, quotePolicy, cached, "cached"); err == nil {
			return cached, nil
		}

		// If downloaded already, don't try again but just return the last error.
		if refresh {
			qs.logger.Warn("error verifying cached TCB",
				"err", err,
				"update", update,
			)
			return nil, fmt.Errorf("both fresh and cached TCB bundles failed verification, cached error: %w", err)
		}

		// If not downloaded yet this time round, try forcing. Any errors are fatal.
		if fresh, err = qs.client.GetTCBBundle(ctx, quote.Header().TeeType(), pckInfo.FMSPC, update); err != nil {
			qs.logger.Warn("error downloading TCB",
				"err", err,
				"update", update,
			)
			return nil, err
		}
		if err = qs.verifyBundle(quote, quotePolicy, fresh, "downloaded"); err != nil {
			return nil, err
		}
		qs.cache.cache(fresh, pckInfo.FMSPC)
		return fresh, nil
	}
	var tcbBundle *TCBBundle
	for _, update := range []UpdateType{UpdateEarly, UpdateStandard} {
		if tcbBundle, err = getTcbBundle(update); err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}

	// Prepare quote structure.
	return &QuoteBundle{
		Quote: rawQuote[:size], // Trim quote as it may contain extra data.
		TCB:   *tcbBundle,
	}, nil
}
