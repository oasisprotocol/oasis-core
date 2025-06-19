package pcs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
)

const (
	tcbBundleCacheKeyPrefix                = "tcb_bundle_cache"
	tcbEvaluationDataNumbersCacheKeyPrefix = "tcb_evaluation_data_numbers_cache"

	tcbCacheRefreshThreshold    = 14 * 24 * time.Hour
	tcbCacheSlowRefreshInterval = 24 * time.Hour
)

func tcbBundleCacheKey(teeType TeeType) []byte {
	return []byte(fmt.Sprintf("%s.%d", tcbBundleCacheKeyPrefix, teeType))
}

func tcbEvaluationDataNumbersCacheKey(teeType TeeType) []byte {
	return []byte(fmt.Sprintf("%s.%d", tcbEvaluationDataNumbersCacheKeyPrefix, teeType))
}

func readBundleMinTimestamp(bundle *TCBBundle) (time.Time, error) {
	var err error
	var info TCBInfo
	if err = json.Unmarshal(bundle.TCBInfo.TCBInfo, &info); err != nil {
		return time.Time{}, fmt.Errorf("could not unmarshal TCB bundle info: %w", err)
	}
	var bundleUpdate time.Time
	if bundleUpdate, err = time.Parse(TimestampFormat, info.NextUpdate); err != nil {
		return time.Time{}, fmt.Errorf("unreadable TCB bundle info next update timestamp: %w", err)
	}

	var identity QEIdentity
	if err = json.Unmarshal(bundle.QEIdentity.EnclaveIdentity, &identity); err != nil {
		return time.Time{}, fmt.Errorf("could not unmarshal TCB bundle QE identity: %w", err)
	}
	var identityUpdate time.Time
	if identityUpdate, err = time.Parse(TimestampFormat, identity.NextUpdate); err != nil {
		return time.Time{}, fmt.Errorf("unreadable TCB bundle QE identity next update timestamp: %w", err)
	}

	if bundleUpdate.Compare(identityUpdate) <= 0 {
		return bundleUpdate, nil
	}
	return identityUpdate, nil
}

type tcbBundleCache struct {
	Bundle         *TCBBundle `json:"bundle"`
	FMSPC          []byte     `json:"fmspc"`
	ExpectedExpiry time.Time  `json:"expected_expiry"`
	LastUpdate     time.Time  `json:"last_update"`
}

type tcbEvaluationDataNumbersCache struct {
	Numbers    []uint32  `json:"numbers"`
	LastUpdate time.Time `json:"last_update"`
}

type tcbCache struct {
	serviceStore *persistent.ServiceStore
	logger       *logging.Logger
	now          func() time.Time
}

func (tc *tcbCache) checkEvaluationDataNumbers(teeType TeeType) ([]uint32, bool) {
	var stored tcbEvaluationDataNumbersCache
	switch err := tc.serviceStore.GetCBOR(tcbEvaluationDataNumbersCacheKey(teeType), &stored); err {
	case nil:
		// No error, continues below.
	case persistent.ErrNotFound:
		// Not cached yet. Not an error, but needs refresh.
		return nil, true
	default:
		// Can't get it... an error, but we can still try downloading it.
		tc.logger.Warn("error checking common store for cached TCB evaluation data numbers",
			"err", err,
		)
		return nil, true
	}

	now := tc.now()
	delta := now.Sub(stored.LastUpdate)
	refresh := delta > tcbCacheSlowRefreshInterval
	return stored.Numbers, refresh
}

func (tc *tcbCache) cacheEvaluationDataNumbers(teeType TeeType, numbers []uint32) {
	cached := tcbEvaluationDataNumbersCache{
		Numbers:    numbers,
		LastUpdate: tc.now(),
	}
	if err := tc.serviceStore.PutCBOR(tcbEvaluationDataNumbersCacheKey(teeType), cached); err != nil {
		tc.logger.Error("could not store new TCB evaluation data numbers to cache, ignoring",
			"err", err,
		)
	}
}

func (tc *tcbCache) checkBundle(teeType TeeType, fmspc []byte) (*TCBBundle, bool) {
	var err error

	// Check if we have a copy in the local store.
	var stored tcbBundleCache
	switch err = tc.serviceStore.GetCBOR(tcbBundleCacheKey(teeType), &stored); err {
	case nil:
		// No error, continues below.
	case persistent.ErrNotFound:
		// Not cached yet. Not an error, but needs refresh.
		return nil, true
	default:
		// Can't get it... an error, but we can still try downloading it.
		tc.logger.Warn("error checking common store for cached TCB bundle",
			"err", err,
		)
		return nil, true
	}

	// Check if the needed and cached FMSPC are the same.
	// If they aren't, the bundle shouldn't be used, but leave
	// overriding to the caller.
	if !bytes.Equal(stored.FMSPC, fmspc) {
		return nil, true
	}

	refresh := func() bool {
		now := tc.now()

		// Wait for the first two weeks, then check once daily.
		// After expected expiration, check every time.
		if delta := stored.ExpectedExpiry.Sub(now); delta < tcbCacheRefreshThreshold {
			if delta < 0 || now.Sub(stored.LastUpdate) > tcbCacheSlowRefreshInterval {
				return true
			}
		}
		return false
	}()
	return stored.Bundle, refresh
}

func (tc *tcbCache) cacheBundle(teeType TeeType, tcbBundle *TCBBundle, fmspc []byte) {
	expectedExpiry, err := readBundleMinTimestamp(tcbBundle)
	if err != nil {
		tc.logger.Error("could not determine next update timestamp from TCB bundle",
			"err", err,
		)
		return
	}

	cached := tcbBundleCache{
		Bundle:         tcbBundle,
		FMSPC:          fmspc,
		ExpectedExpiry: expectedExpiry,
		LastUpdate:     tc.now(),
	}
	if err = tc.serviceStore.PutCBOR(tcbBundleCacheKey(teeType), cached); err != nil {
		tc.logger.Error("could not store new TCB bundle to cache, ignoring",
			"err", err,
		)
	}
}

func (tc *tcbCache) migrate() {
	// Migrate any old (without TEE type) cached entries.
	var stored tcbBundleCache
	switch err := tc.serviceStore.GetCBOR([]byte(tcbBundleCacheKeyPrefix), &stored); err {
	case nil:
		// No error, migrate. Any errors during migration are ignored as this is a cache.
		_ = tc.serviceStore.PutCBOR(tcbBundleCacheKey(TeeTypeSGX), stored)
		_ = tc.serviceStore.Delete([]byte(tcbBundleCacheKeyPrefix))
	default:
		// No migration needed.
	}
}

func newTcbCache(serviceStore *persistent.ServiceStore, logger *logging.Logger) *tcbCache {
	tc := &tcbCache{
		serviceStore: serviceStore,
		logger:       logger,
		now:          time.Now,
	}
	tc.migrate()
	return tc
}

func newMockTcbCache(serviceStore *persistent.ServiceStore, logger *logging.Logger, now func() time.Time) *tcbCache {
	tc := &tcbCache{
		serviceStore: serviceStore,
		logger:       logger,
		now:          now,
	}
	tc.migrate()
	return tc
}
