package pcs

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
)

const loggerModule = "runtime/host/sgx/tests"

type fakeTime struct {
	now time.Time
}

func (ft *fakeTime) get() time.Time {
	return ft.now
}

func testStorageRoundtrip(t *testing.T, store *persistent.ServiceStore, bundle *TCBBundle) {
	require := require.New(t)
	fmspc := []byte("fmspc")

	tcbCache := newMockTcbCache(store, logging.GetLogger(loggerModule), time.Now)
	tcbCache.cache(bundle, fmspc)

	cached, _ := tcbCache.check(fmspc)
	require.EqualValues(cached, bundle, "tcbCache.check")
}

func testFMSPCInvalidation(t *testing.T, store *persistent.ServiceStore, bundle *TCBBundle) {
	require := require.New(t)
	fmspc := []byte("fmspc")
	expiryTime, err := readBundleMinTimestamp(bundle)
	require.NoError(err, "readBundleMinTimestamp")
	ft := fakeTime{
		now: expiryTime,
	}
	tcbCache := newMockTcbCache(store, logging.GetLogger(loggerModule), ft.get)

	var cached *TCBBundle
	var refresh bool

	// Cache initial and check.
	tcbCache.cache(bundle, fmspc)
	cached, refresh = tcbCache.check(fmspc)
	require.NotNil(cached, "tcbCache.check 1")
	require.False(refresh, "tcbCache.check 1")

	// Check again with bogus fmspc; shouldn't return anything
	// but should still be available.
	cached, refresh = tcbCache.check([]byte("different"))
	require.Nil(cached, "tcbCache.check 2")
	require.True(refresh, "tcbCache.check 2")

	cached, refresh = tcbCache.check(fmspc)
	require.NotNil(cached, "tcbCache.check 3")
	require.False(refresh, "tcbCache.check 3")
}

func testCheckIntervals(t *testing.T, store *persistent.ServiceStore, bundle *TCBBundle) {
	require := require.New(t)
	fmspc := []byte("fmspc")
	expiryTime, err := readBundleMinTimestamp(bundle)
	require.NoError(err, "readBundleMinTimestamp")

	timer := fakeTime{
		now: expiryTime,
	}
	tcbCache := newMockTcbCache(store, logging.GetLogger(loggerModule), timer.get)

	// Initially, always needs to be refreshed.
	cache, refresh := tcbCache.check(fmspc)
	require.Nil(cache, "tcbCache.check pre-cache")
	require.True(refresh, "tcbCache.check pre-cache")

	// Cache it, pretend it's a day before the first check will need to be performed.
	timer.now = expiryTime.Add(-(tcbCacheRefreshThreshold + 24*time.Hour))
	tcbCache.cache(bundle, fmspc)

	// An hour after the initial cache, shouldn't be refreshed.
	timer.now = timer.now.Add(time.Hour)
	cache, refresh = tcbCache.check(fmspc)
	require.NotNil(cache, "tcbCache.check 1")
	require.False(refresh, "tcbCache.check 1")

	// Another day later, we're in the slow refresh cycle. First check should refresh.
	// Advance by 25 hours, because 24 would still be within the slow refresh interval.
	timer.now = timer.now.Add(25 * time.Hour)
	cache, refresh = tcbCache.check(fmspc)
	require.NotNil(cache, "tcbCache.check 2")
	require.True(refresh, "tcbCache.check 2")
	tcbCache.cache(bundle, fmspc)

	// An hour later, don't check again.
	timer.now = timer.now.Add(time.Hour)
	cache, refresh = tcbCache.check(fmspc)
	require.NotNil(cache, "tcbCache.check 3")
	require.False(refresh, "tcbCache.check 3")

	// 22 hours later, still don't check (within slow refresh interval).
	// Two hours after that, do check.
	timer.now = timer.now.Add(22 * time.Hour)
	cache, refresh = tcbCache.check(fmspc)
	require.NotNil(cache, "tcbCache.check 4")
	require.False(refresh, "tcbCache.check 4")

	timer.now = timer.now.Add(2 * time.Hour)
	cache, refresh = tcbCache.check(fmspc)
	require.NotNil(cache, "tcbCache.check 5")
	require.True(refresh, "tcbCache.check 5")
	tcbCache.cache(bundle, fmspc)

	// After the bundle expires, check all the time.
	timer.now = expiryTime
	for i := 0; i < 4; i++ {
		cache, refresh = tcbCache.check(fmspc)
		require.NotNil(cache, "tcbCache.check loop")
		require.True(refresh, "tcbCache.check loop")
		tcbCache.cache(bundle, fmspc)
		timer.now = timer.now.Add(time.Hour)
	}
}

func TestTCBCache(t *testing.T) {
	require := require.New(t)

	// Set up the service store.
	dir, err := os.MkdirTemp("", "oasis-core-unittests")
	require.NoError(err, "os.MkdirTemp")
	defer os.RemoveAll(dir)

	common, err := persistent.NewCommonStore(dir)
	require.NoError(err, "NewCommonStore")

	store := common.GetServiceStore("persistent_test")

	// Read a sample tcb bundle.
	rawTCBInfo, err := os.ReadFile("testdata/tcb_info_v3_fmspc_00606A000000.json") // From PCS V4 response.
	require.NoError(err, "Read test vector")
	rawCerts, err := os.ReadFile("testdata/tcb_info_v3_fmspc_00606A000000_certs.pem") // From PCS V4 response (TCB-Info-Issuer-Chain header).
	require.NoError(err, "Read test vector")
	rawQEIdentity, err := os.ReadFile("testdata/qe_identity_v2.json") // From PCS V4 response.
	require.NoError(err, "Read test vector")

	var tcbInfo SignedTCBInfo
	err = json.Unmarshal(rawTCBInfo, &tcbInfo)
	require.NoError(err, "Parse TCB info")

	var qeIdentity SignedQEIdentity
	err = json.Unmarshal(rawQEIdentity, &qeIdentity)
	require.NoError(err, "Parse QE identity")

	tcbBundle := TCBBundle{
		TCBInfo:      tcbInfo,
		QEIdentity:   qeIdentity,
		Certificates: rawCerts,
	}

	for name, fun := range map[string]func(*testing.T, *persistent.ServiceStore, *TCBBundle){
		"StorageRoundtrip":  testStorageRoundtrip,
		"CheckIntervals":    testCheckIntervals,
		"FMSPCInvalidation": testFMSPCInvalidation,
	} {
		t.Run(name, func(t *testing.T) {
			fun(t, store, &tcbBundle)
			_ = store.Delete([]byte(tcbCacheKey))
		})
	}
}
