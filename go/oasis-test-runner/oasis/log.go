package oasis

import (
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci"
	tendermint "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
	workerStorage "github.com/oasisprotocol/oasis-core/go/worker/storage/committee"
)

// LogAssertEvent returns a handler which checks whether a specific log event was
// emitted based on JSON log output.
func LogAssertEvent(event, message string) log.WatcherHandlerFactory {
	return log.AssertJSONContains(logging.LogEvent, event, message)
}

// LogAssertNotEvent returns a handler which checks whether a specific log event
// was not emitted based on JSON log output.
func LogAssertNotEvent(event, message string) log.WatcherHandlerFactory {
	return log.AssertNotJSONContains(logging.LogEvent, event, message)
}

// LogAssertTimeouts returns a handler which checks whether a timeout was
// detected based on JSON log output.
func LogAssertTimeouts() log.WatcherHandlerFactory {
	return LogAssertEvent(roothash.LogEventTimerFired, "timeout not detected")
}

// LogAssertNoTimeouts returns a handler which checks whether a timeout was
// detected based on JSON log output.
func LogAssertNoTimeouts() log.WatcherHandlerFactory {
	return LogAssertNotEvent(roothash.LogEventTimerFired, "timeout detected")
}

// LogAssertNoRoundFailures returns a handler which checks whether a round failure
// was detected based on JSON log output.
func LogAssertNoRoundFailures() log.WatcherHandlerFactory {
	return LogAssertNotEvent(roothash.LogEventRoundFailed, "round failure detected")
}

// LogAssertRoundFailures returns a handler which ensures that a round failure
// was detected based on JSON log output.
func LogAssertRoundFailures() log.WatcherHandlerFactory {
	return LogAssertEvent(roothash.LogEventRoundFailed, "round failure not detected")
}

// LogAssertExecutionDiscrepancyDetected returns a handler which checks whether an
// execution discrepancy was detected based on JSON log output.
func LogAssertExecutionDiscrepancyDetected() log.WatcherHandlerFactory {
	return LogAssertEvent(roothash.LogEventExecutionDiscrepancyDetected, "execution discrepancy not detected")
}

// LogAssertNoExecutionDiscrepancyDetected returns a handler which checks whether an
// execution discrepancy was not detected based on JSON log output.
func LogAssertNoExecutionDiscrepancyDetected() log.WatcherHandlerFactory {
	return LogAssertNotEvent(roothash.LogEventExecutionDiscrepancyDetected, "execution discrepancy detected")
}

// LogAssertPeerExchangeDisabled returns a handler which checks whether a peer
// exchange disabled event was detected based on JSON log output.
func LogAssertPeerExchangeDisabled() log.WatcherHandlerFactory {
	return LogAssertEvent(tendermint.LogEventPeerExchangeDisabled, "peer exchange not disabled")
}

// LogAssertUpgradeIncompatibleBinary returns a handler which checks whether the binary was deemed
// incompatible with the upgrade based on JSON log output.
func LogAssertUpgradeIncompatibleBinary() log.WatcherHandlerFactory {
	return LogAssertEvent(upgrade.LogEventIncompatibleBinary, "expected binary to be incompatible")
}

// LogAssertUpgradeStartup returns a handler which checks whether a startup migration
// handler was run based on JSON log output.
func LogAssertUpgradeStartup() log.WatcherHandlerFactory {
	return LogAssertEvent(upgrade.LogEventStartupUpgrade, "expected startup upgrade did not run")
}

// LogAssertUpgradeConsensus returns a handler which checks whether a consensus migration
// handler was run based on JSON log output.
func LogAssertUpgradeConsensus() log.WatcherHandlerFactory {
	return LogAssertEvent(upgrade.LogEventConsensusUpgrade, "expected consensus upgrade did not run")
}

// LogAssertNoUpgradeStartup returns a handler which checks that no startup migration
// handler was run based on JSON log output.
func LogAssertNoUpgradeStartup() log.WatcherHandlerFactory {
	return LogAssertNotEvent(upgrade.LogEventStartupUpgrade, "unexpected startup upgrade was run")
}

// LogAssertNoUpgradeConsensus returns a handler which checks that no consensus migration
// handler was run based on JSON log output.
func LogAssertNoUpgradeConsensus() log.WatcherHandlerFactory {
	return LogAssertNotEvent(upgrade.LogEventConsensusUpgrade, "unexpected consensus upgrade was run")
}

// LogEventABCIPruneDelete returns a handler which checks whether a ABCI pruning delete
// was detected based on JSON log output.
func LogEventABCIPruneDelete() log.WatcherHandlerFactory {
	return LogAssertEvent(abci.LogEventABCIPruneDelete, "expected ABCI pruning to be done")
}

// LogEventABCIStateSyncComplete returns a handler which checks whether an ABCI state sync
// completion was detected based on JSON log output.
func LogEventABCIStateSyncComplete() log.WatcherHandlerFactory {
	return LogAssertEvent(abci.LogEventABCIStateSyncComplete, "expected ABCI state sync to complete")
}

// LogAssertRoothashRoothashReindexing returns a handler which checks whether roothash reindexing was
// run based on JSON log output.
func LogAssertRoothashRoothashReindexing() log.WatcherHandlerFactory {
	return LogAssertEvent(roothash.LogEventHistoryReindexing, "roothash runtime reindexing not detected")
}

// LogAssertCheckpointSync returns a handler which checks whether initial storage sync from
// a checkpoint was successful or not.
func LogAssertCheckpointSync() log.WatcherHandlerFactory {
	return LogAssertEvent(workerStorage.LogEventCheckpointSyncSuccess, "checkpoint sync did not succeed")
}

// LogAssertDiscrepancyMajorityFailure returns a handler which checks whether a discrepancy resolution
// resulted in MajorityFailure.
func LogAssertDiscrepancyMajorityFailure() log.WatcherHandlerFactory {
	return LogAssertEvent(commitment.LogEventDiscrepancyMajorityFailure,
		"discrepancy resolution majority failure not detected")
}
