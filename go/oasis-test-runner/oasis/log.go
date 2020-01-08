package oasis

import (
	"github.com/oasislabs/oasis-core/go/common/logging"
	tendermint "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/log"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
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

// LogAssertMergeDiscrepancyDetected returns a handler which checks whether a
// merge discrepancy was detected based on JSON log output.
func LogAssertMergeDiscrepancyDetected() log.WatcherHandlerFactory {
	return LogAssertEvent(roothash.LogEventMergeDiscrepancyDetected, "merge discrepancy not detected")
}

// LogAssertNoMergeDiscrepancyDetected returns a handler which checks whether a
// merge discrepancy was not detected based on JSON log output.
func LogAssertNoMergeDiscrepancyDetected() log.WatcherHandlerFactory {
	return LogAssertNotEvent(roothash.LogEventMergeDiscrepancyDetected, "merge discrepancy detected")
}

// LogAssertPeerExchangeDisabled returns a handler which checks whether a peer
// exchange disabled event was detected based on JSON log output.
func LogAssertPeerExchangeDisabled() log.WatcherHandlerFactory {
	return LogAssertEvent(tendermint.LogEventPeerExchangeDisabled, "peer exchange not disabled")
}
