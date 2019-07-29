package ekiden

import (
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/log"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
)

// LogAssertEvent returns a handler which checks whether a specific log event was
// emitted based on JSON log output.
func LogAssertEvent(event, message string) log.WatcherHandler {
	return log.AssertJSONContains(logging.LogEvent, event, message)
}

// LogAssertNotEvent returns a handler which checks whether a specific log event
// was not emitted based on JSON log output.
func LogAssertNotEvent(event, message string) log.WatcherHandler {
	return log.AssertNotJSONContains(logging.LogEvent, event, message)
}

// LogAssertTimeouts returns a handler which checks whether a timeout was
// detected based on JSON log output.
func LogAssertTimeouts() log.WatcherHandler {
	return LogAssertEvent(roothash.LogEventTimerFired, "timeout not detected")
}

// LogAssertNoTimeouts returns a handler which checks whether a timeout was
// detected based on JSON log output.
func LogAssertNoTimeouts() log.WatcherHandler {
	return LogAssertNotEvent(roothash.LogEventTimerFired, "timeout detected")
}

// LogAssertNoRoundFailures returns a handler which checks whether a round failure
// was detected based on JSON log output.
func LogAssertNoRoundFailures() log.WatcherHandler {
	return LogAssertNotEvent(roothash.LogEventRoundFailed, "round failure detected")
}

// LogAssertComputeDiscrepancyDetected returns a handler which checks whether a
// compute discrepancy was detected based on JSON log output.
func LogAssertComputeDiscrepancyDetected() log.WatcherHandler {
	return LogAssertEvent(roothash.LogEventComputeDiscrepancyDetected, "compute discrepancy not detected")
}

// LogAssertNoComputeDiscrepancyDetected returns a handler which checks whether a
// compute discrepancy was not detected based on JSON log output.
func LogAssertNoComputeDiscrepancyDetected() log.WatcherHandler {
	return LogAssertNotEvent(roothash.LogEventComputeDiscrepancyDetected, "compute discrepancy detected")
}

// LogAssertMergeDiscrepancyDetected returns a handler which checks whether a
// merge discrepancy was detected based on JSON log output.
func LogAssertMergeDiscrepancyDetected() log.WatcherHandler {
	return LogAssertEvent(roothash.LogEventMergeDiscrepancyDetected, "merge discrepancy not detected")
}

// LogAssertNoMergeDiscrepancyDetected returns a handler which checks whether a
// merge discrepancy was not detected based on JSON log output.
func LogAssertNoMergeDiscrepancyDetected() log.WatcherHandler {
	return LogAssertNotEvent(roothash.LogEventMergeDiscrepancyDetected, "merge discrepancy detected")
}
