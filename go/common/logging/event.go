package logging

// LogEvent is the structured log key used to signal log events to
// be easily parsed by the testing harness.
//
// Values should be defined as constants in the respective modules
// that emit these events.
const LogEvent = "log_event"
