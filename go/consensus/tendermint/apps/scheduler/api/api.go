// Package api defines the scheduler application API for other applications.
package api

type messageKind uint8

// MessageBeforeSchedule is the message kind for before-schedule notifications.
var MessageBeforeSchedule = messageKind(0)
