// Package api defines the governance application API for other applications.
package api

type messageKind uint8

// MessageChangeParameters is the message kind for when the change parameters proposal closes
// as accepted. The message is the change parameters proposal.
var MessageChangeParameters = messageKind(0)

// MessageValidateParameterChanges is the message kind for when the change parameters proposal's
// changes should be validated. The message is the change parameters proposal. Consensus module
// to which changes should be applied should respond with an empty struct if validation is
// successful and with error otherwise. Other modules should ignore the message and return a nil
// response.
var MessageValidateParameterChanges = messageKind(1)
