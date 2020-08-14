// Package errors implements errors that can be easily sent across the
// wire and reconstructed at the other end.
package errors

import (
	"errors"
	"fmt"
	"sync"
)

const (
	// UnknownModule is the module name used when the module is unknown.
	UnknownModule = "unknown"

	// CodeNoError is the reserved "no error" code.
	CodeNoError = 0
)

var errUnknownError = New(UnknownModule, 1, "unknown error")

// Re-exports so this package can be used as a replacement for errors.
var (
	As     = errors.As
	Is     = errors.Is
	Unwrap = errors.Unwrap
)

var registeredErrors sync.Map

type codedError struct {
	module string
	code   uint32
	msg    string
}

func (e *codedError) Error() string {
	return e.msg
}

// New creates a new error.
//
// Module and code pair must be unique. If they are not, this method
// will panic.
//
// The error code must not be equal to the reserved "no error" code.
func New(module string, code uint32, msg string) error {
	if code == CodeNoError {
		panic(fmt.Errorf("error: code reserved 'no error' code: %d", CodeNoError))
	}

	e := &codedError{
		module: module,
		code:   code,
		msg:    msg,
	}

	key := errorKey(module, code)
	if prev, isRegistered := registeredErrors.Load(key); isRegistered {
		panic(fmt.Errorf("error: already registered: %s (existing: %s)", key, prev))
	}
	registeredErrors.Store(key, e)

	return e
}

// FromCode reconstructs a previously registered error from module
// and code.
//
// In case an error cannot be resolved, this method returns nil.
func FromCode(module string, code uint32) error {
	err, exists := registeredErrors.Load(errorKey(module, code))
	if !exists || err == errUnknownError {
		return nil
	}

	return err.(*codedError)
}

// Code returns the module and code for the given error.
//
// In case the error is not of the correct type, default values
// for an unknown error are returned.
func Code(err error) (string, uint32) {
	var ce *codedError
	if !As(err, &ce) {
		ce = errUnknownError.(*codedError)
	}

	return ce.module, ce.code
}

func errorKey(module string, code uint32) string {
	return fmt.Sprintf("%s-%d", module, code)
}
