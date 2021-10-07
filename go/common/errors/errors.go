// Package errors implements errors that can be easily sent across the
// wire and reconstructed at the other end.
package errors

import (
	"errors"
	"fmt"
	"strings"
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

type codedErrorWithContext struct {
	err     error
	context string
}

func (e *codedErrorWithContext) Error() string {
	return fmt.Sprintf("%v: %s", e.err, e.context)
}

func (e *codedErrorWithContext) Unwrap() error {
	return e.err
}

// WithContext creates a wrapped error that provides additional context.
func WithContext(err error, context string) error {
	if len(context) == 0 {
		return err
	}

	return &codedErrorWithContext{
		err:     err,
		context: context,
	}
}

// Context returns the additional context associated with the error.
func Context(err error) string {
	if err == nil {
		return ""
	}

	var cec *codedErrorWithContext
	if As(err, &cec) {
		return cec.context
	}
	return ""
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
// In case an error cannot be resolved, this method returns a new
// error with its message equal to the passed message string.
func FromCode(module string, code uint32, message string) error {
	e, exists := registeredErrors.Load(errorKey(module, code))
	if !exists || e == errUnknownError {
		return &codedError{
			module: module,
			code:   code,
			msg:    message,
		}
	}
	err := e.(error)

	if message == err.Error() {
		// No added context, return exactly this error.
		return err
	}

	// Message contains the coded message and the context. Extract only the context.
	prefix := fmt.Sprintf("%v: ", err)
	context := strings.TrimPrefix(message, prefix)

	return WithContext(err.(*codedError), context)
}

// Code returns the module and code for the given error.
//
// In case the error is not of the correct type, default values
// for an unknown error are returned.
//
// In case the error is nil, an empty module name and CodeNoError
// are returned.
func Code(err error) (string, uint32) {
	if err == nil {
		return "", CodeNoError
	}

	var ce *codedError
	if !As(err, &ce) {
		ce = errUnknownError.(*codedError)
	}

	return ce.module, ce.code
}

func errorKey(module string, code uint32) string {
	return fmt.Sprintf("%s-%d", module, code)
}
