package api

import (
	"errors"
	"fmt"
	"reflect"
)

type errorUnavailableState struct {
	inner error
}

func (e *errorUnavailableState) Error() string {
	return fmt.Sprintf("unavailable/corrupted state: %s", e.inner.Error())
}

func (e *errorUnavailableState) Unwrap() error {
	return e.inner
}

func (e *errorUnavailableState) Is(err error) bool {
	_, is := err.(*errorUnavailableState)
	return is
}

// UnavailableStateError wraps an error in an unavailable state error.
func UnavailableStateError(err error) error {
	if err == nil {
		return nil
	}
	if v := reflect.ValueOf(err); v.Kind() == reflect.Ptr && v.IsNil() {
		return nil
	}
	return &errorUnavailableState{err}
}

// IsUnavailableStateError returns true if any error in err's chain is an unavailable state error.
func IsUnavailableStateError(err error) bool {
	return errors.Is(err, &errorUnavailableState{})
}
