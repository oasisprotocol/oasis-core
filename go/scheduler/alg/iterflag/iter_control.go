package iterflag

import (
	"fmt"
)

// IterControl is the interface for incrementing flag parameter values for which incrementing makes
// sense.  This means int, int64, float64.  (We don't use float32.)  The ability to increment
// such values is used to iterate through the space of simulation parameters.
type IterControl interface {
	Reset()
	AtStart() bool
	HasNext() bool
	WillIterate() bool
	Incr()
	Key() string
	Value(colWidth, precision int) string
	// Displays the current value as string; we do not use String() since Stringer
	// interface expect something that represents the "whole" object (end/incr)
	Parse(input string) error
	String() string
	// To output for reproducible simulations: fmt.Printf("-%s=%s", ic.Key(), ic.String())
}

// TODO(bsy) consider multiplicative controls, e.g., start:end:*mul to iterate through the
// values start, start * mul, start * mul^2, ..., i.e., start * mul^k, with mul > 0 and
// math.Signbit(start)=math.Signbit(end) (for float64).  This is obviously easily simulated
// using additive iteration control that iterates through the exponent values, but a
// multiplicative control might be easier to use.

// IntIterControl is the concrete type implementing IterControl for integers.
type IntIterControl struct {
	vp    *int
	key   string
	start int
	end   int
	incr  int
}

// Reset resets the parameter being incremented to the initial value.  This is used when, for
// example, the parameter being controlled is not in the outer-most loop.
func (iic *IntIterControl) Reset() {
	*iic.vp = iic.start
}

// AtStart return true if the control is at the starting value
func (iic *IntIterControl) AtStart() bool {
	return *iic.vp == iic.start
}

// HasNext returns true when it is permissible to invoke Incr, i.e., we have not reached the
// end of iteration for this parameter value.
func (iic *IntIterControl) HasNext() bool {
	if iic.incr == 0 {
		return false
	} else if iic.incr > 0 {
		return *iic.vp+iic.incr < iic.end
	} else {
		return *iic.vp+iic.incr > iic.end
	}
}

// WillIterate returns true if the control thinks it will try to iterate the value, e.g., the
// default value or the flag-supplied value is not a singleton.  It does not, however,
// guarantee iteration, e.g., if the step is larger than the difference between the start and
// end values.
func (iic *IntIterControl) WillIterate() bool {
	return iic.incr != 0
}

// Incr increments the parameter value to the next value as controlled by this iterator.
func (iic *IntIterControl) Incr() {
	*iic.vp += iic.incr
}

// Key returns a string key used to sort parametric iterators so that the sort order can be
// used to determine the order of parameter iteration (i.e., in odometric order).
func (iic *IntIterControl) Key() string {
	return iic.key
}

// Value returns the current parameter value as a string. This enables tabular printing
// of parameter values with the result(s).
func (iic IntIterControl) Value(colWidth, precision int) string {
	return fmt.Sprintf("%*d", colWidth, *iic.vp)
}

// String returns a string representation of the iteration control.  The flag name is not
// included.
func (iic IntIterControl) String() string {
	return fmt.Sprintf("%d:%d:%d", iic.start, iic.end, iic.incr)
}

// Parse decodes a string representing an IntIterControl and sets the internal state
// accordingly. A non-nil error is returned if there is a parsing error.  There are two input
// formats accepted: %d:%d:%d or %d.  The first form is the triple start:end:incr.  The latter
// is just the start value, with end=start and incr=0, i.e., the value will not change.
func (iic *IntIterControl) Parse(input string) error {
	var start, end, incr int
	// Note that Sscanf is "loose" in that extraneous characters after the last %d are ignored.
	scanned, err := fmt.Sscanf(input, "%d:%d:%d", &start, &end, &incr)
	if err == nil && scanned == 3 {
		if (start < end && incr < 0) || (start > end && incr > 0) {
			incr = 0
		}
		iic.start = start
		iic.end = end
		iic.incr = incr
		return nil
	}
	scanned, err = fmt.Sscanf(input, "%d", &start)
	if err != nil {
		return err
	}
	if scanned == 1 {
		iic.start = start
		iic.end = start
		iic.incr = 0
		return nil
	}
	return fmt.Errorf("cannot parse int IterControl range spec: '%s'", input)
}

// NewIntIterControl creates a new IterControl for an int variable.
func NewIntIterControl(vp *int, key string, start, end, incr int) IterControl {
	if (start < end && incr < 0) || (start > end && incr > 0) {
		incr = 0
	}
	return &IntIterControl{vp: vp, key: key, start: start, end: end, incr: incr}
}

// Int64IterControl is the concrete type implementing IterControl for 64-bit integers.
type Int64IterControl struct {
	vp    *int64
	key   string
	start int64
	end   int64
	incr  int64
}

// Reset resets the parameter being incremented to the initial value.  This is used when, for
// example, the parameter being controlled is not in the outer-most loop.
func (i64ic *Int64IterControl) Reset() {
	*i64ic.vp = i64ic.start
}

// AtStart return true if the control is at the starting value
func (i64ic *Int64IterControl) AtStart() bool {
	return *i64ic.vp == i64ic.start
}

// HasNext returns true when it is permissible to invoke Incr, i.e., we have not reached the
// end of iteration for this parameter value.
func (i64ic *Int64IterControl) HasNext() bool {
	if i64ic.incr == 0 {
		return false
	} else if i64ic.incr > 0 {
		return *i64ic.vp+i64ic.incr < i64ic.end
	} else {
		return *i64ic.vp+i64ic.incr > i64ic.end
	}
}

// WillIterate returns true if the control thinks it will try to iterate the value, e.g., the
// default value or the flag-supplied value is not a singleton.  It does not, however,
// guarantee iteration, e.g., if the step is larger than the difference between the start and
// end values.
func (i64ic *Int64IterControl) WillIterate() bool {
	return i64ic.incr != 0
}

// Incr increments the parameter value to the next value as controlled by this iterator.
func (i64ic *Int64IterControl) Incr() {
	*i64ic.vp += i64ic.incr
}

// Key returns a string key used to sort parametric iterators so that the sort order can be
// used to determine the order of parameter iteration (i.e., in odometric order).
func (i64ic *Int64IterControl) Key() string {
	return i64ic.key
}

// Value returns the current parameter value as a string. This enables tabular printing
// of parameter values with the result(s).
func (i64ic Int64IterControl) Value(colWidth, precision int) string {
	return fmt.Sprintf("%*d", colWidth, *i64ic.vp)
}

// String returns a string representation of the iteration control.  The flag name is not
// included.
func (i64ic Int64IterControl) String() string {
	return fmt.Sprintf("%d:%d:%d", i64ic.start, i64ic.end, i64ic.incr)
}

// Parse decodes a string representing an IntIterControl and sets the internal state
// accordingly. A non-nil error is returned if there is a parsing error.  There are two input
// formats accepted: %d:%d:%d or %d.  The first form is the triple start:end:incr.  The latter
// is just the start value, with end=start and incr=0, i.e., the value will not change.
func (i64ic *Int64IterControl) Parse(input string) error {
	var start, end, incr int64
	// Note that Sscanf is "loose" in that extraneous characters after the last %d are ignored.
	scanned, err := fmt.Sscanf(input, "%d:%d:%d", &start, &end, &incr)
	if err == nil && scanned == 3 {
		if (start < end && incr < 0) || (start > end && incr > 0) {
			incr = 0
		}
		i64ic.start = start
		i64ic.end = end
		i64ic.incr = incr
		return nil
	}
	scanned, err = fmt.Sscanf(input, "%d", &start)
	if err != nil {
		return err
	}
	if scanned == 1 {
		i64ic.start = start
		i64ic.end = start
		i64ic.incr = 0
		return nil
	}
	return fmt.Errorf("cannot parse int64 IterControl range spec: '%s'", input)
}

// NewInt64IterControl creates a new IterControl for an int64 variable.
func NewInt64IterControl(vp *int64, key string, start, end, incr int64) IterControl {
	if (start < end && incr < 0) || (start > end && incr > 0) {
		incr = 0
	}
	return &Int64IterControl{vp: vp, key: key, start: start, end: end, incr: incr}
}

// Float64IterControl is the concrete type implementing IterControl for 64-bit floating point
// values (IEEE-754 double precision binary floating point).
type Float64IterControl struct {
	vp    *float64
	key   string
	start float64
	end   float64
	incr  float64
}

// Reset resets the parameter being incremented to the initial value.  This is used when, for
// example, the parameter being controlled is not in the outer-most loop.
func (f64ic *Float64IterControl) Reset() {
	*f64ic.vp = f64ic.start
}

// AtStart return true if the control is at the starting value
func (f64ic *Float64IterControl) AtStart() bool {
	return *f64ic.vp == f64ic.start
}

// HasNext returns true when it is permissible to invoke Incr, i.e., we have not reached the
// end of iteration for this parameter value.
func (f64ic *Float64IterControl) HasNext() bool {
	// NB: negative zero in IEEE754 will compare equal to zero.
	if f64ic.incr == 0.0 {
		return false
	} else if f64ic.incr > 0.0 {
		return *f64ic.vp+f64ic.incr < f64ic.end
	} else {
		return *f64ic.vp+f64ic.incr > f64ic.end
	}

}

// WillIterate returns true if the control thinks it will try to iterate the value, e.g., the
// default value or the flag-supplied value is not a singleton.  It does not, however,
// guarantee iteration, e.g., if the step is larger than the difference between the start and
// end values.
func (f64ic *Float64IterControl) WillIterate() bool {
	return f64ic.incr != 0.0
}

// Incr increments the parameter value to the next value as controlled by this iterator.
func (f64ic *Float64IterControl) Incr() {
	*f64ic.vp += f64ic.incr
}

// Key returns a string key used to sort parametric iterators so that the sort order can be
// used to determine the order of parameter iteration (i.e., in odometric order).
func (f64ic *Float64IterControl) Key() string {
	return f64ic.key
}

// Value returns the current parameter value as a string. This enables tabular printing
// of parameter values with the result(s).
func (f64ic Float64IterControl) Value(colWidth, precision int) string {
	return fmt.Sprintf("%*.*g", colWidth, precision, *f64ic.vp)
}

// String returns a string representation of the iteration control.  The flag name is not
// included.
func (f64ic Float64IterControl) String() string {
	return fmt.Sprintf("%g:%g:%g", f64ic.start, f64ic.end, f64ic.incr)
}

// Parse decodes a string representing an IntIterControl and sets the internal state
// accordingly. A non-nil error is returned if there is a parsing error.  There are two input
// formats accepted: %d:%d:%d or %d.  The first form is the triple start:end:incr.  The latter
// is just the start value, with end=start and incr=0, i.e., the value will not change.
func (f64ic *Float64IterControl) Parse(input string) error {
	var start, end, incr float64
	// Note that Sscanf is "loose" in that extraneous characters after the last %d are ignored.
	scanned, err := fmt.Sscanf(input, "%g:%g:%g", &start, &end, &incr)
	if err == nil && scanned == 3 {
		if (start < end && incr < 0) || (start > end && incr > 0) {
			incr = 0.0
		}
		f64ic.start = start
		f64ic.end = end
		f64ic.incr = incr
		return nil
	}
	scanned, err = fmt.Sscanf(input, "%g", &start)
	if err != nil {
		return err
	}
	if scanned == 1 {
		f64ic.start = start
		f64ic.end = start
		f64ic.incr = 0.0
		return nil
	}
	return fmt.Errorf("cannot parse float64 IterControl range spec: '%s'", input)
}

// NewFloat64IterControl creates a new IterControl for a float64 variable.
func NewFloat64IterControl(vp *float64, key string, start, end, incr float64) IterControl {
	if (start < end && incr < 0.0) || (start > end && incr > 0.0) {
		incr = 0.0
	}
	return &Float64IterControl{vp: vp, key: key, start: start, end: end, incr: incr}
}
