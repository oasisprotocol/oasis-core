package simulator

// ParamIncr is the interface for incrementing flag parameter values for which incrementing
// makes sense.  This means int, int64, float64.  (We don't use float32.)  The ability to
// increment such values is used to iterate through the space of design parameters to evaluate
// how well the scheduling algorithm executes with different configurations.
type ParamIncr interface {
	Reset()
	HasNext() bool
	Incr()
	Key() string
}

// IntParamIncr is the concrete type implementing ParamIncr for integers.
type IntParamIncr struct {
	vp   *int
	orig int
	incr int
	end  int
	key  string
}

// Reset resets the parameter being incremented to the initial value.  This is used when, for
// example, the parameter being controlled is not in the outer-most loop.
func (ipi *IntParamIncr) Reset() {
	*ipi.vp = ipi.orig
}

// HasNext returns true when it is permissible to invoke Incr, i.e., we have not reached the
// end of iteration for this parameter value.
func (ipi *IntParamIncr) HasNext() bool {
	return *ipi.vp+ipi.incr < ipi.end
}

// Incr increments the parameter value to the next value as controlled by this iterator.
func (ipi *IntParamIncr) Incr() {
	*ipi.vp += ipi.incr
}

// Key returns a string key used to sort parametric iterators so that the sort order can be
// used to determine the order of parameter iteration (i.e., in odometric order).
func (ipi *IntParamIncr) Key() string {
	return ipi.key
}

// NewIntParamIncr creates a new ParamIncr for an int variable.
func NewIntParamIncr(vp *int, incr int, end int, k string) ParamIncr {
	return &IntParamIncr{vp: vp, orig: *vp, incr: incr, end: end, key: k}
}

// Int64ParamIncr is the concrete type implementing ParamIncr for 64-bit integers.
type Int64ParamIncr struct {
	vp   *int64
	orig int64
	incr int64
	end  int64
	key  string
}

// Reset resets the parameter being incremented to the initial value.  This is used when, for
// example, the parameter being controlled is not in the outer-most loop.
func (i64pi *Int64ParamIncr) Reset() {
	*i64pi.vp = i64pi.orig
}

// HasNext returns true when it is permissible to invoke Incr, i.e., we have not reached the
// end of iteration for this parameter value.
func (i64pi *Int64ParamIncr) HasNext() bool {
	return *i64pi.vp+i64pi.incr < i64pi.end
}

// Incr increments the parameter value to the next value as controlled by this iterator.
func (i64pi *Int64ParamIncr) Incr() {
	*i64pi.vp += i64pi.incr
}

// Key returns a string key used to sort parametric iterators so that the sort order can be
// used to determine the order of parameter iteration (i.e., in odometric order).
func (i64pi *Int64ParamIncr) Key() string {
	return i64pi.key
}

// NewInt64ParamIncr creates a new ParamIncr for an int64 variable.
func NewInt64ParamIncr(vp *int64, incr int64, end int64, k string) ParamIncr {
	return &Int64ParamIncr{vp: vp, orig: *vp, incr: incr, end: end, key: k}
}

// Float64ParamIncr is the concrete type implementing ParamIncr for 64-bit floating point values
// (IEEE-754 double precision binary floating point).
type Float64ParamIncr struct {
	vp   *float64
	orig float64
	incr float64
	end  float64
	key  string
}

// Reset resets the parameter being incremented to the initial value.  This is used when, for
// example, the parameter being controlled is not in the outer-most loop.
func (f64pi *Float64ParamIncr) Reset() {
	*f64pi.vp = f64pi.orig
}

// HasNext returns true when it is permissible to invoke Incr, i.e., we have not reached the
// end of iteration for this parameter value.
func (f64pi *Float64ParamIncr) HasNext() bool {
	return *f64pi.vp+f64pi.incr < f64pi.end
}

// Incr increments the parameter value to the next value as controlled by this iterator.
func (f64pi *Float64ParamIncr) Incr() {
	*f64pi.vp += f64pi.incr
}

// Key returns a string key used to sort parametric iterators so that the sort order can be
// used to determine the order of parameter iteration (i.e., in odometric order).
func (f64pi *Float64ParamIncr) Key() string {
	return f64pi.key
}

// NewFloat64ParamIncr creates a new ParamIncr for a float64 variable.
func NewFloat64ParamIncr(vp *float64, incr float64, end float64, k string) ParamIncr {
	return &Float64ParamIncr{vp: vp, orig: *vp, incr: incr, end: end, key: k}
}
