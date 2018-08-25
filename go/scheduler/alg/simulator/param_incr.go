package simulator

type ParamIncr interface {
	Reset()
	HasNext() bool
	Incr()
	Key() string
}

type IntParamIncr struct {
	vp *int
	orig int
	incr int
	end int
	key string
}

func (ipi *IntParamIncr) Reset() {
	*ipi.vp = ipi.orig
}

func (ipi *IntParamIncr) HasNext() bool {
	return *ipi.vp + ipi.incr < ipi.end
}

func (ipi *IntParamIncr) Incr() {
	*ipi.vp += ipi.incr
}

func (ipi *IntParamIncr) Key() string {
	return ipi.key
}

func NewIntParamIncr(vp *int, incr int, end int, k string) ParamIncr {
	return &IntParamIncr{ vp: vp, orig: *vp, incr: incr, end: end, key: k }
}

type Int64ParamIncr struct {
	vp *int64
	orig int64
	incr int64
	end int64
	key string
}

func (i64pi *Int64ParamIncr) Reset() {
	*i64pi.vp = i64pi.orig
}

func (i64pi *Int64ParamIncr) HasNext() bool {
	return *i64pi.vp + i64pi.incr < i64pi.end
}

func (i64pi *Int64ParamIncr) Incr() {
	*i64pi.vp += i64pi.incr
}

func (i64pi *Int64ParamIncr) Key() string {
	return i64pi.key
}

func NewInt64ParamIncr(vp *int64, incr int64, end int64, k string) ParamIncr {
	return &Int64ParamIncr{ vp: vp, orig: *vp, incr: incr, end: end, key: k }
}

type Float64ParamIncr struct {
	vp *float64
	orig float64
	incr float64
	end float64
	key string
}

func (f64pi *Float64ParamIncr) Reset() {
	*f64pi.vp = f64pi.orig
}

func (f64pi *Float64ParamIncr) HasNext() bool {
	return *f64pi.vp + f64pi.incr < f64pi.end
}

func (f64pi *Float64ParamIncr) Incr() {
	*f64pi.vp += f64pi.incr
}

func (f64pi *Float64ParamIncr) Key() string {
	return f64pi.key
}

func NewFloat64ParamIncr(vp *float64, incr float64, end float64, k string) ParamIncr {
	return &Float64ParamIncr{ vp: vp, orig: *vp, incr: incr, end: end, key: k }
}
