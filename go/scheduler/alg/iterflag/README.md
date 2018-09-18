# Iterable Flags

The `iterflag` package is designed to make it easy to control
iterating a variable through a range of values via a mechanism similar
to the `flag` package.

In one particular use case, starting off with simulation code with
various simulation parameters that can be set at the command-line via
the `flag` package, we can quickly change the code to use `iterflag`
instead to automatically iterate through ranges of simulation
parameters, for example, to explore a design space.

Multiple flags can be iterated at once.  All iterations are with fixed
increments and are additive.  (NB: if we need to use multiplicative
factors, this can be coded additively via an `iterflag`-controlled
exponent for a given base.)  While the dimensionality of the space
being explored can be high, the API is the same: the code obtains an
`Iterator` object via `MakeIterator`, runs the simulation, and then
invokes the iterator's `Incr` function to move to the next point in
the iteration space.  `Incr` returns false when the iterator is done,
i.e., cannot be incremented to a next location.

A particular iteration nesting order can be specified via the
`MakeIteratorForFlags` interface, specifying the iterable flags by
name.  The flags in the strings slice parameter will be iterated in
odometric order, i.e., the last flag named will iterate from start to
finish before the next flag is incremented, then the last flag cycles
from start to finish again, etc.  If, for example, we invoked

```go
iterator := iterflag.MakeIteratorForFlags([]string{"foo", "bar", "baz"})
for {
        simulate()
        if !iterator.Incr() {
                break
        }
}
```

and used the iterator, it would be equivalent to

```go
for fooIterator := fooStart; fooIterator < fooEnd; fooIterator += fooIncr {
        for barIterator := barStart; barIterator < barEnd; barIterator += barIncr {
                for bazIterator := bazStart; bazIterator< bazEnd; bazIterator += bazIncr {
                        simulate()
                }
        }
}
```

## API

### `func IntVar`

`func IntVar(p *int, name string, start, end, incr int, usage string)`

### `func Int64Var`

`func Int64Var(p *int64, name string, start, end, incr int64, usage string)`

### `func Float64Var`

`func Float64Var(p *float64, name string, start, end, incr float64, usage string)`

Variables that should be iterable are associated with command-line
flags using `IntVar`, `Int64Var`, and `Float64Var` in the same spirit
as the `flag` package counterparts, but instead of a single default
value, we supply three values: a starting value, an ending value, and
an increment value.  Iterating down instead of up is supported: to
iterate down, the starting value should be greater than the ending
value, and the increment value should be negative.

Iterable flag values do not necessarily have to actually iterate.  To
specify that the value should _not_ iterate by default, use an `incr` value of 0.

### `func AllIterableFlags() []string`

`AllIterableFlags` return the names of all iterable flags that have
been registered.  This can be used to specify an iteration order for
`MakeIteratorForFlags` below.

### `type Iterator`

```go

type Iterator struct {
	Control []IterControl
}
```

#### `func (it *Iterator) AtStart(numIters int) bool`

`AtStart` returns `true` iff the right-most `numIters` iterating iterable flags
are at their `start` value.  Only

#### `func (it *Iterator) Incr() bool`

### `func MakeIteratorForFlags(flagName []string) (*Iterator, error)`

### `func MakeIterator() (*Iterator, error)`

### `type IterControl`

```go
type IterControl interface {
	WillIterate() bool
	Key() string
	Value(colWidth, precision int) string
	String() string
}
```

#### `func (*ic) WillIterate() bool`

`WillIterate` returns true if the iterable flag is configured to
iterate, i.e., the `incr` value is non-zero.  Note that if `start +
incr > end` holds, even though `WillIterate` returns true, the
iterable flag will only ever take on the `start` value.

#### `func (*ic) Key() string`

`Key` returns the flag name associated with the iterable variable.

#### `func (*ic) Value(colWidth, precision int) string`

`Value` returns a string representing the current value of the
iterable flag variable.  The value is converted to a string using
either `"%*d"` or `"%*.*g` format specifiers as appropriate for the
iterable variable type.

#### `func (*ic) String() string`

`String` returns a string representing the iterable flag setting,
formatted as a triple using the format `"%d:%d:%d` or `%g:%g:%g` as
appropriate for the iterable variable type.

## Example usage

```go
fooFlag int
barFlag float64
bazFlag int64

func init() {
	iterflag.IntVar(&fooFlag, "foo", 0, 10, 1, "foo controls the simulator...")
	iterflag.Float64Var(&barFlag, "bar", 1.0, 10.0, 0.1, "bar controls...")
	iterflag.Int64Var(&bazFlag, "baz", 10, 15, 1, "baz controls...")
}

func main() {
	flag.Parse()
	iterflag.Parse()

	colWidth=16
	precision=4 // for float64 values

	iterator := iterflag.MakeIterator()
	// Print varying headers
	for _, c := range iterator.Control {
		if c.WillIterate() {
			fmt.Printf("|%*s", colWidth, c.Key())
		}
	}
	fmt.Printf("|%*s|\n", colWidth, "Results")
	for {
		for _, c := range iterator.Control {
			if c.WillIterate() {
				fmt.Printf("|%*s", colWidth, c.Value(colWidth, precision))
			}
		}
		fmt.Printf("|%*.*g|\n", colWidth, precision, runSimulation())
	}
	if !iterator.Incr() {
		break
	}
}
```