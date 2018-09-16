package iterflag

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var fooFlag int
var barFlag float64
var bazFlag int64

// This test should be run WITHOUT setting these flags at the command-line.
func init() {
	IntVar(&fooFlag, "foo", 5, 7, 1, "foo controls the simulator...")
	Float64Var(&barFlag, "bar", 10.0, 10.31, 0.1, "bar controls...")
	Int64Var(&bazFlag, "baz", 10, 5, -2, "baz controls...")
}

type expectedOutput struct {
	foo                    int
	bar                    float64
	baz                    int64
	start1, start2, start3 bool
}

var goldenOutput = []expectedOutput{
	{5, 10.0, 10, true, true, true},
	{5, 10.0, 8, false, false, false},
	{5, 10.0, 6, false, false, false},
	{5, 10.1, 10, true, false, false},
	{5, 10.1, 8, false, false, false},
	{5, 10.1, 6, false, false, false},
	{5, 10.2, 10, true, false, false},
	{5, 10.2, 8, false, false, false},
	{5, 10.2, 6, false, false, false},
	{5, 10.3, 10, true, false, false},
	{5, 10.3, 8, false, false, false},
	{5, 10.3, 6, false, false, false},
	{6, 10.0, 10, true, true, false},
	{6, 10.0, 8, false, false, false},
	{6, 10.0, 6, false, false, false},
	{6, 10.1, 10, true, false, false},
	{6, 10.1, 8, false, false, false},
	{6, 10.1, 6, false, false, false},
	{6, 10.2, 10, true, false, false},
	{6, 10.2, 8, false, false, false},
	{6, 10.2, 6, false, false, false},
	{6, 10.3, 10, true, false, false},
	{6, 10.3, 8, false, false, false},
	{6, 10.3, 6, false, false, false},
}

func runSimulationAndReturnResults() float64 {
	return float64(fooFlag)*barFlag + float64(bazFlag) // silly example
}

// sym should be a single rune.
func printSeparatorSymbol(sym string, colWidth, numCol int) {
	fmt.Printf("+")
	for ix := 0; ix < numCol; ix++ {
		for jx := 0; jx < colWidth; jx++ {
			fmt.Printf("%s", sym)
		}
		fmt.Printf("+")
	}
	fmt.Printf("\n")
}

func printSeparator(colWidth, numCol int) {
	printSeparatorSymbol("-", colWidth, numCol)
}

func printSeparatorHeavy(colWidth, numCol int) {
	printSeparatorSymbol("=", colWidth, numCol)
}

func TestIterflags(t *testing.T) {
	assert := assert.New(t)
	Parse()

	colWidth := 10
	precision := 10 // for float64 values

	// printFlagValues() // flag values under control of the flag module

	it, err := MakeIterator()
	if err != nil {
		panic(err.Error())
	}

	numCol := 1 // result
	// Print invariant flags and count columns
	for ix := range it.Control {
		if !it.Control[ix].WillIterate() {
			fmt.Printf("%s: %s\n", it.Control[ix].Key(), it.Control[ix].Value(colWidth, precision))
		} else {
			numCol++
		}
	}

	// Print column header (only varying flags)
	printSeparatorHeavy(colWidth, numCol)
	for ix := range it.Control {
		if it.Control[ix].WillIterate() {
			fmt.Printf("|%*s", colWidth, it.Control[ix].Key())
		}
	}
	fmt.Printf("|%*s|\n", colWidth, "Result")
	goldenIx := 0
	for {
		if it.AtStart(2) {
			printSeparatorHeavy(colWidth, numCol)
		} else if it.AtStart(1) {
			printSeparator(colWidth, numCol)
		}
		// Print varying flag values
		var outputAsStrings []string
		for ix := range it.Control {
			if it.Control[ix].WillIterate() {
				fmt.Printf("|%*s", colWidth, it.Control[ix].Value(colWidth, precision))
				outputAsStrings = append(outputAsStrings, it.Control[ix].Value(colWidth, precision))
			}
		}
		// result is last column.
		fmt.Printf("|%*.*g|\n", colWidth, precision, runSimulationAndReturnResults())

		assert.Len(outputAsStrings, 3, "should have 3 flag variables iterating")
		var curFoo int
		var curBar float64
		var curBaz int64
		_, err = fmt.Sscanf(outputAsStrings[0], "%d", &curFoo)
		assert.Nilf(err, "foo output cannot be scanned: %s", outputAsStrings[0])
		_, err = fmt.Sscanf(outputAsStrings[1], "%g", &curBar)
		assert.Nilf(err, "bar output cannot be scanned: %s", outputAsStrings[1])
		_, err = fmt.Sscanf(outputAsStrings[2], "%d", &curBaz)
		assert.Nilf(err, "baz output cannot be scanned: %s", outputAsStrings[2])
		assert.Equal(goldenOutput[goldenIx].foo, curFoo)
		assert.InDelta(goldenOutput[goldenIx].bar, curBar, 0.001)
		assert.Equal(goldenOutput[goldenIx].baz, curBaz)
		assert.Equal(goldenOutput[goldenIx].start1, it.AtStart(1))
		assert.Equal(goldenOutput[goldenIx].start2, it.AtStart(2))
		assert.Equal(goldenOutput[goldenIx].start3, it.AtStart(3))

		goldenIx++

		if !it.Incr() {
			break
		}
	}
	printSeparatorHeavy(colWidth, numCol)
}
