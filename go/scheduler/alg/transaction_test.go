package alg

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func ReadAndWriteTransaction(t *testing.T, input string) {
	bufr := bufio.NewReader(bytes.NewReader([]byte(input)))
	var proto Location = new(TestLocation)
	tr, err := ReadNewTransaction(proto, bufr)
	assert.NoError(t, err, "Could not parse %s", input)
	outputBuffer := new(bytes.Buffer)
	bufw := bufio.NewWriter(outputBuffer)
	tr.Write(bufw)
	err = bufw.Flush()
	assert.NoError(t, err, "Could not write as string")
	fmt.Printf("Got %s\n", outputBuffer.String())
	assert.Equal(t, input, outputBuffer.String(), "Output should match input")
}

func RejectBadTransaction(t *testing.T, input string) {
	bufr := bufio.NewReader(bytes.NewReader([]byte(input)))
	var proto Location = new(TestLocation)
	_, err := ReadNewTransaction(proto, bufr)
	assert.Error(t, io.EOF, err, "Parsed bad input %s", input)
	fmt.Printf("Rejected %s\n", input)
}

func TestTransaction(t *testing.T) {
	ReadAndWriteTransaction(t, "({}, {}, 314159, 271828)")
	ReadAndWriteTransaction(t, "({1, 2, 3}, {4, 5, 6}, 7, 8)")
	ReadAndWriteTransaction(t, "({}, {4, 5, 6}, 7, 8)")
	ReadAndWriteTransaction(t, "({4, 5, 6}, {}, 7, 8)")
	ReadAndWriteTransaction(t, "({-4, 5, 6}, {}, 7, 27)")

	RejectBadTransaction(t, "")
	RejectBadTransaction(t, "(123, {}, {}, 2)")
	RejectBadTransaction(t, "({1, 2, {3, 4}}, {}, 2, 3)")
	RejectBadTransaction(t, "({1, 2, 3, 4}, {-5, 2.2}, 2, 3)")
	RejectBadTransaction(t, "({1, 2, 3, 4}, {-5, 2.2}, garbage, 2, 3)")
	RejectBadTransaction(t, "garbage-in")
	RejectBadTransaction(t, "({}, {}, 314159,")
}

func TestTransactionReadString(t *testing.T) {
	assert := assert.New(t)

	input := "({1, 2}, {3, 4, 5}, 10, 1)"
	expected := "({1, 2}, {3, 4, 5}, 10, 1)"
	txn, err := TransactionFromString(TestLocation(0), input)
	assert.NoError(err, "TransactionFromString, setup")
	assert.Equal(expected, txn.String())

	input = "({2, 1}, {5, 3, 4}, 10, 1)"
	expected = "({1, 2}, {3, 4, 5}, 10, 1)"
	txn, err = TransactionFromString(TestLocation(0), input)
	assert.NoError(err, "TransactionFromString, setup")
	assert.Equal(expected, txn.String())
}
