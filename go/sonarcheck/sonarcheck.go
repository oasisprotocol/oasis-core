// +build gofuzz

package sonarcheck

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

var callbacks = make(map[string]func())

func Fuzz(data []byte) int {
	src := bytes.NewReader(data)
	var mnBuf []byte
	var ll uint8
	if err := binary.Read(src, binary.LittleEndian, &ll); err != nil {
		return 0
	}
	mnBuf = make([]byte, ll)
	if err := binary.Read(src, binary.LittleEndian, &mnBuf); err != nil {
		return 0
	}
	mn := string(mnBuf)

	cb, ok := callbacks[mn]
	if !ok {
		return 0
	}
	cb()
	return 1
}

func init() {
	callbacks["easy"] = func() {
		fmt.Println("ok easy")
	}
	callbacks["staking.Transfer"] = func() {
		fmt.Println("ok t")
	}
	callbacks["staking.Burn"] = func() {
		fmt.Println("ok b")
	}
	callbacks["staking.AddEscrow"] = func() {
		panic("problem ae")
	}
	callbacks["staking.ReclaimEscrow"] = func() {
		panic("problem re")
	}
}
