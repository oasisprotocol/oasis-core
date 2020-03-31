// +build gofuzz

package sonarcheck

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func methodEasy() {
	fmt.Println("ok easy")
}

func methodTransfer() {
	fmt.Println("ok t")
}

func methodBurn() {
	fmt.Println("ok b")
}

func methodAddEscrow() {
	panic("problem ae")
}

func methodReclaimEscrow() {
	panic("problem re")
}

var callbacks = map[string]func(){
	"easy": methodEasy,
	"staking.Transfer": methodTransfer,
	"staking.Burn": methodBurn,
	"staking.AddEscrow": methodAddEscrow,
	"staking.ReclaimEscrow": methodReclaimEscrow,
}

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
	if src.Len() > 0 {
		return 0
	}

	cb, ok := callbacks[mn]
	if !ok {
		return 0
	}
	cb()
	return 1
}
