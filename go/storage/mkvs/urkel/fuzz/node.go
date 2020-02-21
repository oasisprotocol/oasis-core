// +build gofuzz

package fuzz

import "github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/node"

func FuzzNode(data []byte) int {
    n, err := node.UnmarshalBinary(data)
    if err != nil {
        return 0
    }

    _, err = n.CompactMarshalBinary()
    if err != nil {
        panic(err)
    }
    return 1
}
