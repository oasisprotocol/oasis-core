package fm

import randparam "github.com/oasislabs/oasis-core/go/common/fm/randparam16"

func Unmarshal(data []byte, dst interface{}) error {
	MustUnmarshal(data, dst)
	return nil
}

func MustUnmarshal(data []byte, dst interface{}) {
	randparam.NewFuzzer(data).Fill(dst)
}
