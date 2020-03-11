package fm

import "github.com/thepudds/fzgo/randparam"

func Unmarshal(data []byte, dst interface{}) error {
	MustUnmarshal(data, dst)
	return nil
}

func MustUnmarshal(data []byte, dst interface{}) {
	randparam.NewFuzzer(data).Fill(dst)
}
