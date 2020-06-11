package process

import "testing"

func TestBubbleWrapSandbox(t *testing.T) {
	t.Run("BindData", func(t *testing.T) {
		testBindData(t, NewBubbleWrap, "/usr/bin/bwrap")
	})
}
