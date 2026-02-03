package pcs

import "testing"

func TestTCBLevelMatches(t *testing.T) {
	pcesvn := uint16(10)
	sgxSvn := [16]int32{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30}
	tdxSvn := [16]byte{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31}

	var tl TCBLevel
	tl.TCB.PCESVN = pcesvn
	for i := range 16 {
		tl.TCB.SGXComponents[i].SVN = sgxSvn[i]
		tl.TCB.TDXComponents[i].SVN = int32(tdxSvn[i])
	}

	tcs := []struct {
		name    string
		pcesvn  uint16
		sgxSvn  [16]int32
		tdxSvn  *[16]byte
		matches bool
		msg     string
	}{
		{
			name:    "same values",
			pcesvn:  pcesvn,
			sgxSvn:  sgxSvn,
			tdxSvn:  &tdxSvn,
			matches: true,
		},
		{
			name:    "higher pcesvn",
			pcesvn:  pcesvn + 1,
			sgxSvn:  sgxSvn,
			tdxSvn:  &tdxSvn,
			matches: true,
		},
		{
			name:    "lower pcesvn",
			pcesvn:  pcesvn - 1,
			sgxSvn:  sgxSvn,
			tdxSvn:  &tdxSvn,
			matches: false,
		},
		{
			name:    "higher sgx svn",
			pcesvn:  pcesvn,
			sgxSvn:  func() [16]int32 { ss := sgxSvn; ss[5] += 1; return ss }(),
			tdxSvn:  &tdxSvn,
			matches: true,
		},
		{
			name:    "lower sgx svn",
			pcesvn:  pcesvn,
			sgxSvn:  func() [16]int32 { ss := sgxSvn; ss[5] -= 1; return ss }(),
			tdxSvn:  &tdxSvn,
			matches: false,
		},
		{
			name:    "higher tdx svn",
			pcesvn:  pcesvn,
			sgxSvn:  sgxSvn,
			tdxSvn:  func() *[16]byte { ts := tdxSvn; ts[5] += 1; return &ts }(),
			matches: true,
		},
		{
			name:    "lower tdx svn",
			pcesvn:  pcesvn,
			sgxSvn:  sgxSvn,
			tdxSvn:  func() *[16]byte { ts := tdxSvn; ts[5] -= 1; return &ts }(),
			matches: false,
		},
		{
			name:    "no tdx svn",
			pcesvn:  pcesvn,
			sgxSvn:  sgxSvn,
			tdxSvn:  nil,
			matches: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if tl.matches(tc.sgxSvn, tc.tdxSvn, tc.pcesvn) != tc.matches {
				switch tc.matches {
				case true:
					t.Errorf("tcb level should match")
				case false:
					t.Errorf("tcb level should not match")
				}
			}
		})
	}
}
