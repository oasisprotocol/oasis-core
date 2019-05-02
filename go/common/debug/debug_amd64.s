// +build !noasm

#include "textflag.h"

TEXT ·debugTrap(SB), NOSPLIT|NOFRAME, $0-0
	BYTE $0xcc // INT 3
	RET
