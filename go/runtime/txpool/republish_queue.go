package txpool

import "time"

// spreads out a sequence of txs to republish uniformly across an interval
// backed by a circular gap buffer thing

// todo: obtain programmatically
const publishInterval = 2 * time.Minute

type republishQueue struct {
	gb           gapBuffer
	readPos      int
	previousRead time.Time
}

func (rq *republishQueue) PushNow(tx []byte) {
	rq.gb.Insert(rq.readPos, tx)
}

func (rq *republishQueue) PushLater(tx []byte) {
	rq.gb.Insert(rq.readPos, tx)
	rq.readPos++
}

func (rq *republishQueue) GetTxsToPublish(now time.Time) ([][]byte, time.Time) {
	if rq.gb.Len() == 0 {
		rq.previousRead = now
		return nil, now.Add(publishInterval)
	}
	space := publishInterval / time.Duration(rq.gb.Len())
	timePassed := now.Sub(rq.previousRead)
	var numWanted int
	if timePassed > publishInterval {
		numWanted = rq.gb.Len()
	} else {
		numWanted = int(time.Duration(rq.gb.Len()) * timePassed / publishInterval)
	}
	if numWanted == 0 {
		return nil, now.Add(space)
	}
	txs := make([][]byte, numWanted)
	for i := 0; i < numWanted; i++ {
		txs[i] = rq.gb.Get((rq.readPos + i) % rq.gb.Len())
	}
	rq.readPos = (rq.readPos + numWanted) % rq.gb.Len()
	rq.previousRead = now
	return txs, now.Add(space)
}

// ---------------- buffer
// xxxxx      xxxxx items
//      ^ gapStart
//      <----> gapLen

const gapIncrement = 100

type gapBuffer struct {
	buf      [][]byte
	gapStart int
	gapLen   int
}

// ensureGap resizes buf by gapIncrement if the gap is down to zero size
func (g *gapBuffer) ensureGap() {
	if g.gapLen == 0 {
		oldBufEnd := len(g.buf)
		buf := g.buf
		g.buf = make([][]byte, len(buf)+gapIncrement)
		copy(g.buf, buf)
		g.gapStart = oldBufEnd
		g.gapLen = gapIncrement
	}
}

// moveGap moves the gap to logical index i
func (g *gapBuffer) moveGap(i int) {
	if i < g.gapStart {
		// ---------------- buffer
		// xxxXX      xxxxx items
		//    ^ i
		// xxx      XXxxxxx items
		copy(g.buf[i+g.gapLen:], g.buf[i:g.gapStart])
		g.gapStart = i
	} else if i > g.gapStart {
		// ---------------- buffer
		// xxxxx      XXxxx items
		//        ^ i
		// xxxxxXX      xxx items
		copy(g.buf[g.gapStart:i], g.buf[g.gapStart+g.gapLen:])
		g.gapStart = i
	}
}

func (g *gapBuffer) Len() int {
	return len(g.buf) - g.gapLen
}

func (g *gapBuffer) Get(i int) []byte {
	if i > g.gapStart {
		i -= g.gapLen
	}
	return g.buf[i]
}

func (g *gapBuffer) Insert(i int, v []byte) {
	g.ensureGap()
	g.moveGap(i)
	g.buf[i] = v
	g.gapStart++
	g.gapLen--
}
