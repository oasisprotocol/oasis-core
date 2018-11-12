package abci

import (
	"fmt"
	"time"

	"github.com/oasislabs/ekiden/go/common/cbor"
)

const (
	stateTimerMap = "timers/id/%s"

	stateTimerDeadlineMap      = "timers/deadline/%d/%s"
	stateTimerDeadlineMapStart = "timers/deadline/"
	stateTimerDeadlineMapEnd   = "timers/deadline/%d"
)

type timerState struct {
	ID       string    `codec:"id"`
	App      string    `codec:"app"`
	Armed    bool      `codec:"armed"`
	Deadline time.Time `codec:"deadline"`
	Data     []byte    `codec:"data"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (s *timerState) MarshalCBOR() []byte {
	return cbor.Marshal(s)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (s *timerState) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, s)
}

func (s *timerState) getDeadlineMapKey() []byte {
	return []byte(fmt.Sprintf(stateTimerDeadlineMap, s.Deadline.Unix(), s.ID))
}

// Timer is a serializable timer that can be used in ABCI applications.
type Timer struct {
	ID string `codec:"id"`

	currentState *timerState
	pendingState *timerState
}

// NewTimer creates a new timer.
func NewTimer(ctx *Context, app Application, id string, data []byte) *Timer {
	state := &timerState{
		ID:    fmt.Sprintf("%s:%s", app.Name(), id),
		App:   app.Name(),
		Armed: false,
		Data:  data,
	}

	t := &Timer{
		ID:           state.ID,
		currentState: state,
		pendingState: state,
	}
	t.registerOnCommitHook(ctx)

	return t
}

// Data returns custom data associated with the timer.
func (t *Timer) Data() []byte {
	if t.pendingState != nil && t.pendingState.Data != nil {
		return t.pendingState.Data
	}
	if t.currentState == nil {
		return nil
	}
	return t.currentState.Data
}

// Reset resets the timer, rearming it.
//
// The timer's custom data will be set to the new value iff it is non-nil,
// otherwise it will be left unaltered.
func (t *Timer) Reset(ctx *Context, duration time.Duration, newData []byte) {
	t.pendingState = &timerState{
		Armed: true,
		// Round deadline to the nearest second to ensure that serialization only
		// uses integers and not floats.
		Deadline: ctx.Now().Add(duration).Round(time.Second),
		Data:     newData,
	}
	t.registerOnCommitHook(ctx)
}

// Stop stops the timer.
func (t *Timer) Stop(ctx *Context) {
	t.pendingState = &timerState{
		Armed: false,
	}
	t.registerOnCommitHook(ctx)
}

func (t *Timer) getMapKey() []byte {
	return []byte(fmt.Sprintf(stateTimerMap, t.ID))
}

func (t *Timer) registerOnCommitHook(ctx *Context) {
	ctx.RegisterOnCommitHook(t.ID, func(state *ApplicationState) {
		t.persist(state)
	})
}

func (t *Timer) persist(state *ApplicationState) {
	if t.pendingState == nil {
		return
	}

	tree := state.DeliverTxTree()

	// Load current timer state and update it.
	var currentState timerState
	_, data := tree.Get(t.getMapKey())
	if data == nil {
		// This should only happen when timer is first created.
		if t.currentState == nil {
			panic("timer: no state in tree and current state not available")
		}
		currentState = *t.currentState
	} else {
		if err := currentState.UnmarshalCBOR(data); err != nil {
			panic("timer: state corruption")
		}
	}

	t.pendingState.ID = currentState.ID
	t.pendingState.App = currentState.App
	if t.pendingState.Data == nil {
		t.pendingState.Data = currentState.Data
	}
	tree.Set(t.getMapKey(), t.pendingState.MarshalCBOR())

	// Update deadline state.
	if currentState.Armed {
		if _, removed := tree.Remove(currentState.getDeadlineMapKey()); !removed {
			panic("timer: armed timer not removed from deadline map")
		}
	}
	if t.pendingState.Armed {
		tree.Set(t.pendingState.getDeadlineMapKey(), []byte(t.ID))
	}

	t.pendingState = nil
}

func fireTimers(ctx *Context, state *ApplicationState, app Application) {
	now := ctx.Now()
	tree := state.DeliverTxTree()

	// Iterate through all timers which have already expired.
	tree.IterateRange(
		[]byte(stateTimerDeadlineMapStart),
		[]byte(fmt.Sprintf(stateTimerDeadlineMapEnd, now.Unix()+1)),
		true,
		func(key, value []byte) bool {
			_, data := tree.Get([]byte(fmt.Sprintf(stateTimerMap, value)))
			if data == nil {
				panic("timer: state corruption")
			}

			var ts timerState
			if err := ts.UnmarshalCBOR(data); err != nil {
				panic("timer: state corruption")
			}

			if !ts.Armed {
				panic("timer: attempted to fire an unarmed timer")
			}

			if ts.App != app.Name() {
				return false
			}

			app.FireTimer(ctx, &Timer{
				ID:           ts.ID,
				currentState: &ts,
			})

			return false
		},
	)
}
