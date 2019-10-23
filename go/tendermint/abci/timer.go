package abci

import (
	"encoding/hex"
	"time"

	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/common/logging"
)

// deadlineDisarmed is a special deadline value for disarmed timers.
const deadlineDisarmed uint64 = 0xffffffffffffffff

var (
	// timerKeyFmt is the timer key format (deadline, app-id, timer-kind-id, timer-id).
	//
	// Value is CBOR-serialized custom timer data.
	timerKeyFmt = keyformat.New(0xF0, uint64(0), uint8(0), uint8(0), []byte{})

	logger = logging.GetLogger("tendermint/abci/timer")
)

type timerState struct {
	app      uint8
	kind     uint8
	id       []byte
	deadline uint64

	data []byte
}

func (s *timerState) getKey() []byte {
	return timerKeyFmt.Encode(s.deadline, s.app, s.kind, s.id)
}

func (s *timerState) fromKeyValue(key, value []byte) {
	var deadline uint64
	var app, kind uint8
	var id []byte
	if !timerKeyFmt.Decode(key, &deadline, &app, &kind, &id) {
		panic("timer: corrupted key: " + hex.EncodeToString(key))
	}

	// Disarmed timers have no associated data.
	if value == nil && deadline == deadlineDisarmed {
		value = []byte{}
	}

	*s = timerState{
		app:      app,
		kind:     kind,
		id:       id,
		deadline: deadline,
		data:     value,
	}
}

// Timer is a serializable timer that can be used in ABCI applications.
type Timer struct {
	ID []byte `json:"id"`

	state *timerState
}

// NewTimer creates a new timer.
func NewTimer(ctx *Context, app Application, kind uint8, id []byte, data []byte) *Timer {
	if data == nil {
		data = []byte{}
	}

	state := &timerState{
		app:      app.TransactionTag(),
		kind:     kind,
		id:       id,
		data:     data,
		deadline: deadlineDisarmed,
	}

	return &Timer{
		ID:    state.getKey(),
		state: state,
	}
}

func (t *Timer) refreshState() {
	if t.state != nil {
		return
	}

	var ts timerState
	ts.fromKeyValue(t.ID, nil)
	t.state = &ts
}

// Kind returns the timer kind.
func (t *Timer) Kind() uint8 {
	t.refreshState()
	return t.state.kind
}

// CustomID returns the custom ID of the timer provided by the timer creator.
func (t *Timer) CustomID() []byte {
	t.refreshState()
	return t.state.id
}

// Data returns custom data associated with the timer.
func (t *Timer) Data(ctx *Context) []byte {
	t.refreshState()

	if t.state.data == nil {
		_, value := ctx.State().Get(t.ID)
		if value == nil {
			logger.Error("timer not found",
				"id", hex.EncodeToString(t.ID),
			)
			panic("timer: not found")
		}

		t.state.data = value
	}
	return t.state.data
}

// Reset resets the timer, rearming it.
//
// The timer's custom data will be set to the new value iff it is non-nil,
// otherwise it will be left unaltered.
func (t *Timer) Reset(ctx *Context, duration time.Duration, data []byte) {
	if data == nil {
		// Load previous data.
		_ = t.Data(ctx)
	}
	// Remove previous timer entry (if any).
	t.remove(ctx)

	deadline := ctx.Now().Add(duration).Unix()
	if deadline < 0 {
		deadline = 0
	}
	t.state.deadline = uint64(deadline)
	if data != nil {
		t.state.data = data
	}

	// Create timer entry.
	ctx.State().Set(t.state.getKey(), t.state.data)
	t.ID = t.state.getKey()
}

// Stop stops the timer.
//
// This removes any data associated with the timer.
func (t *Timer) Stop(ctx *Context) {
	// Remove previous timer entry (if any).
	t.remove(ctx)

	t.state.deadline = deadlineDisarmed
	t.ID = t.state.getKey()
}

func (t *Timer) remove(ctx *Context) {
	t.refreshState()

	if t.state.deadline == deadlineDisarmed {
		return
	}

	if _, removed := ctx.State().Remove(t.ID); !removed {
		logger.Error("timer not removed",
			"id", hex.EncodeToString(t.ID),
		)
		panic("timer: not removed")
	}
}

func fireTimers(ctx *Context, app Application) (err error) {
	// Iterate through all timers which have already expired.
	ctx.State().IterateRange(
		timerKeyFmt.Encode(),
		timerKeyFmt.Encode(uint64(ctx.Now().Unix())+1),
		true,
		func(key, value []byte) bool {
			var ts timerState
			ts.fromKeyValue(key, value)

			// Skip timers that are not for this application.
			if app.TransactionTag() != ts.app {
				return false
			}

			if err = app.FireTimer(ctx, &Timer{ID: key, state: &ts}); err != nil {
				return true
			}

			return false
		},
	)
	return
}
