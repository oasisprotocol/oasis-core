package tickermock

import (
	"github.com/pkg/errors"
	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/ticker/api"
)

const (
	// Mock ticker state.
	stateCurrentTick = "ticker_mock/current"
)

var (
	_ cbor.Marshaler   = (*mockTickerState)(nil)
	_ cbor.Unmarshaler = (*mockTickerState)(nil)
)

type mockTickerState struct {
	Tick          api.TickTime `codec:"tick"`
	TickScheduled bool         `codec:"tick_scheduled"`
}

func (s *mockTickerState) MarshalCBOR() []byte {
	return cbor.Marshal(s)
}

func (s *mockTickerState) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, s)
}

type immutableState struct {
	*abci.ImmutableState
}

func (s *immutableState) getTick() (api.TickTime, error) {
	_, raw := s.Snapshot.Get([]byte(stateCurrentTick))
	if raw == nil {
		return api.TickTime(0), nil
	}

	var state mockTickerState
	err := state.UnmarshalCBOR(raw)
	return state.Tick, err
}

func (s *immutableState) isTickScheduled() (bool, error) {
	_, raw := s.Snapshot.Get([]byte(stateCurrentTick))
	if raw == nil {
		return false, nil
	}

	var state mockTickerState
	if err := state.UnmarshalCBOR(raw); err != nil {
		return false, errors.Wrap(err, "ticker_settable: failed to check scheduled tick")
	}
	return state.TickScheduled, nil
}

func newImmutableState(state *abci.ApplicationState, version int64) (*immutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}

	return &immutableState{inner}, nil
}

type mutableState struct {
	*immutableState

	tree *iavl.MutableTree
}

func (s *mutableState) doTick() (api.TickTime, error) {
	tick, err := s.getTick()
	if err != nil {
		return api.TickTime(0), errors.Wrap(err, "ticker_settable: failed to do tick")
	}
	state := mockTickerState{Tick: tick + 1}

	s.tree.Set(
		[]byte(stateCurrentTick),
		state.MarshalCBOR(),
	)

	return tick + 1, nil
}

func (s *mutableState) scheduleTick() error {
	scheduledTick, err := s.isTickScheduled()
	if err != nil {
		return errors.Wrap(err, "ticker_settable: failed to check if tick is scheduled")
	}
	if scheduledTick {
		return errors.New("ticker_settable: tick already scheduled")
	}

	tick, err := s.getTick()
	if err != nil {
		return errors.Wrap(err, "ticker_settable: failed to get current tick state")
	}

	state := mockTickerState{Tick: tick, TickScheduled: true}
	s.tree.Set(
		[]byte(stateCurrentTick),
		state.MarshalCBOR(),
	)

	return nil
}

func (s *mutableState) clearScheduledTick() error {
	_, raw := s.Snapshot.Get([]byte(stateCurrentTick))
	if raw == nil {
		return errors.New("ticker_settable: failed to get current tick state")
	}

	var state mockTickerState
	if err := state.UnmarshalCBOR(raw); err != nil {
		return errors.Wrap(err, "ticker_settable: failed to check scheduled tick")
	}

	state = mockTickerState{Tick: state.Tick, TickScheduled: false}
	s.tree.Set(
		[]byte(stateCurrentTick),
		state.MarshalCBOR(),
	)

	return nil
}

func newMutableState(tree *iavl.MutableTree) *mutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &mutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
