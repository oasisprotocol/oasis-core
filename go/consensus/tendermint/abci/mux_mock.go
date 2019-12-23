// +build gofuzz

package abci

import (
	"context"
)

// MockABCIMux exports some of the muxer's internal methods for testing use.
type MockABCIMux struct {
	*abciMux
}

// MockRegisterApp is used to register apps with this muxer during testing.
func (mux *MockABCIMux) MockRegisterApp(app Application) error {
	return mux.doRegister(app)
}

// MockClose cleans up the muxer's state; it must be called once the muxer is no longer needed.
func (mux *MockABCIMux) MockClose() {
	mux.doCleanup()
}

// NewMockMux creates a new ABCI mux suitable for testing.
func NewMockMux(ctx context.Context, cfg *ApplicationConfig) (*MockABCIMux, error) {
	mux, err := newABCIMux(ctx, cfg)
	if err != nil {
		return nil, err
	}
	mockMux := &MockABCIMux{
		abciMux: mux,
	}
	return mockMux, nil
}
