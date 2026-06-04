package sgx

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	sgxCommon "github.com/oasisprotocol/oasis-core/go/runtime/host/sgx/common"
)

type teeStateMock struct{}

func (ec *teeStateMock) Init(ctx context.Context, _ *sgxProvisioner, _ *host.Config) ([]byte, error) {
	// Generate mock QE target info.
	var targetInfo [512]byte

	return targetInfo[:], nil
}

func (ec *teeStateMock) Update(ctx context.Context, sp *sgxProvisioner, conn protocol.Connection, report []byte, _ string) ([]byte, error) {
	rawQuote, err := pcs.NewMockQuote(report)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %w", err)
	}

	quoteBundle, err := sp.pcs.ResolveQuote(ctx, rawQuote, nil)
	if err != nil {
		return nil, err
	}
	return sgxCommon.UpdateRuntimeQuote(ctx, conn, quoteBundle)
}
