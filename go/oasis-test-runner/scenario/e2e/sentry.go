package e2e

import (
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// Sentry is the Tendermint Sentry node scenario.
	Sentry scenario.Scenario = newSentryImpl()
)

type sentryImpl struct {
	basicImpl

	logger *logging.Logger
}

func newSentryImpl() scenario.Scenario {
	s := &sentryImpl{
		basicImpl: basicImpl{
			clientBinary: "simple-keyvalue-client",
		},
		logger: logging.GetLogger("scenario/e2e/sentry"),
	}
	return s
}

func (s *sentryImpl) Name() string {
	return "sentry"
}

func (s *sentryImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := s.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Provision sentry nodes and validators with the following topology:
	//
	//                          +----------+
	//                     +--->| Sentry 0 |
	// +-------------+     |    +----------+
	// | Validator 0 +<----+    +----------+
	// |             +<-------->+ Sentry 1 |
	// +-------------+          +----------+
	//
	// +-------------+
	// | Validator 1 +<----+
	// +-------------+     |    +----------+
	// +-------------+     +--->+ Sentry 2 |
	// | Validator 2 +<-------->+          |
	// +-------------+          +----------+

	f.Sentries = []oasis.SentryFixture{
		oasis.SentryFixture{
			Validators: []int{0},
		},
		oasis.SentryFixture{
			Validators: []int{0},
		},
		oasis.SentryFixture{
			Validators: []int{1, 2},
		},
	}
	f.Validators = []oasis.ValidatorFixture{
		oasis.ValidatorFixture{
			Entity:   1,
			Sentries: []int{0, 1},
		},
		oasis.ValidatorFixture{
			Entity:   1,
			Sentries: []int{2},
		},
		oasis.ValidatorFixture{
			Entity:   1,
			Sentries: []int{2},
		},
	}

	f.Network.LogWatcherHandlers = append(
		f.Network.LogWatcherHandlers,
		// NOTE: This currently works because logs from all nodes are checked
		// by the same log watcher handler.
		// It needs to be properly implemented after:
		// - https://github.com/oasislabs/oasis-core/issues/2355
		// - https://github.com/oasislabs/oasis-core/issues/2356
		// are implemented.
		oasis.LogAssertPeerExchangeDisabled(),
	)

	return f, nil
}
