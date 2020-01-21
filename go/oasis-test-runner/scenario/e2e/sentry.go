package e2e

import (
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/log"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasislabs/oasis-core/go/storage/database"
)

var (
	// Sentry is the Sentry node basic scenario.
	Sentry scenario.Scenario = newSentryImpl("sentry", "simple-keyvalue-client", nil)
	// SentryEncryption is the Sentry node basic encryption scenario.
	SentryEncryption scenario.Scenario = newSentryImpl("sentry-encryption", "simple-keyvalue-enc-client", nil)

	ValidatorExtraLogWatcherHandlerFactories = []log.WatcherHandlerFactory{
		oasis.LogAssertPeerExchangeDisabled(),
	}
)

type sentryImpl struct {
	basicImpl
}

func newSentryImpl(name, clientBinary string, clientArgs []string) scenario.Scenario {
	return &sentryImpl{
		basicImpl: *newBasicImpl(name, clientBinary, clientArgs),
	}
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
	//
	// +-----------+            +----------+
	// | Storage 1 +<---------->+ Sentry 3 |
	// +-----------+            +----------+
	//
	// +-----------+            +----------+
	// | Storage 2 +<---------->+ Sentry 4 |
	// +-----------+            +----------+
	//
	// +------------+           +----------+
	// | Keymanager |<--------->| Sentry 5 |
	// +------------+           +----------+
	//
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
		oasis.SentryFixture{
			StorageWorkers: []int{0},
		},
		oasis.SentryFixture{
			StorageWorkers: []int{1},
		},
		oasis.SentryFixture{
			KeymanagerWorkers: []int{0},
		},
	}

	f.Validators = []oasis.ValidatorFixture{
		oasis.ValidatorFixture{
			Entity:                     1,
			LogWatcherHandlerFactories: ValidatorExtraLogWatcherHandlerFactories,
			Sentries:                   []int{0, 1},
		},
		oasis.ValidatorFixture{
			Entity:                     1,
			LogWatcherHandlerFactories: ValidatorExtraLogWatcherHandlerFactories,
			Sentries:                   []int{2},
		},
		oasis.ValidatorFixture{
			Entity:                     1,
			LogWatcherHandlerFactories: ValidatorExtraLogWatcherHandlerFactories,
			Sentries:                   []int{2},
		},
	}

	f.StorageWorkers = []oasis.StorageWorkerFixture{
		oasis.StorageWorkerFixture{
			Backend:  database.BackendNameBadgerDB,
			Entity:   1,
			Sentries: []int{3},
		},
		oasis.StorageWorkerFixture{
			Backend:  database.BackendNameBadgerDB,
			Entity:   1,
			Sentries: []int{4},
		},
	}

	f.Keymanagers = []oasis.KeymanagerFixture{
		oasis.KeymanagerFixture{
			Runtime:  0,
			Entity:   1,
			Sentries: []int{5},
		},
	}

	return f, nil
}
