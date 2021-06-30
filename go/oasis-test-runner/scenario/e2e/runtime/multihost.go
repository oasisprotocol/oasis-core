package runtime

import (
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// MultihostDouble is the MultiHost node scenario with nodes with two workers.
	MultihostDouble scenario.Scenario = newMultiHostImpl("multihost-double", BasicKVTestClient, false)
	// MultihostTriple is the MultiHost node scenario with nodes with three workers.
	MultihostTriple scenario.Scenario = newMultiHostImpl("multihost-triple", BasicKVTestClient, true)
)

type multiHostImpl struct {
	runtimeImpl
	triple bool
}

func newMultiHostImpl(name string, testClient TestClient, triple bool) scenario.Scenario {
	return &multiHostImpl{
		runtimeImpl: *newRuntimeImpl(name, testClient),
		triple:      triple,
	}
}

func (sc *multiHostImpl) Clone() scenario.Scenario {
	return &multiHostImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
		triple:      sc.triple,
	}
}

func (sc *multiHostImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	if !sc.triple {
		// Assign some compute, client and storage workers to shared nodes.
		f.ComputeWorkers[0].Name = "compute-storage-0"
		f.StorageWorkers[0].Name = "compute-storage-0"

		f.Clients[0].Name = "client-storage-0"
		f.StorageWorkers[1].Name = "client-storage-0"
	} else {
		// Have a node with everything.
		const nodeName = "compute-storage-client-0"
		f.ComputeWorkers[0].Name = nodeName
		f.StorageWorkers[0].Name = nodeName
		f.Clients[0].Name = nodeName
	}

	return f, nil
}
