// Package scheduler implements the scheduler.
package scheduler

import (
	"fmt"

	"github.com/oasislabs/ekiden/go/common/contract"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/epochtime"

	pbSched "github.com/oasislabs/ekiden/go/grpc/scheduler"
)

// Role is the role a given node plays in a committee.
type Role int

const (
	// Worker indicates the node is a worker.
	Worker Role = iota

	// BackupWorker indicates the node is a backup worker.
	BackupWorker

	// Leader indicates the node is a group leader.
	Leader
)

// String returns a string representation of a Role.
func (r Role) String() string {
	switch r {
	case Worker:
		return "worker"
	case BackupWorker:
		return "backup worker"
	case Leader:
		return "leader"
	default:
		return fmt.Sprintf("unknown role: %d", r)
	}
}

// CommitteeNode is a node participating in a committee.
type CommitteeNode struct {
	// Role is the node's role in a committee.
	Role Role

	// PublicKey is the node's public key.
	PublicKey signature.PublicKey
}

// ToProto serializes a CommitteeNode into a protobuf.
func (n *CommitteeNode) ToProto() *pbSched.CommitteeNode {
	pb := new(pbSched.CommitteeNode)

	pb.PublicKey, _ = n.PublicKey.MarshalBinary()
	switch n.Role {
	case Worker:
		pb.Role = pbSched.CommitteeNode_WORKER
	case BackupWorker:
		pb.Role = pbSched.CommitteeNode_BACKUP_WORKER
	case Leader:
		pb.Role = pbSched.CommitteeNode_LEADER
	default:
		panic("scheduler: invalid node role")
	}

	return pb
}

// CommitteeKind is the functionality a committee exists to provide.
type CommitteeKind int

const (
	// Compute is a compute committee.
	Compute CommitteeKind = iota

	// Storage is a storage committee.
	Storage
)

// String returns a string representation of a CommitteeKind.
func (k CommitteeKind) String() string {
	switch k {
	case Compute:
		return "compute"
	case Storage:
		return "storage"
	default:
		return fmt.Sprintf("unknown kind: %d", k)
	}
}

// Committee is a per-contract (instance) committee.
type Committee struct {
	// Kind is the functionality a committee exists to provide.
	Kind CommitteeKind

	// Members is the committee members.
	Members []*CommitteeNode

	// Contract is the contract (runtime) that this committee is for.
	Contract *contract.Contract

	// ValidFor is the epoch for which the committee is valid.
	ValidFor epochtime.EpochTime
}

// ToProto serializes a Committee into a protobuf.
func (c *Committee) ToProto() *pbSched.Committee {
	pb := new(pbSched.Committee)

	switch c.Kind {
	case Compute:
		pb.Kind = pbSched.Committee_COMPUTE
	case Storage:
		pb.Kind = pbSched.Committee_STORAGE
	default:
		panic("scheduler: invalid committee kind")
	}
	for _, v := range c.Members {
		pb.Members = append(pb.Members, v.ToProto())
	}
	pb.Contract = c.Contract.ToProto()
	pb.ValidFor = uint64(c.ValidFor)

	return pb
}

// Scheduler is a scheduler implementation.
type Scheduler interface {
	// GetCommittees returns a vector of the committees for a given
	// contract ID, for the current epoch.
	GetCommittees(signature.PublicKey) []*Committee

	// WatchCommittees returns a channel that produces a stream of
	// Committee.
	//
	// Upon subscription, all committees for the current epoch will
	// be sent immediately.
	WatchCommittees() (<-chan *Committee, *pubsub.Subscription)
}

func subscribeTypedCommittee(notifier *pubsub.Broker) (<-chan *Committee, *pubsub.Subscription) {
	typedCh := make(chan *Committee)
	sub := notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}
