// Package api implements the scheduler API.
package api

import (
	"errors"
	"fmt"

	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/common/runtime"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"

	pbSched "github.com/oasislabs/ekiden/go/grpc/scheduler"
)

var (
	// ErrNilProtobuf is the error returned when a protobuf is nil.
	ErrNilProtobuf = errors.New("scheduler: protobuf is nil")

	// ErrInvalidRole is the error returned when a role is invalid.
	ErrInvalidRole = errors.New("scheduler: invalid role")
)

// Role is the role a given node plays in a committee.
type Role uint8

const (
	// Invalid is an invalid role (should never appear on the wire).
	Invalid Role = 0

	// Worker indicates the node is a worker.
	Worker Role = 1

	// BackupWorker indicates the node is a backup worker.
	BackupWorker Role = 2

	// Leader indicates the node is a group leader.
	Leader Role = 3
)

// String returns a string representation of a Role.
func (r Role) String() string {
	switch r {
	case Invalid:
		return "invalid"
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
	Role Role `codec:"role"`

	// PublicKey is the node's public key.
	PublicKey signature.PublicKey `codec:"public_key"`
}

// FromProto deserializes a protobuf into a CommitteeNode.
func (n *CommitteeNode) FromProto(pb *pbSched.CommitteeNode) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	switch pb.GetRole() {
	case pbSched.CommitteeNode_WORKER:
		n.Role = Worker
	case pbSched.CommitteeNode_BACKUP_WORKER:
		n.Role = BackupWorker
	case pbSched.CommitteeNode_LEADER:
		n.Role = Leader
	default:
		return ErrInvalidRole
	}
	return n.PublicKey.UnmarshalBinary(pb.GetPublicKey())
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
		panic(ErrInvalidRole)
	}

	return pb
}

// CommitteeKind is the functionality a committee exists to provide.
type CommitteeKind uint8

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

// Committee is a per-runtime (instance) committee.
type Committee struct {
	// Kind is the functionality a committee exists to provide.
	Kind CommitteeKind `codec:"kind"`

	// Members is the committee members.
	Members []*CommitteeNode `codec:"members"`

	// Runtime is the runtime that this committee is for.
	Runtime *runtime.Runtime `codec:"-"`

	// ValidFor is the epoch for which the committee is valid.
	ValidFor epochtime.EpochTime `codec:"valid_for"`
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
	pb.Runtime = c.Runtime.ToProto()
	pb.ValidFor = uint64(c.ValidFor)

	return pb
}

// EncodedMembersHash returns the encoded cryptographic hash of the committee members.
func (c *Committee) EncodedMembersHash() hash.Hash {
	var hh hash.Hash

	hh.From(c.Members)

	return hh
}

// Backend is a scheduler implementation.
type Backend interface {
	// GetCommittees returns a vector of the committees for a given
	// runtime ID, for the current epoch.
	GetCommittees(context.Context, signature.PublicKey) ([]*Committee, error)

	// WatchCommittees returns a channel that produces a stream of
	// Committee.
	//
	// Upon subscription, all committees for the current epoch will
	// be sent immediately.
	WatchCommittees() (<-chan *Committee, *pubsub.Subscription)
}

// BlockBackend is a Backend that is backed by a blockchain.
type BlockBackend interface {
	Backend

	// GetBlockCommittees returns the vector of committees for a given
	// runtime ID, at the specified block height.
	GetBlockCommittees(context.Context, signature.PublicKey, int64) ([]*Committee, error)
}
