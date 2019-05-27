// Package api implements the scheduler API.
package api

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
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

// CommitteeKind is the functionality a committee exists to provide.
type CommitteeKind uint8

// TODO: Add "Kind" prefix to all constants, use explicit values instead of iota.
const (
	// Compute is a compute committee.
	Compute CommitteeKind = iota

	// Storage is a storage committee.
	Storage

	// TransactionScheduler is a transaction scheduler committee.
	TransactionScheduler

	// Merge is a merge committee.
	Merge
)

// String returns a string representation of a CommitteeKind.
func (k CommitteeKind) String() string {
	switch k {
	case Compute:
		return "compute"
	case Storage:
		return "storage"
	case TransactionScheduler:
		return "transaction"
	case Merge:
		return "merge"
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

	// RuntimeID is the runtime ID that this committee is for.
	RuntimeID signature.PublicKey `codec:"-"`

	// ValidFor is the epoch for which the committee is valid.
	ValidFor epochtime.EpochTime `codec:"valid_for"`
}

// String returns a string representation of a Committee.
func (c Committee) String() string {
	members := make([]string, len(c.Members))
	for i, m := range c.Members {
		members[i] = fmt.Sprintf("%+v", m)
	}
	return fmt.Sprintf("&{Kind:%v Members:[%v] RuntimeID:%v ValidFor:%v}", c.Kind, strings.Join(members, " "), c.RuntimeID, c.ValidFor)
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

	// Cleanup cleans up the scheduler backend.
	Cleanup()
}

// BlockBackend is a Backend that is backed by a blockchain.
type BlockBackend interface {
	Backend

	// GetBlockCommittees returns the vector of committees for a given
	// runtime ID, at the specified block height, and optional callback
	// for querying the beacon for a given epoch/block height.
	//
	// Iff the callback is nil, `beacon.GetBlockBeacon` will be used.
	GetBlockCommittees(context.Context, signature.PublicKey, int64, GetBeaconFunc) ([]*Committee, error)
}

// GetBeaconFunc is the callback used to query a beacon from a BlockBackend.
type GetBeaconFunc func() ([]byte, error)
