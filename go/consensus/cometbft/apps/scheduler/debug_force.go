package scheduler

import (
	"bytes"
	"sort"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

type debugForceElectState struct {
	params  map[signature.PublicKey]scheduler.ForceElectCommitteeRole
	elected map[signature.PublicKey]bool
}

func (app *Application) debugForceElect(
	ctx *api.Context,
	schedulerParameters *scheduler.ConsensusParameters,
	rt *registry.Runtime,
	kind scheduler.CommitteeKind,
	role scheduler.Role,
	nodeList []*node.Node,
	wantedNodes int,
) (bool, []*scheduler.CommitteeNode, *debugForceElectState) {
	elected := make([]*scheduler.CommitteeNode, 0, wantedNodes)
	if !flags.DebugDontBlameOasis() || schedulerParameters.DebugForceElect == nil {
		return true, elected, nil
	}

	var (
		toForce []signature.PublicKey
		state   = &debugForceElectState{
			params:  make(map[signature.PublicKey]scheduler.ForceElectCommitteeRole),
			elected: make(map[signature.PublicKey]bool),
		}
	)

	for nodeID, ri := range schedulerParameters.DebugForceElect[rt.ID] {
		if kind == ri.Kind && ri.HasRole(role) {
			toForce = append(toForce, nodeID)
			state.params[nodeID] = *ri
		}
	}
	sort.SliceStable(toForce, func(i, j int) bool {
		a, b := toForce[i], toForce[j]
		return bytes.Compare(a[:], b[:]) < 0
	})
forceLoop:
	for _, nodeID := range toForce {
		ctx.Logger().Debug("attempting to force-elect node",
			"runtime", rt.ID,
			"node", nodeID,
			"role", role,
		)
		if len(elected) >= wantedNodes {
			break
		}

		// Ensure the node is currently registered and eligible.
		for _, v := range nodeList {
			ctx.Logger().Debug("checking to see if this is the force elected node",
				"iter_id", v.ID,
				"node", nodeID,
			)
			if v.ID.Equal(nodeID) {
				// And force it into the committee.
				elected = append(elected, &scheduler.CommitteeNode{
					Role:      role,
					PublicKey: nodeID,
				})
				state.elected[nodeID] = true
				ctx.Logger().Debug("force elected node to committee",
					"runtime", rt.ID,
					"node", nodeID,
					"role", role,
				)
				continue forceLoop
			}
		}
	}
	if len(elected) != len(toForce) {
		ctx.Logger().Error("available nodes can't fulfill forced committee members",
			"kind", kind,
			"runtime_id", rt.ID,
			"nr_nodes", len(nodeList),
			"mandatory_nodes", len(toForce),
		)
		return false, nil, nil
	}

	return true, elected, state
}

func (app *Application) debugForceRoles(
	ctx *api.Context,
	state *debugForceElectState,
	elected []*scheduler.CommitteeNode,
	role scheduler.Role,
) (bool, []*scheduler.CommitteeNode) {
	if !flags.DebugDontBlameOasis() || state == nil || len(state.elected) == 0 || role != scheduler.RoleWorker {
		return true, elected
	}

	reordered := make([]*scheduler.CommitteeNode, len(elected))
	queue := make([]*scheduler.CommitteeNode, 0, len(elected))

	for _, n := range elected {
		ri, ok := state.params[n.PublicKey]
		if !ok {
			queue = append(queue, n)
			continue
		}

		if ri.Index >= uint64(len(reordered)) {
			ctx.Logger().Error("invalid worker index",
				"index", ri.Index,
			)
			return false, nil
		}

		if reordered[ri.Index] != nil {
			ctx.Logger().Error("duplicate worker index",
				"index", ri.Index,
			)
			return false, nil
		}

		reordered[ri.Index] = n
	}

	for i, n := range reordered {
		if n != nil {
			continue
		}
		reordered[i] = queue[0]
		queue = queue[1:]
	}

	return true, reordered
}
