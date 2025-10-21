package api

import (
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
)

// RuntimeAdmissionPolicy is a specification of which nodes are allowed to register for a runtime.
type RuntimeAdmissionPolicy struct {
	AnyNode         *AnyNodeRuntimeAdmissionPolicy         `json:"any_node,omitempty"`
	EntityWhitelist *EntityWhitelistRuntimeAdmissionPolicy `json:"entity_whitelist,omitempty"`

	// PerRole is a per-role admission policy that must be satisfied in addition to the global
	// admission policy for a specific role.
	PerRole map[node.RolesMask]PerRoleAdmissionPolicy `json:"per_role,omitempty"`
}

// ValidateBasic performs basic runtime admission policy validity checks.
func (rap *RuntimeAdmissionPolicy) ValidateBasic() error {
	// Ensure there's a valid admission policy.
	if !common.ExactlyOneTrue(
		rap.AnyNode != nil,
		rap.EntityWhitelist != nil || rap.PerRole != nil,
	) {
		return fmt.Errorf("%w: invalid admission policy", ErrInvalidArgument)
	}

	// Ensure valid whitelist if present.
	if ewl := rap.EntityWhitelist; ewl != nil {
		if err := ewl.ValidateBasic(); err != nil {
			return err
		}
	}

	// Ensure valid per-role policy if present.
	if perRole := rap.PerRole; perRole != nil {
		for role, prap := range perRole {
			if !role.IsSingleRole() {
				return fmt.Errorf("%w: non-single role in per-role admission policy", ErrInvalidArgument)
			}

			if err := prap.ValidateBasic(); err != nil {
				return err
			}
		}
	}

	return nil
}

// Verify ensures the runtime admission policy is satisfied, returning an error otherwise.
func (rap *RuntimeAdmissionPolicy) Verify(
	ctx context.Context,
	nodeLookup NodeLookup,
	newNode *node.Node,
	rt *Runtime,
	epoch beacon.EpochTime,
) error {
	if rap.EntityWhitelist != nil {
		if err := rap.EntityWhitelist.Verify(ctx, nodeLookup, newNode, rt, epoch); err != nil {
			return err
		}
	}

	if len(rap.PerRole) > 0 {
		// Iterate over all valid roles (each entry in the map can only have a single role).
		for _, role := range node.Roles() {
			if !newNode.HasRoles(role) {
				// Skip unset roles.
				continue
			}

			prap, ok := rap.PerRole[role]
			if !ok {
				// Skip roles for which a per-role policy is not set.
				continue
			}

			if err := prap.Verify(ctx, nodeLookup, newNode, rt, epoch, role); err != nil {
				return err
			}
		}
	}

	return nil
}

// AnyNodeRuntimeAdmissionPolicy allows any node to register.
type AnyNodeRuntimeAdmissionPolicy struct{}

// EntityWhitelistRuntimeAdmissionPolicy allows only whitelisted entities' nodes to register.
type EntityWhitelistRuntimeAdmissionPolicy struct {
	Entities map[signature.PublicKey]EntityWhitelistConfig `json:"entities"`
}

// ValidateBasic performs basic runtime admission policy validity checks.
func (ewl *EntityWhitelistRuntimeAdmissionPolicy) ValidateBasic() error {
	for ent, wc := range ewl.Entities {
		// Entity ID should be valid.
		if !ent.IsValid() {
			return fmt.Errorf("%w: invalid entity ID in entity whitelist", ErrInvalidArgument)
		}

		// MaxNodes map should contain only single roles as keys.
		if wc.MaxNodes != nil {
			for role := range wc.MaxNodes {
				if !role.IsSingleRole() {
					return fmt.Errorf("%w: non-single role in entity whitelist max nodes map", ErrInvalidArgument)
				}
			}
		}
	}
	return nil
}

// Verify ensures the runtime admission policy is satisfied, returning an error otherwise.
func (ewl *EntityWhitelistRuntimeAdmissionPolicy) Verify(
	ctx context.Context,
	nodeLookup NodeLookup,
	newNode *node.Node,
	rt *Runtime,
	epoch beacon.EpochTime,
) error {
	wcfg, entIsWhitelisted := ewl.Entities[newNode.EntityID]
	if !entIsWhitelisted {
		return ErrForbidden
	}
	if len(wcfg.MaxNodes) == 0 {
		return nil // Any amount of nodes allowed.
	}

	// Map is present and non-empty, check per-role restrictions
	// on the maximum number of nodes per entity.

	// Iterate over all valid roles (each entry in the map can
	// only have a single role).
	for _, role := range node.Roles() {
		if !newNode.HasRoles(role) {
			// Skip unset roles.
			continue
		}

		maxNodes, exists := wcfg.MaxNodes[role]
		if !exists {
			// No such role found in whitelist.
			return ErrForbidden
		}
		if maxNodes == 0 {
			// No nodes of this type are allowed.
			return ErrForbidden
		}

		if err := verifyNodeCountWithRoleForRuntime(ctx, nodeLookup, newNode, rt, epoch, role, int(maxNodes)); err != nil {
			return err
		}
	}

	return nil
}

// EntityWhitelistConfig is a per-entity whitelist configuration.
type EntityWhitelistConfig struct {
	// MaxNodes is the maximum number of nodes that an entity can register under
	// the given runtime for a specific role. If the map is empty or absent, the
	// number of nodes is unlimited. If the map is present and non-empty, the
	// the number of nodes is restricted to the specified maximum (where zero
	// means no nodes allowed), any missing roles imply zero nodes.
	MaxNodes map[node.RolesMask]uint16 `json:"max_nodes,omitempty"`
}

// PerRoleAdmissionPolicy is a per-role admission policy.
type PerRoleAdmissionPolicy struct {
	EntityWhitelist *EntityWhitelistRoleAdmissionPolicy `json:"entity_whitelist,omitempty"`
}

// ValidateBasic performs basic runtime admission policy validity checks.
func (prap *PerRoleAdmissionPolicy) ValidateBasic() error {
	// Ensure valid whitelist if present.
	if ewl := prap.EntityWhitelist; ewl != nil {
		if err := ewl.ValidateBasic(); err != nil {
			return err
		}
	}
	return nil
}

// Verify ensures the runtime admission policy is satisfied, returning an error otherwise.
func (prap *PerRoleAdmissionPolicy) Verify(
	ctx context.Context,
	nodeLookup NodeLookup,
	newNode *node.Node,
	rt *Runtime,
	epoch beacon.EpochTime,
	role node.RolesMask,
) error {
	if prap.EntityWhitelist != nil {
		if err := prap.EntityWhitelist.Verify(ctx, nodeLookup, newNode, rt, epoch, role); err != nil {
			return err
		}
	}
	return nil
}

// EntityWhitelistRoleAdmissionPolicy is a per-role entity whitelist policy.
type EntityWhitelistRoleAdmissionPolicy struct {
	Entities map[signature.PublicKey]EntityWhitelistRoleConfig `json:"entities"`
}

// ValidateBasic performs basic runtime admission policy validity checks.
func (ewl *EntityWhitelistRoleAdmissionPolicy) ValidateBasic() error {
	for ent := range ewl.Entities {
		// Entity ID should be valid.
		if !ent.IsValid() {
			return fmt.Errorf("%w: invalid entity ID in per-role entity whitelist", ErrInvalidArgument)
		}
	}
	return nil
}

// Verify ensures the runtime admission policy is satisfied, returning an error otherwise.
func (ewl *EntityWhitelistRoleAdmissionPolicy) Verify(
	ctx context.Context,
	nodeLookup NodeLookup,
	newNode *node.Node,
	rt *Runtime,
	epoch beacon.EpochTime,
	role node.RolesMask,
) error {
	wcfg, entIsWhitelisted := ewl.Entities[newNode.EntityID]
	if !entIsWhitelisted {
		return ErrForbidden
	}
	if wcfg.MaxNodes == 0 {
		return nil // Any amount of nodes allowed.
	}

	return verifyNodeCountWithRoleForRuntime(ctx, nodeLookup, newNode, rt, epoch, role, int(wcfg.MaxNodes))
}

// EntityWhitelistRoleConfig is a per-entity whitelist configuration for a given role.
type EntityWhitelistRoleConfig struct {
	MaxNodes uint16 `json:"max_nodes,omitempty"`
}

// verifyNodeCountWithRoleForRuntime verifies that the number of nodes registered by the specified
// entity for the specified runtime with the specified role is at most the specified maximum.
func verifyNodeCountWithRoleForRuntime(
	ctx context.Context,
	nodeLookup NodeLookup,
	newNode *node.Node,
	rt *Runtime,
	epoch beacon.EpochTime,
	role node.RolesMask,
	maxNodes int,
) error {
	// Count existing nodes owned by entity.
	nodes, err := nodeLookup.GetEntityNodes(ctx, newNode.EntityID)
	if err != nil {
		return err
	}

	var curNodes int
	for _, n := range nodes {
		if n.ID.Equal(newNode.ID) || n.IsExpired(epoch) || !n.HasRuntime(rt.ID) {
			// Skip existing node when re-registering.  Also skip
			// expired nodes and nodes that haven't registered
			// for the same runtime.
			continue
		}

		if n.HasRoles(role) {
			curNodes++
		}

		// The check is inside the for loop, so we can stop as
		// soon as possible once we're over the limit.
		if curNodes+1 > maxNodes {
			// Too many nodes with given role already registered.
			return ErrForbidden
		}
	}

	return nil
}
