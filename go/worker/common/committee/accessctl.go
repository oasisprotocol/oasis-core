package committee

import (
	"github.com/oasislabs/oasis-core/go/common/accessctl"
	"github.com/oasislabs/oasis-core/go/common/node"
)

// AccessPolicy defines a list of actions that are allowed by the policy.
type AccessPolicy struct {
	Actions []accessctl.Action
}

// AddRulesForCommittee augments the given policy by allowing actions in the current AccessPolicy
// for the nodes in the given committee.
func (ap AccessPolicy) AddRulesForCommittee(policy *accessctl.Policy, committee *CommitteeInfo) {
	for _, node := range committee.Nodes {
		subject := accessctl.SubjectFromDER(node.Committee.Certificate)
		for _, action := range ap.Actions {
			policy.Allow(subject, action)
		}
	}
}

// AddRulesForNodeRoles augments the given policy by allowing actions in the current AccessPolicy
// for the nodes that have the given roles mask.
func (ap AccessPolicy) AddRulesForNodeRoles(
	policy *accessctl.Policy,
	nodes []*node.Node,
	roles node.RolesMask,
) {
	for _, n := range nodes {
		if n.HasRoles(roles) {
			subject := accessctl.SubjectFromDER(n.Committee.Certificate)
			for _, action := range ap.Actions {
				policy.Allow(subject, action)
			}
		}

	}
}
