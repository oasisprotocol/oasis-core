package committee

import (
	"github.com/oasisprotocol/oasis-core/go/common/accessctl"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes"
)

var logger = logging.GetLogger("worker/common/committee/accessctl")

// AccessPolicy defines a list of actions that are allowed by the policy.
type AccessPolicy struct {
	Actions []accessctl.Action
}

// AddRulesForCommittee augments the given policy by allowing actions in the current AccessPolicy
// for the nodes in the given committee.
func (ap AccessPolicy) AddRulesForCommittee(policy *accessctl.Policy, committee *CommitteeInfo, nodes nodes.NodeDescriptorLookup) {
	for id := range committee.PublicKeys {
		node := nodes.Lookup(id)
		if node == nil {
			// This should never happen as nodes cannot disappear mid-epoch.
			logger.Warn("ignoring node that disappeared mid-epoch",
				"node", id,
			)
			continue
		}

		// Allow the node to perform actions from the given access policy.
		subject := accessctl.SubjectFromPublicKey(node.TLS.PubKey)
		for _, action := range ap.Actions {
			policy.Allow(subject, action)
		}

		// Make sure to also allow the node to perform actions after it has
		// rotated its TLS certificates.
		if node.TLS.NextPubKey.IsValid() {
			subject := accessctl.SubjectFromPublicKey(node.TLS.NextPubKey)
			for _, action := range ap.Actions {
				policy.Allow(subject, action)
			}
		}
	}
}

// AddPublicKeyPolicy augments the given policy by allowing actions in the current AccessPolicy
// to given TLS public key.
func (ap AccessPolicy) AddPublicKeyPolicy(policy *accessctl.Policy, pubKey signature.PublicKey) {
	subject := accessctl.SubjectFromPublicKey(pubKey)
	for _, action := range ap.Actions {
		policy.Allow(subject, action)
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
			subject := accessctl.SubjectFromPublicKey(n.TLS.PubKey)
			for _, action := range ap.Actions {
				policy.Allow(subject, action)
			}

			// Make sure to also allow the node to perform actions after is has
			// rotated its TLS certificates.
			if n.TLS.NextPubKey.IsValid() {
				subject := accessctl.SubjectFromPublicKey(n.TLS.NextPubKey)
				for _, action := range ap.Actions {
					policy.Allow(subject, action)
				}
			}
		}
	}
}
