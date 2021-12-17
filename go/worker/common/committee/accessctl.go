package committee

import (
	"github.com/oasisprotocol/oasis-core/go/common/accessctl"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
)

// AccessPolicy defines a list of actions that are allowed by the policy.
type AccessPolicy struct {
	Actions []accessctl.Action
}

// AddRulesForNodes augments the given policy by allowing actions in the current AccessPolicy for
// the specified list of nodes.
func (ap AccessPolicy) AddRulesForNodes(policy *accessctl.Policy, nodes []*node.Node) {
	for _, node := range nodes {
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
