package committee

import (
	"crypto/x509"

	"github.com/oasislabs/oasis-core/go/common/accessctl"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/runtime/committee"
)

var logger = logging.GetLogger("worker/common/committee/accessctl")

// AccessPolicy defines a list of actions that are allowed by the policy.
type AccessPolicy struct {
	Actions []accessctl.Action
}

// AddRulesForCommittee augments the given policy by allowing actions in the current AccessPolicy
// for the nodes in the given committee.
func (ap AccessPolicy) AddRulesForCommittee(policy *accessctl.Policy, committee *CommitteeInfo, nodes committee.NodeDescriptorLookup) {
	for id := range committee.PublicKeys {
		node := nodes.Lookup(id)
		if node == nil {
			// This should never happen as nodes cannot disappear mid-epoch.
			logger.Warn("ignoring node that disappeared mid-epoch",
				"node", id,
			)
			continue
		}

		subject := accessctl.SubjectFromDER(node.Committee.Certificate)
		for _, action := range ap.Actions {
			policy.Allow(subject, action)
		}
	}
}

// AddCertPolicy augments the given policy by allowing actions in the current AccessPolicy
// to given certificate.
func (ap AccessPolicy) AddCertPolicy(policy *accessctl.Policy, cert *x509.Certificate) {
	subject := accessctl.SubjectFromX509Certificate(cert)
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
			subject := accessctl.SubjectFromDER(n.Committee.Certificate)
			for _, action := range ap.Actions {
				policy.Allow(subject, action)
			}
		}

	}
}
