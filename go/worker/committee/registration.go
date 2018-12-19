package committee

import (
	"net"
	"time"

	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/node"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

// XXX: This is needed until we decide how we want to actually register runtimes.
func (n *Node) registerRuntime() error {
	n.logger.Info("performing runtime registration")

	rtDesc := registry.Runtime{
		ID:                     n.runtimeID,
		ReplicaGroupSize:       1,
		ReplicaGroupBackupSize: 0,
		StorageGroupSize:       1,
		RegistrationTime:       uint64(time.Now().Unix()),
	}

	signedRt, err := registry.SignRuntime(*n.identity.NodeKey, registry.RegisterRuntimeSignatureContext, &rtDesc)
	if err != nil {
		n.logger.Error("failed to register runtime: unable to sign runtime descriptor",
			"err", err,
		)
		return err
	}

	if err := n.registry.RegisterRuntime(n.ctx, signedRt); err != nil {
		n.logger.Error("failed to register runtime",
			"err", err,
		)
		return err
	}

	n.logger.Info("runtime registered")

	return nil
}

// RegisterNode (re-)registers a node with the registry.
func (n *Node) registerNode() error {
	n.logger.Info("performing node (re-)registration")

	// Get current epoch.
	epoch, _, err := n.epochtime.GetEpoch(n.ctx)
	if err != nil {
		n.logger.Error("failed to register node: unable to determine current epoch",
			"err", err,
		)
		return err
	}

	// Get node's local addresses.
	var addresses []node.Address
	if len(n.cfg.ClientAddresses) > 0 {
		addresses = n.cfg.ClientAddresses
	} else {
		// Use all non-loopback addresses of this node.
		ifaces, ierr := net.Interfaces()
		if ierr != nil {
			n.logger.Error("failed to register node: unable to get interfaces",
				"err", ierr,
			)
			return ierr
		}

		for _, iface := range ifaces {
			// Skip interfaces which are down or loopback.
			if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
				continue
			}

			addrs, aerr := iface.Addrs()
			if aerr != nil {
				continue
			}

			for _, addr := range addrs {
				var ip net.IP
				switch a := addr.(type) {
				case *net.IPAddr:
					ip = a.IP
				case *net.IPNet:
					ip = a.IP
				}

				var address node.Address
				if derr := address.FromIP(ip, n.cfg.ClientPort); derr != nil {
					continue
				}

				addresses = append(addresses, address)
			}
		}
	}

	identityPublic := n.identity.NodeKey.Public()

	// XXX: Also create an entity with the same key for now.
	entityDesc := entity.Entity{
		ID:               identityPublic,
		RegistrationTime: uint64(time.Now().Unix()),
	}

	signedEnt, err := entity.SignEntity(*n.identity.NodeKey, registry.RegisterEntitySignatureContext, &entityDesc)
	if err != nil {
		n.logger.Error("failed to register entity: unable to sign entity descriptor",
			"err", err,
		)
		return err
	}

	if rerr := n.registry.RegisterEntity(n.ctx, signedEnt); rerr != nil {
		n.logger.Error("failed to register entity",
			"err", rerr,
		)
		return rerr
	}

	nodeDesc := node.Node{
		ID:         identityPublic,
		EntityID:   identityPublic,
		Expiration: uint64(epoch) + 2,
		Addresses:  addresses,
		P2P:        n.group.P2PInfo(),
		Certificate: &node.Certificate{
			DER: n.identity.TLSCertificate.Certificate[0],
		},
		RegistrationTime: uint64(time.Now().Unix()),
	}

	signedNode, err := node.SignNode(*n.identity.NodeKey, registry.RegisterNodeSignatureContext, &nodeDesc)
	if err != nil {
		n.logger.Error("failed to register node: unable to sign node descriptor",
			"err", err,
		)
		return err
	}

	if err := n.registry.RegisterNode(n.ctx, signedNode); err != nil {
		n.logger.Error("failed to register node",
			"err", err,
		)
		return err
	}

	n.logger.Info("node registered with the registry")

	return nil
}
