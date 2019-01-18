package worker

import (
	"context"
	"net"
	"time"

	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

// XXX: This is needed until we decide how we want to actually register runtimes.
func (w *Worker) registryRegisterRuntime(cfg *RuntimeConfig) error {
	w.logger.Info("performing runtime registration")

	rtDesc := registry.Runtime{
		ID:                     cfg.ID,
		FeaturesSGX:            cfg.TEEHardware == node.TEEHardwareIntelSGX,
		ReplicaGroupSize:       cfg.ReplicaGroupSize,
		ReplicaGroupBackupSize: cfg.ReplicaGroupBackupSize,
		StorageGroupSize:       1,
		RegistrationTime:       uint64(time.Now().Unix()),
	}

	signedRt, err := registry.SignRuntime(*w.identity.NodeKey, registry.RegisterRuntimeSignatureContext, &rtDesc)
	if err != nil {
		w.logger.Error("failed to register runtime: unable to sign runtime descriptor",
			"err", err,
			"runtime", cfg.ID,
		)
		return err
	}

	if err := w.registry.RegisterRuntime(w.ctx, signedRt); err != nil {
		w.logger.Error("failed to register runtime",
			"err", err,
			"runtime", cfg.ID,
		)
		return err
	}

	w.logger.Info("runtime registered",
		"runtime", cfg.ID,
	)

	return nil
}

func (w *Worker) doNodeRegistration() {
	// (re-)register the node on each epoch transition.  This doesn't
	// need to be strict block-epoch time, since it just serves to
	// extend the node's expiration.
	ch, sub := w.epochtime.WatchEpochs()
	defer sub.Close()

	regFn := func(epoch epochtime.EpochTime, retry bool) error {
		for {
			err := w.registerNode(epoch)
			switch err {
			case nil, context.Canceled:
				return err
			default:
				if !retry {
					return err
				}
			}

			// WARNING: This can potentially infinite loop, on certain
			// "shouldn't be possible" pathological failures.
			//
			// w.ctx being canceled will break out of the loop correctly
			// but it's entirely possible to sit around in an ininite
			// retry loop with no hope of success.

			time.Sleep(1 * time.Second)
		}
	}

	epoch := <-ch
	if err := regFn(epoch, true); err != nil {
		// This by definition is a cancelation.
		return
	}

	for {
		select {
		case <-w.quitCh:
			return
		case epoch = <-ch:
			if err := regFn(epoch, false); err != nil {
				w.logger.Error("failed to re-register node",
					"err", err,
				)
			}
		}
	}
}

func (w *Worker) registerNode(epoch epochtime.EpochTime) error {
	w.logger.Info("performing node (re-)registration",
		"epoch", epoch,
	)

	// Get node's local addresses.
	var addresses []node.Address
	if len(w.cfg.ClientAddresses) > 0 {
		addresses = w.cfg.ClientAddresses
	} else {
		// Use all non-loopback addresses of this node.
		ifaces, ierr := net.Interfaces()
		if ierr != nil {
			w.logger.Error("failed to register node: unable to get interfaces",
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
				if derr := address.FromIP(ip, w.cfg.ClientPort); derr != nil {
					continue
				}

				addresses = append(addresses, address)
			}
		}
	}

	identityPublic := w.identity.NodeKey.Public()
	nodeDesc := node.Node{
		ID:         identityPublic,
		EntityID:   identityPublic,
		Expiration: uint64(epoch) + 2,
		Addresses:  addresses,
		P2P:        w.p2p.Info(),
		Certificate: &node.Certificate{
			DER: w.identity.TLSCertificate.Certificate[0],
		},
		RegistrationTime: uint64(time.Now().Unix()),
	}

	for _, v := range w.runtimes {
		var err error

		rt := &node.Runtime{
			ID: v.cfg.ID,
		}
		if rt.Capabilities.TEE, err = v.workerHost.WaitForCapabilityTEE(w.ctx); err != nil {
			w.logger.Error("failed to obtain CapabilityTEE",
				"err", err,
				"runtime", rt.ID,
			)
			continue
		}
		nodeDesc.Runtimes = append(nodeDesc.Runtimes, rt)
	}

	signedNode, err := node.SignNode(*w.identity.NodeKey, registry.RegisterNodeSignatureContext, &nodeDesc)
	if err != nil {
		w.logger.Error("failed to register node: unable to sign node descriptor",
			"err", err,
		)
		return err
	}

	if err := w.registry.RegisterNode(w.ctx, signedNode); err != nil {
		w.logger.Error("failed to register node",
			"err", err,
		)
		return err
	}

	w.logger.Info("node registered with the registry")

	return nil
}

func (w *Worker) registerEntity() error {
	w.entity.RegistrationTime = uint64(time.Now().Unix())

	signedEnt, err := entity.SignEntity(*w.identity.NodeKey, registry.RegisterEntitySignatureContext, w.entity)
	if err != nil {
		w.logger.Error("failed to register entity: unable to sign entity descriptor",
			"err", err,
		)
		return err
	}

	if err = w.registry.RegisterEntity(w.ctx, signedEnt); err != nil {
		w.logger.Error("failed to register entity",
			"err", err,
		)
	}
	return err
}
