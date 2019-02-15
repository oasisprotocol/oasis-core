package worker

import (
	"context"
	"net"
	"time"

	"github.com/cenkalti/backoff"

	"github.com/oasislabs/ekiden/go/common/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

func (w *Worker) doNodeRegistration() {
	// (re-)register the node on each epoch transition.  This doesn't
	// need to be strict block-epoch time, since it just serves to
	// extend the node's expiration.
	ch, sub := w.epochtime.WatchEpochs()
	defer sub.Close()

	regFn := func(epoch epochtime.EpochTime, retry bool) error {
		var off backoff.BackOff

		switch retry {
		case true:
			expBackoff := backoff.NewExponentialBackOff()
			expBackoff.MaxElapsedTime = 0
			off = expBackoff
		case false:
			off = &backoff.StopBackOff{}
		}
		off = backoff.WithContext(off, w.ctx)

		// WARNING: This can potentially infinite loop, on certain
		// "shouldn't be possible" pathological failures.
		//
		// w.ctx being canceled will break out of the loop correctly
		// but it's entirely possible to sit around in an ininite
		// retry loop with no hope of success.
		return backoff.Retry(func() error {
			// Update the epoch if it happens to change while retrying.
			var ok bool
			select {
			case epoch, ok = <-ch:
				if !ok {
					return context.Canceled
				}
			default:
			}

			return w.registerNode(epoch)
		}, off)
	}

	epoch := <-ch
	err := regFn(epoch, true)
	close(w.regCh)
	if err != nil {
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
		EntityID:   w.entityPrivKey.Public(),
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

	signedNode, err := node.SignNode(*w.entityPrivKey, registry.RegisterNodeSignatureContext, &nodeDesc)
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
