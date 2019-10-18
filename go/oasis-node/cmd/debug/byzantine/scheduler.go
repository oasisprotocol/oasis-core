package byzantine

import (
	"bytes"
	"context"
	"fmt"

	"github.com/pkg/errors"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/node"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	tmapi "github.com/oasislabs/oasis-core/go/tendermint/api"
	schedulerapp "github.com/oasislabs/oasis-core/go/tendermint/apps/scheduler"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
	"github.com/oasislabs/oasis-core/go/worker/common/p2p"
)

func schedulerNextElectionHeight(svc service.TendermintService, kind scheduler.CommitteeKind) (int64, error) {
	sub, err := svc.Subscribe("script", schedulerapp.QueryApp)
	if err != nil {
		return 0, errors.Wrap(err, "Tendermint Subscribe")
	}
	defer func() {
		if err := tendermintUnsubscribeDrain(svc, "script", schedulerapp.QueryApp, sub); err != nil {
			panic(fmt.Sprintf("Tendermint unsubscribe drain: %+v", err))
		}
	}()

	for {
		ev := (<-sub.Out()).Data().(tmtypes.EventDataNewBlock)
		for _, tmEv := range ev.ResultBeginBlock.GetEvents() {
			if tmEv.GetType() != tmapi.EventTypeOasis {
				continue
			}

			for _, pair := range tmEv.GetAttributes() {
				if bytes.Equal(pair.GetKey(), schedulerapp.TagElected) {
					var kinds []scheduler.CommitteeKind
					if err := cbor.Unmarshal(pair.GetValue(), &kinds); err != nil {
						return 0, errors.Wrap(err, "CBOR Unmarshal kinds")
					}

					for _, k := range kinds {
						if k == kind {
							return ev.Block.Header.Height, nil
						}
					}
				}
			}
		}
	}
}

func schedulerGetCommittee(ht *honestTendermint, height int64, kind scheduler.CommitteeKind, runtimeID signature.PublicKey) (*scheduler.Committee, error) {
	q, err := ht.schedulerQuery.QueryAt(height)
	if err != nil {
		return nil, errors.Wrap(err, "Tendermint QueryAt scheduler")
	}

	committees, err := q.KindsCommittees(context.Background(), []scheduler.CommitteeKind{kind})
	if err != nil {
		return nil, errors.Wrap(err, "Tendermint KindsCommittees scheduler")
	}

	for _, committee := range committees {
		if committee.Kind != kind {
			return nil, errors.Errorf("query returned a committee of the wrong kind %s, expected %s", committee.Kind, kind)
		}

		if !committee.RuntimeID.Equal(runtimeID) {
			continue
		}

		return committee, nil
	}
	return nil, errors.New("query didn't return a committee for our runtime")
}

func schedulerCheckScheduled(committee *scheduler.Committee, nodeID signature.PublicKey, role scheduler.Role) error {
	for _, member := range committee.Members {
		if !member.PublicKey.Equal(nodeID) {
			continue
		}

		if member.Role != role {
			return errors.Errorf("we're scheduled as %s, expected %s", member.Role, role)
		}

		// All good.
		return nil
	}
	return errors.New("we're not scheduled")
}

func schedulerForRoleInCommittee(ht *honestTendermint, height int64, committee *scheduler.Committee, role scheduler.Role, fn func(*node.Node) error) error {
	for _, member := range committee.Members {
		if member.Role != role {
			continue
		}

		n, err := registryGetNode(ht, height, member.PublicKey)
		if err != nil {
			return errors.Wrapf(err, "registry get node %s", member.PublicKey)
		}

		if err = fn(n); err != nil {
			// Forward callback error to caller verbatim.
			return err
		}
	}

	return nil
}

func schedulerPublishToCommittee(ht *honestTendermint, height int64, committee *scheduler.Committee, role scheduler.Role, ph *p2pHandle, message *p2p.Message) error {
	if err := schedulerForRoleInCommittee(ht, height, committee, role, func(n *node.Node) error {
		ph.service.Publish(ph.context, n, message)

		return nil
	}); err != nil {
		return err
	}

	ph.service.Flush()

	return nil
}
