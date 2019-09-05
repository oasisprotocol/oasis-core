package byzantine

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	schedulerapp "github.com/oasislabs/ekiden/go/tendermint/apps/scheduler"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

func schedulerNextElectionHeight(svc service.TendermintService, kind scheduler.CommitteeKind) (int64, error) {
	sub, err := svc.Subscribe("script", schedulerapp.QueryApp)
	if err != nil {
		return 0, errors.Wrap(err, "Tendermint Subscribe")
	}
	defer func() {
		// Drain our unbuffered subscription while we work on unsubscribing.
		go func() {
			for {
				select {
				case <-sub.Out():
				case <-sub.Cancelled():
					break
				}
			}
		}()
		err := svc.Unsubscribe("script", schedulerapp.QueryApp)
		if err != nil {
			panic(fmt.Sprintf("Tendermint Unsubscribe: %+v", err))
		}
	}()

	for {
		ev := (<-sub.Out()).Data().(tmtypes.EventDataNewBlock)
		for _, tmEv := range ev.ResultBeginBlock.GetEvents() {
			if tmEv.GetType() != tmapi.EventTypeEkiden {
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

func schedulerGetCommittee(svc service.TendermintService, height int64, kind scheduler.CommitteeKind, runtimeID signature.PublicKey) (*scheduler.Committee, error) {
	raw, err := svc.Query(schedulerapp.QueryKindsCommittees, []scheduler.CommitteeKind{kind}, height)
	if err != nil {
		return nil, errors.Wrapf(err, "Tendermint Query %s", schedulerapp.QueryKindsCommittees)
	}

	var committees []*scheduler.Committee
	if err := cbor.Unmarshal(raw, &committees); err != nil {
		return nil, errors.Wrap(err, "CBOR Unmarshal committees")
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

func schedulerForRoleInCommittee(svc service.TendermintService, height int64, committee *scheduler.Committee, role scheduler.Role, fn func(*node.Node) error) error {
	for _, member := range committee.Members {
		if member.Role != role {
			continue
		}

		n, err := registryGetNode(svc, height, member.PublicKey)
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
