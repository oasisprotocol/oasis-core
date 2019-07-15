package crypto

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
	_ "unsafe" // For go:linkname.

	"github.com/pkg/errors"
	tmcrypto "github.com/tendermint/tendermint/crypto"
	tmcmn "github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/privval"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/json"
)

// This derives heavily from `tendermint/privval/file.go` for reasons that should
// be obvious, and is probably covered by the Tendermint (Apache 2) license.
//
// Frustratingly, while it should be possible to reuse most of the FilePV
// implementation, all of the useful helpers are not exported, and neither is
// `FilePVLastSignState.filePath`.

//go:linkname checkVotesOnlyDifferByTimestamp github.com/tendermint/tendermint/privval.checkVotesOnlyDifferByTimestamp
func checkVotesOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool)

//go:linkname checkProposalsOnlyDifferByTimestamp github.com/tendermint/tendermint/privval.checkProposalsOnlyDifferByTimestamp
func checkProposalsOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool)

const privValFileName = "ekiden_priv_validator.json"

const (
	// stepNone      int8 = 0
	stepPropose   int8 = 1
	stepPrevote   int8 = 2
	stepPrecommit int8 = 3
)

func voteToStep(vote *tmtypes.Vote) int8 {
	switch vote.Type {
	case tmtypes.PrevoteType:
		return stepPrevote
	case tmtypes.PrecommitType:
		return stepPrecommit
	default:
		panic("Unknown vote type")
	}
}

type privVal struct {
	privval.FilePVLastSignState
	PublicKey signature.PublicKey `codec:"public_key"`

	filePath string
	signer   signature.Signer
}

func (pv *privVal) GetPubKey() tmcrypto.PubKey {
	return PublicKeyToTendermint(&pv.PublicKey)
}

func (pv *privVal) SignVote(chainID string, vote *tmtypes.Vote) error {
	height, round, step := vote.Height, vote.Round, voteToStep(vote)

	doubleSigned, err := pv.CheckHRS(height, round, step)
	if err != nil {
		return errors.Wrap(err, "tendermint/crypto: failed to check vote H/R/S")
	}

	signBytes := vote.SignBytes(chainID)
	if doubleSigned {
		if bytes.Equal(signBytes, pv.SignBytes) {
			vote.Signature = pv.Signature
		} else if ts, ok := checkVotesOnlyDifferByTimestamp(pv.SignBytes, signBytes); ok {
			vote.Timestamp = ts
			vote.Signature = pv.Signature
		} else {
			err = errors.New("tendermint/crypto: conflicting vote")
		}
		return err
	}

	sig, err := pv.signer.Sign(signBytes)
	if err != nil {
		return errors.Wrap(err, "tendermint/crypto: failed to sign vote")
	}
	if err = pv.update(height, round, step, signBytes, sig); err != nil {
		return err
	}
	vote.Signature = sig

	return nil
}

func (pv *privVal) SignProposal(chainID string, proposal *tmtypes.Proposal) error {
	height, round, step := proposal.Height, proposal.Round, stepPropose

	doubleSigned, err := pv.CheckHRS(height, round, step)
	if err != nil {
		return errors.Wrap(err, "tendermint/crypto: failed to check proposal H/R/S")
	}

	signBytes := proposal.SignBytes(chainID)
	if doubleSigned {
		if bytes.Equal(signBytes, pv.SignBytes) {
			proposal.Signature = pv.Signature
		} else if ts, ok := checkProposalsOnlyDifferByTimestamp(pv.SignBytes, signBytes); ok {
			proposal.Timestamp = ts
			proposal.Signature = pv.Signature
		} else {
			err = errors.New("tendermint/crypto: conflicting proposal")
		}
		return err
	}

	sig, err := pv.signer.Sign(signBytes)
	if err != nil {
		return errors.Wrap(err, "tendermint/crypto: failed to sign proposal")
	}
	if err = pv.update(height, round, step, signBytes, sig); err != nil {
		return err
	}
	proposal.Signature = sig

	return nil
}

func (pv *privVal) update(height int64, round int, step int8, signBytes, sig []byte) error {
	pv.Height = height
	pv.Round = round
	pv.Step = step
	pv.SignBytes = signBytes
	pv.Signature = sig
	return pv.save()
}

func (pv *privVal) save() error {
	if err := tmcmn.WriteFileAtomic(pv.filePath, json.Marshal(pv), 0600); err != nil {
		return errors.Wrap(err, "tendermint/crypto: failed to save private validator file")
	}

	return nil
}

// LoadOrGeneratePrivVal loads or generates a tendermint PrivValidator for an
// ekiden signature signer.
func LoadOrGeneratePrivVal(baseDir string, signer signature.Signer) (tmtypes.PrivValidator, error) {
	fn := filepath.Join(baseDir, privValFileName)

	pv := &privVal{
		filePath: fn,
		signer:   signer,
	}

	b, err := ioutil.ReadFile(fn)
	if err == nil {
		if err = json.Unmarshal(b, &pv); err != nil {
			return nil, errors.Wrap(err, "tendermint/crypto: failed to parse private validator file")
		}

		// Tendermint doesn't do this, but it's cheap insurance.
		if !signer.Public().Equal(pv.PublicKey) {
			return nil, errors.Wrap(err, "tendermint/crypto: public key mismatch, state corruption?")
		}
	} else if os.IsNotExist(err) {
		pv.PublicKey = signer.Public()

		if err = pv.save(); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.Wrap(err, "tendermint/crypto: failed to load private validator file")
	}

	return pv, nil
}
